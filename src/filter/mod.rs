use std::sync::Arc;
use nfqueue::{Message, Queue, Verdict};

use crate::parser::parse_packet;
use crate::rules::evaluate;
use crate::rules::types::{Action, Config};

pub mod verdict;

/// Holds the shared state for the active firewall.
pub struct FirewallState {
    pub config: Config,
}

impl FirewallState {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self { config })
    }
}

/// Starts the nfqueue listener loop.
/// This will block the current thread and process packets as they arrive in the kernel queue.
pub fn start_nfqueue(config: Config, queue_num: u16) {
    let state = FirewallState::new(config);
    let mut queue = Queue::new(state);

    // 1. Open a connection to the netfilter queue
    queue.open();
    
    // 2. Bind to the specific queue number (configured in iptables)
    queue.bind(queue_num).expect("Failed to bind to nfqueue. Are you running as root?");
    
    // 3. Register the callback function that evaluates each packet
    queue.set_callback(nfqueue_callback);

    println!("[*] Active Enforcement started on NFQUEUE #{}", queue_num);
    println!("[*] Rules are being applied in real-time.");

    // 4. Start the blocking run loop
    queue.run_loop();
}

/// The "Bouncer" function called by the kernel for every intercepted packet.
fn nfqueue_callback(msg: &Message, state: &mut Arc<FirewallState>) {
    let payload = msg.get_payload();

    // 1. Parse the packet coming from the kernel
    let verdict = match parse_packet(payload) {
        Some(packet) => {
            // 2. Evaluate the packet against our rules
            let action = evaluate(&packet, &state.config);
            
            match action {
                Action::Accept => {
                    // Implicitly let it through
                    Verdict::Accept
                }
                Action::Drop => {
                    println!("[BLOCK] {} -> {} (Protocol: {:?})", 
                        packet.src_ip, 
                        packet.dst_ip, 
                        packet.protocol
                    );
                    Verdict::Drop
                }
            }
        }
        // 3. Fallback: If we can't parse it (e.g., non-IPv4), we accept it by default 
        // to avoid breaking system networking.
        None => Verdict::Accept,
    };

    // 4. Send the verdict back to the Linux kernel
    msg.set_verdict(verdict);
}
