use nfqueue::{CopyMode, Message, Queue, Verdict};

use crate::parser::parse_packet;
use crate::rules::evaluate;
use crate::rules::types::{Action, Config};

pub mod verdict;

/// Holds the shared state for the active firewall.
pub struct FirewallState {
    pub config: Config,
}

impl FirewallState {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

/// Starts the nfqueue listener loop.
/// This will block the current thread and process packets as they arrive in the kernel queue.
pub fn start_nfqueue(config: Config, queue_num: u16) {
    let state = FirewallState::new(config);
    let mut queue = Queue::new(state);

    // 1. Open a connection to the netfilter queue subsystem
    queue.open();

    // 2. Bind to the IPv4 protocol (AF_INET = 2)
    // nfqueue 0.9.1 bind returns an i32 status code, not a Result with expect
    if queue.bind(2) < 0 {
        panic!("Failed to bind to nfqueue. Are you running as root?");
    }

    // 3. Create the queue and register the callback function
    // In nfqueue 0.9.1, create_queue takes the queue number and the callback.
    // The callback signature is fn(&Message, &mut T)
    queue.create_queue(queue_num, nfqueue_callback);

    // 4. Set the copy mode to get the full packet payload
    // 0xffff is the max packet length to copy
    queue.set_mode(CopyMode::CopyPacket, 0xffff);

    println!("[*] Active Enforcement started on NFQUEUE #{}", queue_num);
    println!("[*] Rules are being applied in real-time.");

    // 5. Start the blocking run loop
    queue.run_loop();
}

/// The "Bouncer" function called by the kernel for every intercepted packet.
fn nfqueue_callback(msg: &Message, state: &mut FirewallState) {
    let payload = msg.get_payload();

    // 1. Parse the packet coming from the kernel
    let verdict = match parse_packet(payload) {
        Some(packet) => {
            // 2. Evaluate the packet against our rules
            let action = evaluate(&packet, &state.config);

            match action {
                Action::Accept => Verdict::Accept,
                Action::Drop => {
                    println!(
                        "[BLOCK] {} -> {} (Protocol: {:?})",
                        packet.src_ip, packet.dst_ip, packet.protocol
                    );
                    Verdict::Drop
                }
            }
        }
        // 3. Fallback: If we can't parse it, we accept it by default to avoid breaking networking.
        None => Verdict::Accept,
    };

    // 4. Send the verdict back to the Linux kernel
    msg.set_verdict(verdict);
}
