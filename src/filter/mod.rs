#[cfg(target_os = "linux")]
use nfqueue::{CopyMode, Message, Queue, Verdict};

#[cfg(target_os = "linux")]
use crate::parser::parse_packet;
#[cfg(target_os = "linux")]
use crate::rules::evaluate;
#[cfg(target_os = "linux")]
use crate::rules::types::Action;
#[cfg(target_os = "linux")]
use crate::state::update_state;

use crate::rules::types::Config;
use crate::state::table::{create_table, ConnTable};

pub mod verdict;

/// Holds the shared state for the active firewall.
#[allow(dead_code)]
pub struct FirewallState {
    pub config: Config,
    pub state_table: ConnTable,
}

impl FirewallState {
    #[allow(dead_code)]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state_table: create_table(),
        }
    }
}

/// Starts the nfqueue listener loop.
#[cfg(target_os = "linux")]
pub fn start_nfqueue(config: Config, queue_num: u16) {
    let state = FirewallState::new(config);
    let mut queue = Queue::new(state);

    queue.open();

    if queue.bind(2) < 0 {
        panic!("Failed to bind to nfqueue. Are you running as root?");
    }

    queue.create_queue(queue_num, nfqueue_callback);
    queue.set_mode(CopyMode::CopyPacket, 0xffff);

    println!("[*] Active Enforcement started on NFQUEUE #{}", queue_num);

    queue.run_loop();
}

/// The "Bouncer" function called by the kernel for every intercepted packet.
#[cfg(target_os = "linux")]
fn nfqueue_callback(msg: &Message, state: &mut FirewallState) {
    let payload = msg.get_payload();

    let (verdict, _action_log, rule_name_log) = match parse_packet(payload) {
        Some(packet) => {
            let (action, rule_name) = evaluate(&packet, &state.config, &state.state_table);

            let v = match action {
                Action::Accept => {
                    update_state(&state.state_table, &packet);
                    Verdict::Accept
                }
                Action::Drop => Verdict::Drop,
            };
            (v, action, rule_name)
        }
        None => (
            Verdict::Accept,
            Action::Accept,
            "non-ipv4-passthrough".to_string(),
        ),
    };

    if matches!(verdict, Verdict::Drop) {
        println!("[BLOCK] Rule: {}", rule_name_log);
    }

    msg.set_verdict(verdict);
}

// Stub for non-linux systems
#[cfg(not(target_os = "linux"))]
pub fn start_nfqueue(_config: Config, _queue_num: u16) {
    eprintln!("[ERROR] Active 'block' mode is only supported on Linux.");
    std::process::exit(1);
}
