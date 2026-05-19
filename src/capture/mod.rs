pub mod interface;

use crate::logger::log_packet;
use crate::parser::parse_packet;
use crate::rules::evaluate;
use crate::rules::types::{Action, Config};
use crate::state::{table::ConnTable, update_state};
use pnet::datalink::{Channel, Config as DatalinkConfig};
use std::time::Duration;

// Re-export list_interfaces so main.rs doesn't break
pub use self::interface::list_interfaces;

pub fn start_capture(interface_name: &str, config: Config, state_table: ConnTable) {
    let interface = interface::get_interface(interface_name).expect("Network interface not found");

    // Configure the channel
    let datalink_config = DatalinkConfig {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (_, mut rx) = match pnet::datalink::channel(&interface, datalink_config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    println!("[*] Listening on interface: {}", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(parsed) = parse_packet(packet) {
                    // 1. Evaluate packet against rules and connection state
                    let (action, rule_name) = evaluate(&parsed, &config, &state_table);

                    // 2. Audit the decision to the JSON log file
                    log_packet(&parsed, &action, &rule_name);

                    // 3. Update connection state table if the packet is accepted
                    if action == Action::Accept {
                        update_state(&state_table, &parsed);
                    }

                    let transport_info = match (&parsed.src_port, &parsed.dst_port) {
                        (Some(src), Some(dst)) => {
                            format!("{}:{} -> {}:{}", parsed.src_ip, src, parsed.dst_ip, dst)
                        }
                        _ => format!("{} -> {}", parsed.src_ip, parsed.dst_ip),
                    };

                    println!(
                        "[{:?}] {:?} {} | Length: {} | Rule: {}",
                        action, parsed.protocol, transport_info, parsed.payload_len, rule_name
                    );
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                    eprintln!("[ERROR] {}", e);
                }
            }
        }
    }
}
