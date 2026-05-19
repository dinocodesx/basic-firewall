pub mod interface;

use crate::parser::parse_packet;
use crate::rules::evaluate;
use crate::rules::types::Config;
use pnet::datalink::{Channel, Config as DatalinkConfig};
use std::time::Duration;

// Re-export list_interfaces so main.rs doesn't break
pub use self::interface::list_interfaces;

pub fn start_capture(interface_name: &str, config: Config) {
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
                    let verdict = evaluate(&parsed, &config);

                    let transport_info = match (&parsed.src_port, &parsed.dst_port) {
                        (Some(src), Some(dst)) => {
                            format!("{}:{} -> {}:{}", parsed.src_ip, src, parsed.dst_ip, dst)
                        }
                        _ => format!("{} -> {}", parsed.src_ip, parsed.dst_ip),
                    };

                    println!(
                        "[{:?}] {:?} {} | Length: {} | TTL: {}",
                        verdict, parsed.protocol, transport_info, parsed.payload_len, parsed.ttl
                    );

                    if let Some(flags) = parsed.tcp_flags {
                        if flags.syn || flags.ack || flags.fin || flags.rst {
                            println!(
                                "TCP Flags: [SYN: {}, ACK: {}, FIN: {}, RST: {}]",
                                flags.syn, flags.ack, flags.fin, flags.rst
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // Ignore timeouts from the channel config
                if e.kind() != std::io::ErrorKind::TimedOut {
                    eprintln!("[ERROR] {}", e);
                }
            }
        }
    }
}
