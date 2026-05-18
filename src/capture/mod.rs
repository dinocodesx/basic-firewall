pub mod interface;

use pnet::datalink::{Channel, Config};
use pnet::packet::ethernet::EthernetPacket;
use std::time::Duration;

// Re-export list_interfaces so main.rs doesn't break
pub use self::interface::list_interfaces;

pub fn start_capture(interface_name: &str) {
    let interface = interface::get_interface(interface_name)
        .expect("Network interface not found");

    // Configure the channel (we can add more config here later if needed)
    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (_, mut rx) = match pnet::datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    println!("[*] Listening on interface: {}", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    println!(
                        "[PACKET] src_mac={} dst_mac={} ethertype={:?}",
                        eth_packet.get_source(),
                        eth_packet.get_destination(),
                        eth_packet.get_ethertype()
                    );
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
