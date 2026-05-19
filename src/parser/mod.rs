pub mod ip;
pub mod tcp;
pub mod types;
pub mod udp;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use types::{ParsedPacket, Protocol};

/// Takes raw Ethernet frame bytes and attempts to parse them into a structured ParsedPacket.
pub fn parse_packet(raw: &[u8]) -> Option<ParsedPacket> {
    // 1. Unpack Ethernet Frame
    let eth = EthernetPacket::new(raw)?;

    // We only care about IPv4 for this prototype
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    // 2. Unpack IPv4 Packet
    let ipv4 = Ipv4Packet::new(eth.payload())?;
    let protocol = ip::get_protocol(&ipv4);

    // 3. Unpack Transport Layer
    let mut src_port = None;
    let mut dst_port = None;
    let mut tcp_flags = None;

    match protocol {
        Protocol::Tcp => {
            if let Some((src, dst, flags)) = tcp::parse_tcp(ipv4.payload()) {
                src_port = Some(src);
                dst_port = Some(dst);
                tcp_flags = Some(flags);
            }
        }
        Protocol::Udp => {
            if let Some((src, dst)) = udp::parse_udp(ipv4.payload()) {
                src_port = Some(src);
                dst_port = Some(dst);
            }
        }
        _ => {} // Icmp or Unknown - ports remain None
    }

    Some(ParsedPacket {
        src_mac: eth.get_source().to_string(),
        dst_mac: eth.get_destination().to_string(),
        src_ip: ipv4.get_source(),
        dst_ip: ipv4.get_destination(),
        protocol,
        ttl: ipv4.get_ttl(),
        src_port,
        dst_port,
        tcp_flags,
        payload_len: ipv4.payload().len(),
    })
}
