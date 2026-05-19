use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use crate::parser::types::Protocol;

pub fn get_protocol(packet: &Ipv4Packet) -> Protocol {
    match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => Protocol::TCP,
        IpNextHeaderProtocols::Udp => Protocol::UDP,
        IpNextHeaderProtocols::Icmp => Protocol::ICMP,
        other => Protocol::Unknown(other.0),
    }
}
