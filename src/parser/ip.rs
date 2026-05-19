use crate::parser::types::Protocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;

pub fn get_protocol(packet: &Ipv4Packet) -> Protocol {
    match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => Protocol::Tcp,
        IpNextHeaderProtocols::Udp => Protocol::Udp,
        IpNextHeaderProtocols::Icmp => Protocol::Icmp,
        other => Protocol::Unknown(other.0),
    }
}
