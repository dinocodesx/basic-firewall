use pnet::packet::udp::UdpPacket;

pub fn parse_udp(payload: &[u8]) -> Option<(u16, u16)> {
    let udp = UdpPacket::new(payload)?;
    Some((udp.get_source(), udp.get_destination()))
}
