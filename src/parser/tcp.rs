use crate::parser::types::TcpFlags;
use pnet::packet::tcp::TcpPacket;

pub fn parse_tcp(payload: &[u8]) -> Option<(u16, u16, TcpFlags)> {
    let tcp = TcpPacket::new(payload)?;
    let flags = TcpFlags {
        syn: tcp.get_flags() & 0x02 != 0,
        ack: tcp.get_flags() & 0x10 != 0,
        fin: tcp.get_flags() & 0x01 != 0,
        rst: tcp.get_flags() & 0x04 != 0,
        psh: tcp.get_flags() & 0x08 != 0,
        urg: tcp.get_flags() & 0x20 != 0,
    };
    Some((tcp.get_source(), tcp.get_destination(), flags))
}
