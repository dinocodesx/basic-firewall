use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    // Ethernet layer
    pub src_mac: String,
    pub dst_mac: String,

    // IP layer
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: Protocol,
    pub ttl: u8,

    // Transport layer (TCP/UDP)
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,

    // TCP-specific metadata
    pub tcp_flags: Option<TcpFlags>,

    // Payload metadata
    pub payload_len: usize,
}
