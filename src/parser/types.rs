use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown(u8),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

#[allow(dead_code)]
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
