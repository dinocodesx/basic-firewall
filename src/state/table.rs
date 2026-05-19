use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    SynSent,
    Established,
    FinWait,
    Closed,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ConnEntry {
    pub state: ConnState,
    pub last_seen: i64, // Unix timestamp for timeout handling
}

/// A thread-safe table for tracking connection states.
pub type ConnTable = Arc<Mutex<HashMap<ConnKey, ConnEntry>>>;

pub fn create_table() -> ConnTable {
    Arc::new(Mutex::new(HashMap::new()))
}
