pub mod table;

use crate::parser::types::{ParsedPacket, Protocol};
use crate::state::table::{ConnEntry, ConnKey, ConnState, ConnTable};
use chrono::Utc;

/// Updates the connection table based on the observed packet and its flags.
pub fn update_state(table: &ConnTable, packet: &ParsedPacket) {
    // We only track state for TCP in this prototype
    if packet.protocol != Protocol::TCP {
        return;
    }

    let (src_port, dst_port) = match (packet.src_port, packet.dst_port) {
        (Some(s), Some(d)) => (s, d),
        _ => return,
    };

    let flags = match &packet.tcp_flags {
        Some(f) => f,
        None => return,
    };

    let key = ConnKey {
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        src_port,
        dst_port,
        protocol: "TCP".to_string(),
    };

    let mut map = table.lock().expect("Failed to lock connection table");
    let now = Utc::now().timestamp();

    let new_state = if flags.syn && !flags.ack {
        ConnState::SynSent
    } else if flags.syn && flags.ack {
        ConnState::Established
    } else if flags.fin {
        ConnState::FinWait
    } else if flags.rst {
        ConnState::Closed
    } else {
        // For other packets, if it's already in the table, keep it established
        if map.contains_key(&key) {
            ConnState::Established
        } else {
            return; // Don't create new entries for random packets without SYN
        }
    };

    map.insert(key, ConnEntry { state: new_state, last_seen: now });
}

/// Checks if a packet belongs to an established or recognized connection.
pub fn is_established(table: &ConnTable, packet: &ParsedPacket) -> bool {
    let (src_port, dst_port) = match (packet.src_port, packet.dst_port) {
        (Some(s), Some(d)) => (s, d),
        _ => return false,
    };

    // We check both directions: A -> B and B -> A
    let key_forward = ConnKey {
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        src_port,
        dst_port,
        protocol: "TCP".to_string(),
    };

    let key_reverse = ConnKey {
        src_ip: packet.dst_ip,
        dst_ip: packet.src_ip,
        src_port: dst_port,
        dst_port: src_port,
        protocol: "TCP".to_string(),
    };

    let map = table.lock().expect("Failed to lock connection table");
    
    map.contains_key(&key_forward) || map.contains_key(&key_reverse)
}

/// Periodically clean up connections that haven't been seen for a while.
#[allow(dead_code)]
pub fn evict_stale(table: &ConnTable, timeout_secs: i64) {
    let mut map = table.lock().expect("Failed to lock connection table");
    let now = Utc::now().timestamp();
    map.retain(|_, entry| now - entry.last_seen < timeout_secs);
}
