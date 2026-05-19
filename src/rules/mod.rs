pub mod types;
pub mod loader;

use crate::parser::types::{ParsedPacket, Protocol};
use crate::state::table::ConnTable;
use crate::state::is_established;
use types::{Action, Config, Rule};

/// Evaluates a packet against state and rules, returning an Action and the rule name.
pub fn evaluate(packet: &ParsedPacket, config: &Config, state_table: &ConnTable) -> (Action, String) {
    // 1. Check if the connection is already established (Stateful Inspection)
    if is_established(state_table, packet) {
        return (Action::Accept, "established-connection".to_string());
    }

    // 2. Iterate over user-defined rules
    for rule in &config.rules {
        if matches_rule(packet, rule) {
            return (rule.action.clone(), rule.name.clone());
        }
    }

    // 3. No rule matched — apply default policy
    let default_action = match config.defaults.policy.as_str() {
        "drop" => Action::Drop,
        _ => Action::Accept,
    };
    
    (default_action, "default-policy".to_string())
}

/// Checks if a single rule matches the given packet.
fn matches_rule(packet: &ParsedPacket, rule: &Rule) -> bool {
    // 1. Check Protocol
    if let Some(ref rule_proto) = rule.protocol {
        let packet_proto_str = match &packet.protocol {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Unknown(_) => "UNKNOWN",
        };
        if rule_proto.to_uppercase() != packet_proto_str {
            return false;
        }
    }

    // 2. Check Source IP
    if let Some(ref rule_src_ip) = rule.src_ip {
        if packet.src_ip.to_string() != *rule_src_ip {
            return false;
        }
    }

    // 3. Check Destination IP
    if let Some(ref rule_dst_ip) = rule.dst_ip {
        if packet.dst_ip.to_string() != *rule_dst_ip {
            return false;
        }
    }

    // 4. Check Source Port
    if let Some(rule_src_port) = rule.src_port {
        if packet.src_port != Some(rule_src_port) {
            return false;
        }
    }

    // 5. Check Destination Port
    if let Some(rule_dst_port) = rule.dst_port {
        if packet.dst_port != Some(rule_dst_port) {
            return false;
        }
    }

    true
}
