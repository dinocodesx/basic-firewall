pub mod loader;
pub mod types;

use crate::parser::types::{ParsedPacket, Protocol};
use types::{Action, Config, Rule};

/// Evaluates a packet against the provided configuration and returns an Action (Accept/Drop).
pub fn evaluate(packet: &ParsedPacket, config: &Config) -> Action {
    for rule in &config.rules {
        if matches_rule(packet, rule) {
            // In a real firewall, we might log this match here.
            return rule.action.clone();
        }
    }

    // No rule matched — apply default policy
    match config.defaults.policy.as_str() {
        "drop" => Action::Drop,
        _ => Action::Accept,
    }
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

    // If we reached here, all specified fields matched.
    true
}
