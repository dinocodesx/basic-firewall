pub mod loader;
pub mod types;

use crate::parser::types::{ParsedPacket, Protocol};
use crate::state::is_established;
use crate::state::table::ConnTable;
use types::{Action, Config, Rule};

/// Evaluates a packet against state and rules, returning an Action and the rule name.
pub fn evaluate(
    packet: &ParsedPacket,
    config: &Config,
    state_table: &ConnTable,
) -> (Action, String) {
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
fn matches_rule(packet: &ParsedPacket, rule: &Rule) -> bool {
    // Protocol match
    if let Some(ref rule_proto) = rule.protocol {
        let proto_str = match packet.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Unknown(_) => "UNKNOWN",
        };
        if rule_proto.to_uppercase() != proto_str {
            return false;
        }
    }

    // IP matches
    if rule
        .src_ip
        .as_ref()
        .map_or(false, |ip| packet.src_ip.to_string() != *ip)
    {
        return false;
    }
    if rule
        .dst_ip
        .as_ref()
        .map_or(false, |ip| packet.dst_ip.to_string() != *ip)
    {
        return false;
    }

    // Port matches
    if rule.src_port.is_some() && packet.src_port != rule.src_port {
        return false;
    }
    if rule.dst_port.is_some() && packet.dst_port != rule.dst_port {
        return false;
    }

    true
}
