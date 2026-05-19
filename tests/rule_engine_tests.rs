use rust_firewall::parser::types::{ParsedPacket, Protocol};
use rust_firewall::rules::{
    evaluate,
    types::{Action, Config, Defaults, Rule},
};
use rust_firewall::state::table::create_table;

fn mock_packet(src_ip: &str, dst_port: u16, proto: Protocol) -> ParsedPacket {
    ParsedPacket {
        src_mac: "00:00:00:00:00:00".to_string(),
        dst_mac: "00:00:00:00:00:00".to_string(),
        src_ip: src_ip.parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        protocol: proto,
        ttl: 64,
        src_port: Some(12345),
        dst_port: Some(dst_port),
        tcp_flags: None,
        payload_len: 100,
    }
}

#[test]
fn test_rule_matching() {
    let config = Config {
        defaults: Defaults {
            policy: "accept".to_string(),
        },
        rules: vec![
            Rule {
                name: "Block Evil IP".to_string(),
                direction: None,
                protocol: None,
                src_ip: Some("1.2.3.4".to_string()),
                dst_ip: None,
                src_port: None,
                dst_port: None,
                action: Action::Drop,
            },
            Rule {
                name: "Allow Web".to_string(),
                direction: None,
                protocol: Some("TCP".to_string()),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: Some(80),
                action: Action::Accept,
            },
        ],
    };

    let state_table = create_table();

    // Packet from blocked IP
    let p1 = mock_packet("1.2.3.4", 80, Protocol::Tcp);
    let (action, rule) = evaluate(&p1, &config, &state_table);
    assert_eq!(action, Action::Drop);
    assert_eq!(rule, "Block Evil IP");

    // Packet to port 80
    let p2 = mock_packet("192.168.1.1", 80, Protocol::Tcp);
    let (action, rule) = evaluate(&p2, &config, &state_table);
    assert_eq!(action, Action::Accept);
    assert_eq!(rule, "Allow Web");

    // Packet that matches nothing (default policy)
    let p3 = mock_packet("192.168.1.1", 22, Protocol::Tcp);
    let (action, rule) = evaluate(&p3, &config, &state_table);
    assert_eq!(action, Action::Accept);
    assert_eq!(rule, "default-policy");
}
