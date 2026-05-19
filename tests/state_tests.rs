use rust_firewall::state::{is_established, update_state, table::create_table};
use rust_firewall::parser::types::{ParsedPacket, Protocol, TcpFlags};
use rust_firewall::rules::evaluate;
use rust_firewall::rules::types::{Action, Config, Defaults};

fn tcp_packet(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16, syn: bool, ack: bool) -> ParsedPacket {
    ParsedPacket {
        src_mac: "".to_string(),
        dst_mac: "".to_string(),
        src_ip: src_ip.parse().unwrap(),
        dst_ip: dst_ip.parse().unwrap(),
        protocol: Protocol::Tcp,
        ttl: 64,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        tcp_flags: Some(TcpFlags {
            syn, ack, fin: false, rst: false, psh: false, urg: false
        }),
        payload_len: 0,
    }
}

#[test]
fn test_stateful_handshake() {
    let table = create_table();
    let config = Config {
        defaults: Defaults { policy: "drop".to_string() },
        rules: vec![],
    };

    let client_ip = "192.168.1.10";
    let server_ip = "1.1.1.1";
    let client_port = 50000;
    let server_port = 80;

    // 1. Initial SYN (Outbound)
    let p1 = tcp_packet(client_ip, server_ip, client_port, server_port, true, false);
    assert!(!is_established(&table, &p1));
    update_state(&table, &p1);

    // 2. SYN-ACK (Inbound) - Should be recognized as part of the conversation
    let p2 = tcp_packet(server_ip, client_ip, server_port, client_port, true, true);
    assert!(is_established(&table, &p2));
    update_state(&table, &p2);

    // 3. Data Packet (Inbound) - Should be automatically accepted
    let p3 = tcp_packet(server_ip, client_ip, server_port, client_port, false, true);
    let (action, rule) = evaluate(&p3, &config, &table);
    
    assert_eq!(action, Action::Accept);
    assert_eq!(rule, "established-connection");
}
