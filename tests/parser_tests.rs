use rust_firewall::parser::parse_packet;
use rust_firewall::parser::types::Protocol;

#[test]
fn test_parse_invalid_packet() {
    let raw = vec![0u8; 10];
    assert!(parse_packet(&raw).is_none());
}

#[test]
fn test_parse_udp_packet() {
    // A mock Ethernet + IPv4 + UDP packet
    // Ethernet: 6+6+2 = 14 bytes
    // IPv4: 20 bytes
    // UDP: 8 bytes
    let mut raw = vec![0u8; 42];
    
    // Ethernet EtherType 0x0800 (IPv4)
    raw[12] = 0x08;
    raw[13] = 0x00;
    
    // IPv4 Header
    raw[14] = 0x45; // Version 4, IHL 5
    // Total Length: 28 bytes (20 IP + 8 UDP)
    raw[16] = 0x00; raw[17] = 0x1C;
    raw[23] = 17;   // Protocol UDP
    // Src IP: 1.2.3.4
    raw[26] = 1; raw[27] = 2; raw[28] = 3; raw[29] = 4;
    // Dst IP: 5.6.7.8
    raw[30] = 5; raw[31] = 6; raw[32] = 7; raw[33] = 8;
    
    // UDP Header
    // Src Port: 1234 (0x04D2)
    raw[34] = 0x04; raw[35] = 0xD2;
    // Dst Port: 5678 (0x162E)
    raw[36] = 0x16; raw[37] = 0x2E;
    // Length: 8
    raw[38] = 0x00; raw[39] = 0x08;
    
    let parsed = parse_packet(&raw).expect("Should parse valid UDP packet");
    
    assert_eq!(parsed.protocol, Protocol::Udp);
    assert_eq!(parsed.src_ip.to_string(), "1.2.3.4");
    assert_eq!(parsed.dst_ip.to_string(), "5.6.7.8");
    assert_eq!(parsed.src_port, Some(1234));
    assert_eq!(parsed.dst_port, Some(5678));
}

#[test]
fn test_parse_tcp_packet() {
    let mut raw = vec![0u8; 54]; // Eth (14) + IP (20) + TCP (20)
    
    raw[12] = 0x08; raw[13] = 0x00; // IPv4
    raw[14] = 0x45; // Version 4, IHL 5
    // Total Length: 40 bytes (20 IP + 20 TCP)
    raw[16] = 0x00; raw[17] = 0x28;
    raw[23] = 6;    // Protocol TCP
    
    // Src IP: 10.0.0.1
    raw[26] = 10; raw[27] = 0; raw[28] = 0; raw[29] = 1;
    // Dst IP: 10.0.0.2
    raw[30] = 10; raw[31] = 0; raw[32] = 0; raw[33] = 2;
    
    // TCP Header
    // Src Port: 80 (0x0050)
    raw[34] = 0x00; raw[35] = 0x50;
    // Dst Port: 443 (0x01BB)
    raw[36] = 0x01; raw[37] = 0xBB;
    // Flags: SYN (0x02)
    raw[47] = 0x02;
    // Data Offset: 5 words (20 bytes) -> high 4 bits of byte 12
    raw[46] = 0x50;
    
    let parsed = parse_packet(&raw).expect("Should parse valid TCP packet");
    
    assert_eq!(parsed.protocol, Protocol::Tcp);
    assert_eq!(parsed.src_ip.to_string(), "10.0.0.1");
    assert_eq!(parsed.dst_ip.to_string(), "10.0.0.2");
    assert_eq!(parsed.src_port, Some(80));
    assert_eq!(parsed.dst_port, Some(443));
    
    let flags = parsed.tcp_flags.expect("TCP flags should be present");
    assert!(flags.syn);
    assert!(!flags.ack);
}
