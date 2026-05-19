# Building a Basic Firewall in Rust — Project Plan

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Project Structure](#3-project-structure)
4. [Phase 1 — Packet Sniffer](#4-phase-1--packet-sniffer)
5. [Phase 2 — Packet Parser](#5-phase-2--packet-parser)
6. [Phase 3 — Rule Engine](#6-phase-3--rule-engine)
7. [Phase 4 — Netfilter Integration (Actual Blocking)](#7-phase-4--netfilter-integration-actual-blocking)
8. [Phase 5 — Stateful Inspection](#8-phase-5--stateful-inspection)
9. [Phase 6 — Logging System](#9-phase-6--logging-system)
10. [Phase 7 — CLI Interface](#10-phase-7--cli-interface)
11. [Testing Strategy](#11-testing-strategy)
12. [Dependency Reference](#12-dependency-reference)

---

## 1. Project Overview

### What We Are Building
A **userspace firewall** written in Rust that:
- Captures live network packets from a network interface
- Parses Ethernet, IPv4, TCP, UDP, and ICMP headers
- Evaluates packets against a configurable rule set
- Drops or accepts packets using Linux Netfilter (nfqueue)
- Logs all decisions to a structured log file
- Exposes a CLI to manage rules at runtime

### Architecture Diagram
```
Network Interface (eth0)
        │
        ▼
┌───────────────────┐
│   Packet Capture  │  ← pnet / pcap
│   (raw sockets)   │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Packet Parser    │  ← Extract IP, TCP, UDP, ICMP headers
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   Rule Engine     │  ← Match against rules (IP, port, protocol)
└────────┬──────────┘
         │
    ┌────┴────┐
    ▼         ▼
 ACCEPT     DROP
    │         │
    └────┬────┘
         ▼
┌───────────────────┐
│   Logger          │  ← Write decision + metadata to log
└───────────────────┘
```

### Key Design Decisions
| Decision | Choice | Reason |
|---|---|---|
| Packet capture | `pnet` + `nfqueue` | `pnet` for parsing, `nfqueue` for actual dropping |
| Rule storage | TOML config file | Human-readable, easy to reload at runtime |
| Concurrency | `tokio` async runtime | Non-blocking packet processing |
| Logging | `tracing` + `tracing-subscriber` | Structured, filterable logs |
| CLI | `clap` | Industry-standard arg parsing in Rust |

---

## 2. Prerequisites & Environment Setup

### System Requirements
- **OS:** Linux (Ubuntu 22.04+ recommended) — nfqueue is Linux-only
- **Rust:** 1.75+ (install via rustup)
- **Privileges:** Root or `CAP_NET_ADMIN` capability to open raw sockets

### Install System Dependencies
```bash
# libpcap — for raw packet capture
sudo apt update
sudo apt install -y libpcap-dev

# libnetfilter-queue — for hooking into kernel's packet queue
sudo apt install -y libnetfilter-queue-dev

# iptables — to redirect packets into our nfqueue
sudo apt install -y iptables

# Build essentials
sudo apt install -y build-essential pkg-config
```

### Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update stable
```

### Create the Project
```bash
cargo new rust-firewall
cd rust-firewall
```

### Initial `Cargo.toml`
```toml
[package]
name = "rust-firewall"
version = "0.1.0"
edition = "2021"

[dependencies]
# Packet capture and construction
pnet = "0.35"
pcap = "1.3"

# Netfilter queue (actual packet dropping in kernel)
nfqueue = "0.4"

# Async runtime
tokio = { version = "1", features = ["full"] }

# Config file parsing
toml = "0.8"
serde = { version = "1", features = ["derive"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# CLI
clap = { version = "4", features = ["derive"] }

# Utility
anyhow = "1"         # ergonomic error handling
chrono = "0.4"       # timestamps in logs
```

---

## 3. Project Structure

```
rust-firewall/
├── Cargo.toml
├── config/
│   └── rules.toml          # Firewall rules (loaded at startup)
├── logs/
│   └── firewall.log        # Runtime packet decision log
├── src/
│   ├── main.rs             # Entry point, wires everything together
│   ├── capture/
│   │   ├── mod.rs          # Packet capture module
│   │   └── interface.rs    # Network interface selection
│   ├── parser/
│   │   ├── mod.rs          # Packet parser module
│   │   ├── ethernet.rs     # Ethernet frame parsing
│   │   ├── ip.rs           # IPv4 header parsing
│   │   ├── tcp.rs          # TCP segment parsing
│   │   ├── udp.rs          # UDP datagram parsing
│   │   └── icmp.rs         # ICMP parsing
│   ├── rules/
│   │   ├── mod.rs          # Rule engine
│   │   ├── types.rs        # Rule struct definitions
│   │   └── loader.rs       # Load & reload rules from TOML
│   ├── filter/
│   │   ├── mod.rs          # Core filtering logic
│   │   └── verdict.rs      # Accept / Drop decision
│   ├── state/
│   │   ├── mod.rs          # Stateful connection tracking
│   │   └── table.rs        # Connection state table
│   ├── logger/
│   │   └── mod.rs          # Structured packet logging
│   └── cli/
│       └── mod.rs          # CLI command handling
└── tests/
    ├── parser_tests.rs
    └── rule_engine_tests.rs
```

---

## 4. Phase 1 — Packet Sniffer

**Goal:** Open a network interface and print every packet's basic metadata to stdout. No filtering yet.

### What to implement: `src/capture/mod.rs`

```rust
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;

pub fn list_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

pub fn start_capture(interface_name: &str) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Network interface not found");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    println!("[*] Listening on interface: {}", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    println!(
                        "[PACKET] src_mac={} dst_mac={} ethertype={:?}",
                        eth_packet.get_source(),
                        eth_packet.get_destination(),
                        eth_packet.get_ethertype()
                    );
                }
            }
            Err(e) => eprintln!("[ERROR] {}", e),
        }
    }
}
```

### `src/main.rs` for Phase 1
```rust
mod capture;

fn main() {
    // List available interfaces
    for iface in capture::list_interfaces() {
        println!("Interface: {} | UP: {}", iface.name, iface.is_up());
    }

    // Start capturing on eth0
    capture::start_capture("eth0");
}
```

### Run and Test
```bash
# Must run as root for raw socket access
sudo cargo run

# In another terminal, generate traffic
ping 8.8.8.8
curl http://example.com
```

**Expected output:**
```
[PACKET] src_mac=aa:bb:cc:dd:ee:ff dst_mac=ff:ff:ff:ff:ff:ff ethertype=Ipv4
[PACKET] src_mac=aa:bb:cc:dd:ee:ff dst_mac=... ethertype=Arp
```

---

## 5. Phase 2 — Packet Parser

**Goal:** Deeply inspect each packet. Extract source/destination IP, protocol, source/destination port, TCP flags, etc.

### Define a Parsed Packet struct: `src/parser/types.rs`
```rust
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Unknown(u8),
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

    // TCP-specific
    pub tcp_flags: Option<TcpFlags>,

    // Payload size
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}
```

### Implement the Parser: `src/parser/mod.rs`
```rust
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

pub fn parse_packet(raw: &[u8]) -> Option<ParsedPacket> {
    let eth = EthernetPacket::new(raw)?;

    // Only handle IPv4 for now
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(eth.payload())?;
    let protocol = match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp  => Protocol::TCP,
        IpNextHeaderProtocols::Udp  => Protocol::UDP,
        IpNextHeaderProtocols::Icmp => Protocol::ICMP,
        other => Protocol::Unknown(other.0),
    };

    let (src_port, dst_port, tcp_flags) = match &protocol {
        Protocol::TCP => {
            let tcp = TcpPacket::new(ipv4.payload())?;
            let flags = TcpFlags {
                syn: tcp.get_flags() & 0x02 != 0,
                ack: tcp.get_flags() & 0x10 != 0,
                fin: tcp.get_flags() & 0x01 != 0,
                rst: tcp.get_flags() & 0x04 != 0,
                psh: tcp.get_flags() & 0x08 != 0,
            };
            (Some(tcp.get_source()), Some(tcp.get_destination()), Some(flags))
        }
        Protocol::UDP => {
            let udp = UdpPacket::new(ipv4.payload())?;
            (Some(udp.get_source()), Some(udp.get_destination()), None)
        }
        _ => (None, None, None),
    };

    Some(ParsedPacket {
        src_mac: eth.get_source().to_string(),
        dst_mac: eth.get_destination().to_string(),
        src_ip: ipv4.get_source(),
        dst_ip: ipv4.get_destination(),
        ttl: ipv4.get_ttl(),
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        payload_len: ipv4.payload().len(),
    })
}
```

---

## 6. Phase 3 — Rule Engine

**Goal:** Define rules in a TOML config and match each parsed packet against them.

### `config/rules.toml`
```toml
[defaults]
policy = "accept"   # Default policy: "accept" or "drop"

[[rules]]
name        = "Block Telnet"
direction   = "inbound"
protocol    = "TCP"
dst_port    = 23
action      = "drop"

[[rules]]
name        = "Block specific IP"
direction   = "inbound"
src_ip      = "192.168.1.100"
action      = "drop"

[[rules]]
name        = "Allow DNS"
direction   = "outbound"
protocol    = "UDP"
dst_port    = 53
action      = "accept"

[[rules]]
name        = "Allow HTTP/HTTPS"
direction   = "outbound"
protocol    = "TCP"
dst_port    = 80
action      = "accept"

[[rules]]
name        = "Allow HTTPS"
direction   = "outbound"
protocol    = "TCP"
dst_port    = 443
action      = "accept"
```

### Rule Types: `src/rules/types.rs`
```rust
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub direction: Option<String>,   // "inbound" | "outbound"
    pub protocol: Option<String>,    // "TCP" | "UDP" | "ICMP"
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub action: Action,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub defaults: Defaults,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Defaults {
    pub policy: String, // "accept" or "drop"
}
```

### Rule Matching Engine: `src/rules/mod.rs`
```rust
use crate::parser::ParsedPacket;
use crate::rules::types::{Action, Config, Rule};

pub fn evaluate(packet: &ParsedPacket, config: &Config) -> Action {
    for rule in &config.rules {
        if matches_rule(packet, rule) {
            println!("[RULE MATCH] '{}' => {:?}", rule.name, rule.action);
            return rule.action.clone();
        }
    }

    // No rule matched — apply default policy
    match config.defaults.policy.as_str() {
        "drop" => Action::Drop,
        _      => Action::Accept,
    }
}

fn matches_rule(packet: &ParsedPacket, rule: &Rule) -> bool {
    // Check source IP
    if let Some(ref ip) = rule.src_ip {
        if packet.src_ip.to_string() != *ip {
            return false;
        }
    }

    // Check destination IP
    if let Some(ref ip) = rule.dst_ip {
        if packet.dst_ip.to_string() != *ip {
            return false;
        }
    }

    // Check protocol
    if let Some(ref proto) = rule.protocol {
        let packet_proto = match &packet.protocol {
            Protocol::TCP  => "TCP",
            Protocol::UDP  => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Unknown(_) => "UNKNOWN",
        };
        if proto != packet_proto {
            return false;
        }
    }

    // Check destination port
    if let Some(port) = rule.dst_port {
        if packet.dst_port != Some(port) {
            return false;
        }
    }

    // Check source port
    if let Some(port) = rule.src_port {
        if packet.src_port != Some(port) {
            return false;
        }
    }

    true // All specified fields matched
}
```

---

## 7. Phase 4 — Netfilter Integration (Actual Blocking)

**Goal:** Move from passive observation to **actively dropping packets** in the kernel using nfqueue.

### How nfqueue Works
```
Packet arrives at NIC
       │
       ▼
 Linux Kernel (iptables rule: -j NFQUEUE)
       │
       ▼
 Our Rust program receives packet via nfqueue
       │
  ┌────┴────┐
  │  Rust   │  evaluates rules
  └────┬────┘
       │
  ┌────┴────┐
  │ Verdict │  NF_ACCEPT or NF_DROP sent back to kernel
  └─────────┘
```

### Setup iptables to redirect traffic into queue
```bash
# Send all incoming traffic to queue #0
sudo iptables -A INPUT  -j NFQUEUE --queue-num 0

# Send all outgoing traffic to queue #1
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1

# To remove rules when done:
sudo iptables -D INPUT  -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
```

### `src/filter/mod.rs`
```rust
use nfqueue::{Message, Queue, Verdict};
use crate::parser::parse_packet;
use crate::rules::{evaluate, types::Config};
use crate::rules::types::Action;
use std::sync::Arc;

pub struct FirewallState {
    pub config: Config,
}

pub fn start_nfqueue(state: Arc<FirewallState>, queue_num: u16) {
    let mut queue = Queue::new(state);

    queue.open();
    queue.bind(queue_num).expect("Failed to bind to nfqueue");
    queue.set_callback(nfqueue_callback);

    println!("[*] nfqueue listening on queue {}", queue_num);
    queue.run_loop();  // blocking loop
}

fn nfqueue_callback(msg: &Message, state: &mut Arc<FirewallState>) {
    let payload = msg.get_payload();

    let verdict = match parse_packet(payload) {
        Some(packet) => {
            match evaluate(&packet, &state.config) {
                Action::Accept => Verdict::Accept,
                Action::Drop   => {
                    println!("[DROP] {}:{} -> {}:{}", 
                        packet.src_ip,
                        packet.src_port.unwrap_or(0),
                        packet.dst_ip,
                        packet.dst_port.unwrap_or(0)
                    );
                    Verdict::Drop
                }
            }
        }
        None => Verdict::Accept, // Can't parse? Let it through
    };

    msg.set_verdict(verdict);
}
```

---

## 8. Phase 5 — Stateful Inspection

**Goal:** Track TCP connection state so you can allow return traffic for established connections (prevents blocking your own replies).

### Connection State: `src/state/table.rs`
```rust
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use chrono::Utc;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    SynSent,
    Established,
    FinWait,
    Closed,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnKey {
    pub src_ip:   Ipv4Addr,
    pub dst_ip:   Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct ConnEntry {
    pub state:      ConnState,
    pub last_seen:  i64, // Unix timestamp
}

pub type ConnTable = Arc<Mutex<HashMap<ConnKey, ConnEntry>>>;

pub fn update_state(table: &ConnTable, key: ConnKey, flags: &TcpFlags) {
    let mut map = table.lock().unwrap();
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
        ConnState::Established
    };

    map.insert(key, ConnEntry { state: new_state, last_seen: now });
}

pub fn is_established(table: &ConnTable, key: &ConnKey) -> bool {
    let map = table.lock().unwrap();
    matches!(
        map.get(key),
        Some(ConnEntry { state: ConnState::Established, .. })
    )
}

// Periodically call this to clean up old connections
pub fn evict_stale(table: &ConnTable, timeout_secs: i64) {
    let mut map = table.lock().unwrap();
    let now = Utc::now().timestamp();
    map.retain(|_, entry| now - entry.last_seen < timeout_secs);
}
```

---

## 9. Phase 6 — Logging System

**Goal:** Write every packet decision to a structured log file for auditing.

### `src/logger/mod.rs`
```rust
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use std::fs::OpenOptions;

pub fn init_logger(log_path: &str) {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("Cannot open log file");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_writer(file)
        .with_ansi(false)  // no color codes in file
        .json()            // structured JSON logs
        .init();
}

pub fn log_packet(packet: &ParsedPacket, action: &str, rule_name: Option<&str>) {
    info!(
        action      = action,
        rule        = rule_name.unwrap_or("default-policy"),
        src_ip      = %packet.src_ip,
        dst_ip      = %packet.dst_ip,
        src_port    = packet.src_port,
        dst_port    = packet.dst_port,
        protocol    = ?packet.protocol,
        payload_len = packet.payload_len,
        "packet decision"
    );
}
```

### Sample log output (JSON)
```json
{"timestamp":"2025-05-01T12:00:00Z","level":"INFO","action":"DROP","rule":"Block Telnet","src_ip":"10.0.0.5","dst_ip":"10.0.0.1","src_port":54321,"dst_port":23,"protocol":"TCP","payload_len":0}
{"timestamp":"2025-05-01T12:00:01Z","level":"INFO","action":"ACCEPT","rule":"Allow HTTPS","src_ip":"10.0.0.5","dst_ip":"1.1.1.1","src_port":54400,"dst_port":443,"protocol":"TCP","payload_len":512}
```

---

## 10. Phase 7 — CLI Interface

**Goal:** Manage the firewall from the command line without restarting it.

### Commands to support
```bash
# List all active rules
sudo rust-firewall rules list

# Add a rule
sudo rust-firewall rules add --name "Block SSH" --proto TCP --dst-port 22 --action drop

# Remove a rule by name
sudo rust-firewall rules remove --name "Block SSH"

# Show live packet stats
sudo rust-firewall stats

# Reload rules from config file
sudo rust-firewall reload

# Show help
rust-firewall --help
```

### `src/cli/mod.rs`
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rust-firewall", about = "A basic firewall in Rust")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, default_value = "eth0")]
    pub interface: String,

    #[arg(short, long, default_value = "config/rules.toml")]
    pub config: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the firewall
    Start,

    /// List current rules
    Rules {
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Show packet statistics
    Stats,

    /// Reload rules from config file
    Reload,
}

#[derive(Subcommand)]
pub enum RuleAction {
    List,
    Add {
        #[arg(long)] name: String,
        #[arg(long)] proto: Option<String>,
        #[arg(long)] src_ip: Option<String>,
        #[arg(long)] dst_ip: Option<String>,
        #[arg(long)] dst_port: Option<u16>,
        #[arg(long)] action: String,
    },
    Remove {
        #[arg(long)] name: String,
    },
}
```

---

## 11. Testing Strategy

### Unit Tests
```bash
# Run all tests
cargo test

# Run specific module tests
cargo test parser
cargo test rule_engine
```

### Test scenarios to write:
- `parser_tests.rs`: Feed raw bytes of known packets → assert correct IP/port/protocol parsed
- `rule_engine_tests.rs`: Build a rule set → feed parsed packets → assert correct Action returned
- `state_tests.rs`: Simulate TCP handshake → assert state transitions are correct

### Manual Integration Testing
```bash
# Terminal 1: Start firewall
sudo cargo run -- start --interface eth0

# Terminal 2: Generate traffic to test rules
# Test blocked port
telnet localhost 23

# Test blocked IP (replace with a rule you added)
curl http://192.168.1.100

# Test allowed traffic
curl https://example.com
ping 8.8.8.8

# Verify in logs
tail -f logs/firewall.log | jq .
```

### Stress Testing
```bash
# Install hping3 for packet generation
sudo apt install hping3

# Flood packets to test performance
sudo hping3 -S -p 80 -i u1000 192.168.1.1

# Monitor CPU usage of your firewall
top -p $(pgrep rust-firewall)
```

---

## 12. Dependency Reference

| Crate | Version | Purpose |
|---|---|---|
| `pnet` | 0.35 | Low-level packet capture and construction |
| `pcap` | 1.3 | libpcap bindings for packet capture |
| `nfqueue` | 0.4 | Linux Netfilter queue for packet verdicts |
| `tokio` | 1 | Async runtime for concurrent packet handling |
| `serde` | 1 | Serialization/deserialization framework |
| `toml` | 0.8 | Parse TOML config files |
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 | Log output formatting and filtering |
| `clap` | 4 | CLI argument parsing |
| `anyhow` | 1 | Ergonomic error handling |
| `chrono` | 0.4 | Timestamps for logs and connection tracking |

---

## Build & Run Reference

```bash
# Debug build (faster compile, slower binary)
sudo cargo run -- start

# Release build (optimized, use for testing performance)
cargo build --release
sudo ./target/release/rust-firewall start --interface eth0

# Check for compile errors without building
cargo check

# Format code
cargo fmt

# Lint
cargo clippy
```

> **Important:** Always run with `sudo` or grant the binary `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities for raw socket access.
```bash
# Alternative to sudo — grant capabilities to binary
sudo setcap cap_net_admin,cap_net_raw=eip ./target/release/rust-firewall
```
