use crate::parser::types::ParsedPacket;
use crate::rules::types::Action;
use std::fs::OpenOptions;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initializes the global logger to write JSON to a file.
pub fn init_logger(log_path: &str) {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("Cannot open or create log file");

    let file_layer = fmt::layer().with_writer(file).with_ansi(false).json();

    tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(file_layer)
        .init();
}

/// Logs a packet decision with full metadata.
pub fn log_packet(packet: &ParsedPacket, action: &Action, rule_name: &str) {
    info!(
        action      = ?action,
        rule        = rule_name,
        src_ip      = %packet.src_ip,
        dst_ip      = %packet.dst_ip,
        src_port    = packet.src_port,
        dst_port    = packet.dst_port,
        protocol    = ?packet.protocol,
        payload_len = packet.payload_len,
        "packet decision"
    );
}
