use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub direction: Option<String>, // "inbound" | "outbound"
    pub protocol: Option<String>,  // "TCP" | "UDP" | "ICMP"
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
