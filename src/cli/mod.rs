use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "rust-firewall")]
#[command(author = "Gemini CLI")]
#[command(version = "1.0")]
#[command(about = "A high-performance basic firewall prototype written in Rust.", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to the rules configuration file
    #[arg(short, long, default_value = "config/rules.toml")]
    pub config: String,

    /// Path to the log file
    #[arg(short, long, default_value = "logs/firewall.log")]
    pub log: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the firewall in the specified mode
    Start {
        /// Mode to run in: 'sniff' (passive) or 'block' (active, Linux only)
        #[arg(short, long, value_enum, default_value_t = Mode::Sniff)]
        mode: Mode,

        /// Network interface to listen on (required for sniff mode)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Manage firewall rules
    Rules {
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Display live packet processing statistics (Not yet implemented)
    Stats,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum Mode {
    Sniff,
    Block,
}

#[derive(Subcommand)]
pub enum RuleAction {
    /// List all currently loaded rules
    List,
    /// Add a new rule (Note: Currently only updates the local config file)
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        proto: Option<String>,
        #[arg(long)]
        src_ip: Option<String>,
        #[arg(long)]
        dst_ip: Option<String>,
        #[arg(long)]
        dst_port: Option<u16>,
        #[arg(long)]
        action: String,
    },
    /// Remove a rule by name
    Remove {
        #[arg(long)]
        name: String,
    },
}
