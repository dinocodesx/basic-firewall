mod capture;
mod cli;
mod filter;
mod logger;
mod parser;
mod rules;
mod state;

use clap::Parser;
use cli::{Cli, Commands, Mode, RuleAction};

fn main() {
    let args = Cli::parse();

    // Initialize logging immediately
    logger::init_logger(&args.log);

    // Load configuration
    let config = match rules::loader::load_config(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[ERROR] Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    match args.command {
        Commands::Start { mode, interface } => {
            let state_table = state::table::create_table();
            run_firewall(mode, interface, config, state_table);
        }
        Commands::Rules { action } => handle_rules_command(action, config),
        Commands::Stats => println!("[!] Statistics reporting is coming in a future version."),
    }
}

fn run_firewall(
    mode: Mode,
    interface: Option<String>,
    config: rules::types::Config,
    state_table: state::table::ConnTable,
) {
    match mode {
        Mode::Sniff => {
            println!("[MODE] Passive Sniffer");
            let interfaces = capture::list_interfaces();
            let target = interface.unwrap_or_else(|| {
                let default = if cfg!(target_os = "macos") {
                    "en0"
                } else {
                    "eth0"
                };
                interfaces
                    .iter()
                    .find(|iface| iface.name == default && iface.is_up())
                    .map(|iface| iface.name.clone())
                    .or_else(|| {
                        interfaces
                            .iter()
                            .find(|iface| iface.is_up() && !iface.is_loopback())
                            .map(|iface| iface.name.clone())
                    })
                    .expect("No suitable network interface found.")
            });

            println!("[*] Listening on interface: {}", target);
            capture::start_capture(&target, config, state_table);
        }
        Mode::Block => {
            println!("[MODE] Active Blocker (Linux NFQueue)");
            if !cfg!(target_os = "linux") {
                eprintln!("[ERROR] Active 'block' mode requires Linux Netfilter (nfqueue).");
                std::process::exit(1);
            }
            filter::start_nfqueue(config, 0);
        }
    }
}

fn handle_rules_command(action: RuleAction, config: rules::types::Config) {
    match action {
        RuleAction::List => {
            println!("\n--- 🛡️  Active Firewall Rules ---");
            println!(
                "{:<20} {:<10} {:<10} {:<15} {:<15} {:<10}",
                "Name", "Action", "Proto", "Src IP", "Dst Port", "Direction"
            );
            println!("{:-<85}", "");

            for rule in config.rules {
                println!(
                    "{:<20} {:<10?} {:<10} {:<15} {:<15} {:<10}",
                    rule.name,
                    rule.action,
                    rule.protocol.unwrap_or_else(|| "Any".to_string()),
                    rule.src_ip.unwrap_or_else(|| "Any".to_string()),
                    rule.dst_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "Any".to_string()),
                    rule.direction.unwrap_or_else(|| "Any".to_string())
                );
            }
            println!();
        }
        RuleAction::Add { .. } | RuleAction::Remove { .. } => {
            println!("[!] Rule modification via CLI is not yet implemented.");
            println!("Please edit 'config/rules.toml' manually.");
        }
    }
}
