mod capture;
mod parser;
mod rules;
mod filter;
mod state;
mod logger;
mod cli;

use clap::Parser;
use cli::{Cli, Commands, Mode, RuleAction};

fn main() {
    // 1. Parse CLI Arguments
    let args = Cli::parse();

    // 2. Initialize Logger
    logger::init_logger(&args.log);

    // 3. Load rules configuration
    let config = rules::loader::load_config(&args.config)
        .expect("Failed to load rules configuration. Please check the file path.");

    // 4. Handle Subcommands
    match args.command {
        Commands::Start { mode, interface } => {
            let state_table = state::table::create_table();
            
            match mode {
                Mode::Sniff => {
                    println!("[MODE] Passive Sniffer");
                    let interfaces = capture::list_interfaces();
                    
                    let target_iface = interface.as_deref().or_else(|| {
                        let default = if cfg!(target_os = "macos") { "en0" } else { "eth0" };
                        interfaces.iter()
                            .find(|iface| iface.name == default && iface.is_up())
                            .map(|iface| iface.name.as_str())
                    }).or_else(|| {
                        interfaces.iter()
                            .find(|iface| iface.is_up() && !iface.is_loopback())
                            .map(|iface| iface.name.as_str())
                    }).expect("No suitable network interface found.");

                    println!("[*] Listening on interface: {}", target_iface);
                    capture::start_capture(target_iface, config, state_table);
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
        Commands::Rules { action } => {
            match action {
                RuleAction::List => {
                    println!("--- 🛡️  Active Firewall Rules ---");
                    println!("{:<20} {:<10} {:<10} {:<15} {:<15} {:<10}", 
                        "Name", "Action", "Proto", "Src IP", "Dst Port", "Direction");
                    println!("{:-<85}", "");
                    
                    for rule in config.rules {
                        println!("{:<20} {:<10?} {:<10} {:<15} {:<15} {:<10}",
                            rule.name,
                            rule.action,
                            rule.protocol.unwrap_or_else(|| "Any".to_string()),
                            rule.src_ip.unwrap_or_else(|| "Any".to_string()),
                            rule.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "Any".to_string()),
                            rule.direction.unwrap_or_else(|| "Any".to_string())
                        );
                    }
                }
                RuleAction::Add { .. } => {
                    println!("[!] Rule addition via CLI is not yet implemented in the prototype.");
                    println!("Please edit 'config/rules.toml' manually.");
                }
                RuleAction::Remove { name } => {
                    println!("[!] Rule removal ('{}') via CLI is not yet implemented.", name);
                }
            }
        }
        Commands::Stats => {
            println!("[!] Statistics reporting is coming in a future version.");
        }
    }
}
