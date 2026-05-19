mod capture;
mod parser;
mod rules;
mod filter;

use std::env;

fn main() {
    println!("--- 🔥 Rust Firewall Prototype ---");

    // Load rules configuration
    let config = rules::loader::load_config("config/rules.toml")
        .expect("Failed to load config/rules.toml. Please ensure the file exists.");

    println!("[*] Loaded {} rules", config.rules.len());

    // Simple CLI argument handling for modes
    let args: Vec<String> = env::args().collect();
    let mode = if args.len() > 1 {
        args[1].to_lowercase()
    } else {
        "sniff".to_string()
    };

    match mode.as_str() {
        "sniff" => {
            println!("[MODE] Passive Sniffer");
            // List available interfaces
            let interfaces = capture::list_interfaces();

            // Attempt to find a suitable interface to listen on
            let default_interface = if cfg!(target_os = "macos") {
                "en0"
            } else {
                "eth0"
            };

            let target_iface = interfaces
                .iter()
                .find(|iface| iface.name == default_interface && iface.is_up())
                .map(|iface| iface.name.as_str())
                .or_else(|| {
                    // Fallback to the first up interface that isn't loopback
                    interfaces.iter()
                        .find(|iface| iface.is_up() && !iface.is_loopback())
                        .map(|iface| iface.name.as_str())
                })
                .expect("No suitable network interface found.");

            println!("[*] Selected interface: {}", target_iface);
            capture::start_capture(target_iface, config);
        }
        "block" => {
            println!("[MODE] Active Blocker (Linux NFQueue)");
            // Check if we are on Linux
            if !cfg!(target_os = "linux") {
                eprintln!("[ERROR] Active 'block' mode requires Linux Netfilter (nfqueue).");
                std::process::exit(1);
            }

            // Start the active blocker on Queue #0
            filter::start_nfqueue(config, 0);
        }
        _ => {
            println!("Usage: sudo cargo run -- [sniff|block]");
            println!("  sniff: Passive observation (works on macOS/Linux)");
            println!("  block: Active packet dropping (requires Linux)");
        }
    }
}

