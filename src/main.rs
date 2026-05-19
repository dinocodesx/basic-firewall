mod capture;
mod parser;
mod rules;

fn main() {
    println!("--- Rust Firewall Sniffer ---");

    // Load rules configuration
    let config = rules::loader::load_config("config/rules.toml")
        .expect("Failed to load config/rules.toml. Please ensure the file exists.");

    println!("[*] Loaded {} rules", config.rules.len());

    // List available interfaces
    let interfaces = capture::list_interfaces();
    for iface in &interfaces {
        println!("Interface: {} | UP: {}", iface.name, iface.is_up());
    }

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
        .expect("No suitable network interface found. Please ensure you have an active network connection.");

    println!("[*] Selected interface: {}", target_iface);

    // Start capturing (requires root/sudo)
    capture::start_capture(target_iface, config);
}
