use pnet::datalink::{self, NetworkInterface};

/// Returns a list of all available network interfaces.
pub fn list_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

/// Finds a specific interface by its name.
pub fn get_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}
