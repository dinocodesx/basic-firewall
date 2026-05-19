use std::sync::Arc;
pub mod verdict;
use crate::rules::types::Config;

/// Holds the shared state for the active firewall.
/// Wrapped in Arc to allow safe sharing between threads and the nfqueue callback.
pub struct FirewallState {
    pub config: Config,
}

impl FirewallState {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self { config })
    }
}
