use rand::prelude::*;
use std::sync::Arc;
use std::fmt;
use tokio::sync::Mutex;
use anyhow::Result;
use tor_rtcompat::Runtime;
use arti_client::{TorClientConfig, TorClient};
use arti_client::BootstrapBehavior::OnDemand;

pub mod proxy;
pub mod regen;

/// Represents the client list
pub struct Clients<R: Runtime> {
    pub tors: Vec<Arc<Mutex<Client<R>>>>,
}

/// Implement the client list
impl<R: Runtime> Clients<R> {
    /// Create a new client list
    pub fn new() -> Self {
        Clients {
            tors: Vec::new()
        }
    }
    
    /// Get a random client from the list
    pub fn random(&self) -> &Arc<Mutex<Client<R>>> {
        // Generate a random index
        let index = (0..self.tors.len())
            .choose(&mut thread_rng())
            .unwrap();
        // Return a reference to the client
        &self.tors[index]
    }
}


/// Represents a TOR client
pub struct Client<R: Runtime> {
    pub id: u16,
    pub tor: TorClient<R>,
    pub runtime: R,
}


/// Implement Client
impl<R: Runtime> Client<R> {
    /// Create a new client
    ///
    /// # Arguments
    ///
    /// * `id`          - an integer as the unique ID
    /// * `runtime`     - the runtime to use
    /// * `config`      - the tor client configuration
    pub fn new(id: u16,
               runtime: &R,
               config: &TorClientConfig) -> Result<Self> {
        let runtime = runtime.clone();
        let client_builder = TorClient::with_runtime(runtime.clone())
            .config(config.clone())
            .bootstrap_behavior(OnDemand);
        let client = client_builder.create_unbootstrapped()?;

        Ok(Client {
            id,
            tor: client,
            runtime,
        })
    }

    /// Bootstrap the client (AKA connect to TOR)
    pub async fn bootstrap(&self) -> Result<()> {
        self.tor.bootstrap().await?;
        Ok(())
    }

    /// Regenerate the client
    pub fn regenerate(&mut self) -> Result<()> {
        // Create a new isolated client
        // Shares configuration but creates a different circut
        let client_builder = TorClient::with_runtime(self.runtime.clone())
            .config(TorClientConfig::default())
            .bootstrap_behavior(OnDemand);
        // Create an unbootstrapped client
        self.tor = client_builder.create_unbootstrapped()?;
        Ok(())
    }
}

impl<R: Runtime> fmt::Display for Client<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id: {:>2}", self.id)
    }
}

