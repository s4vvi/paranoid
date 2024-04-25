use std::sync::Arc;
use std::collections::VecDeque;
use std::error::Error as StdError;
use std::time::Duration;
use tokio::time::sleep;
use tokio::sync::Mutex;
use log::{warn, error};
use anyhow::Result;
use rand::prelude::*;
use console::style;

use crate::tor::Clients;
use crate::app::TNTR;
use crate::utils::Error;

/// Represents the state of node regeneration queue
struct RegenQueue {
    inner: VecDeque<RegenItem>,
    next_regen: Duration,
    regenerated: u16,
    clients: Arc<Mutex<Clients<TNTR>>>,
    base_rate: Duration,
    max_deviation: Duration,
    node_amount: u16,
    rng: ThreadRng,
}


/// Holds regeneration specific node attributes
/// These are the ID for regeneration messages
/// and the rate at which the node shoud be regenerated
#[derive(Debug)]
struct RegenItem {
    id: u16,
    next: Duration,
}


/// TODO figureout how to get rid of this
/// Is it Okay??? probably not ^_^
unsafe impl Send for RegenQueue {}


impl RegenQueue {
    /// Initialize a new regeneration empty regeneration queue
    fn new(
        clients: Arc<Mutex<Clients<TNTR>>>,
        base_rate: Duration,
        max_deviation: Duration,
        node_amount: u16
    ) -> Self {

        Self {
            inner: VecDeque::new(),
            next_regen: Duration::default(),
            regenerated: 0,
            clients,
            base_rate,
            max_deviation,
            node_amount,
            rng: thread_rng(),
        }
    }

    /// Initialize the queue
    fn initialize(&mut self) {
        self.create_items();
        self.sort_queue();
        self.update_regen();
    }
    
    /// Add all items to the queue
    /// Each queue item represents a Node / TOR Client
    pub fn create_items(&mut self) {
        for id in 0..self.node_amount {
            // Generate the next regen time
            let next = self.new_regen_rate(); 

            self.inner.push_back(RegenItem {
                id, 
                next,
            });
        }
    }
    
    /// Generate a new random regeneration rate
    /// Used to randomize node regeneration within certain bounds
    fn new_regen_rate(&mut self) -> Duration {
        // Get a random duration within bounds
        let d = self.rng.gen_range(0..self.max_deviation.as_secs());
        let regen_dev = Duration::from_secs(d);

        // Calculate the regen rate
        // It is 50% chance to be added / subtracted from base rate
        let regen_rate: Duration;
        if self.rng.gen_bool(0.5) {
            regen_rate = self.base_rate + regen_dev;
        } else {
            regen_rate = self.base_rate - regen_dev;
        }

        return regen_rate;
    }
    
    /// Sort the queue by regeneration rate
    /// This is used at the start, so that the queue makes sense
    fn sort_queue(&mut self) {
        self.inner.rotate_right(self.inner.as_slices().1.len());
        self.inner.as_mut_slices().0.sort_by_key(|i| i.next);
    }

    /// Get the first regen item 
    fn first_item(&self) -> Result<&RegenItem, Box<dyn StdError>>{
        match self.inner.front() {
            Some(item) => Ok(item),
            None => Err(Box::new(Error("first item not found".into()))),
        }
    }

    /// Update next regen time with first items time
    fn update_regen(&mut self) {
        self.next_regen = match self.first_item() {
            Ok(item) => item.next,
            Err(err) => {
                error!("regen failed with `{}`", style(err).bold().red());
                return;
            }
        }
    }
    
    /// Execute the queue loop
    async fn execute(&mut self) {
        let mut first: &RegenItem;

        loop {
            // Sleep until next regen
            sleep(self.next_regen).await;

            // Regenerate the next node in queue
            match self.regen().await {
                Ok(_) => (),
                Err(err) => {
                    error!("regen failed with `{}`", style(err).bold().red());
                    continue;
                }
            }

            first = match self.first_item() {
                Ok(item) => item,
                Err(err) => {
                    error!("regen failed with `{}`",
                           style(err).bold().red());
                    continue;
                }
            };

            if self.regenerated < self.node_amount {
                self.next_regen = first.next - self.next_regen;
                continue;
            } 
            
            self.next_regen = first.next;
            self.regenerated = 0;
        }

    }

    async fn regen(&mut self) -> Result<(), Box<dyn StdError>> {
        // Lock clients
        let clients_lock = self.clients.lock().await;
            
        // Pop the scheduled item from queue
        let mut item = match self.inner.pop_front() {
            Some(item) => item,
            None =>
                return Err(Box::new(Error("can't fetch first item".into()))),
        };
        
        // Grab the client atomic reference
        let client = match clients_lock.tors.get(item.id as usize) {
            Some(client) => client,
            None => return Err(Box::new(Error("cant find item".into()))),
        };
        let client = Arc::clone(&client);
        drop(clients_lock);
        
        // Grab the lock of the client
        let mut client_lock = client.lock().await;
        
        // Regenerate & bootstrap the client
        warn!("Starting regenerating client ({})", style(&client_lock).bold());
        client_lock.regenerate().unwrap();
        client_lock.bootstrap().await.unwrap();
        warn!("Finished regenerating client ({})", style(&client_lock).bold());

        item.next = self.new_regen_rate();
        self.inner.push_back(item); 
        self.regenerated += 1;
        Ok(())
    }
}


/// Main run function that executes the regeneration
/// 
/// # Arguments
///
/// * `base_rate`     - the base interval at which to regenerate nodes
/// * `max_deviation` - the maximum for random deviation
/// * `node_amount`         - the amount of nodes created
/// * `clients`             - for client state updating, and regeneration
pub async fn run(
    base_rate: Duration,
    max_deviation: Duration,
    node_amount: u16,
    clients: Arc<Mutex<Clients<TNTR>>>,
) {
    // Create a new queue, add items & sort them
    let mut queue = RegenQueue::new(clients,
                                    base_rate,
                                    max_deviation,
                                    node_amount);
    queue.initialize();
    queue.execute().await;
}
