use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::runtime::Runtime;
use futures::future::join_all; 
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tor_rtcompat::BlockOn;
use arti_client::TorClientConfig;
use tor_config::Listen;
use log::{set_logger, set_max_level, LevelFilter};
use anyhow::Result;
use console::style;

use crate::tor;
use crate::utils;
use crate::args;

const LOGGER: utils::Logger = utils::Logger; 

// Used runtime for proxy
pub type TNTR = TokioNativeTlsRuntime;

pub struct App {
    args: args::Args,
    runtime: Runtime,
}

impl App {
    pub fn new(args: args::Args) -> Self {
        App {
            args,
            runtime: Runtime::new().unwrap()
        }
    }

    async fn initialize(
        nodes: u16,
        runtime: &TNTR,
        config: &TorClientConfig,
        clients: &Arc<Mutex<tor::Clients<TNTR>>>
    ) {
        // Populate clients
        let mut lock = clients.lock().await;
        for amount in 0..nodes {
            let client = Arc::new(
                Mutex::new(
                    tor::Client::new(amount, runtime, config).unwrap()
                )
            );
            lock.tors.push(client);
        }
        drop(lock);

        // Create tasks to bootstrap all clients asynchronously
        println!("Starting {} clients asynchronously...",
                 style(nodes).bold().green());
        
        let mut tasks = Vec::new();
        for client in &clients.lock().await.tors {
            let client = Arc::clone(&client);

            tasks.push(tokio::spawn(async move {
                let client = client.lock().await;
                let _ = client.bootstrap().await;

            println!("{} client {}.",
                     style("Initialized").bold().green(),
                     style(client).bold());
            }))
        }
        // Await all clients to be bootstrap
        join_all(tasks).await;
    }

    fn regen(&self, clients: &Arc<Mutex<tor::Clients<TNTR>>>) -> Result<()> {
        let base_rate = Duration::from_secs(self.args.base_regen_rate);
        let max_deviation = Duration::from_secs(self.args.max_regen_deviation);

        self.runtime.spawn(tor::regen::run(base_rate,
                                           max_deviation,
                                           self.args.nodes,
                                           Arc::clone(clients)));
        Ok(())
    }


    pub fn start(&mut self) -> Result<()> {
        if self.args.coffee {
            utils::coffee();
            return Ok(());
        }

        let level = match self.args.log_level.as_str() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info
        };

        utils::banner();
        
        set_logger(&LOGGER).map(|()| set_max_level(level)).unwrap();
        
        let listen = Listen::new_localhost(self.args.port);
        let config = TorClientConfig::default();
        let clients = Arc::new(Mutex::new(tor::Clients::<TNTR>::new()));
        let proxy_rt = TNTR::create().unwrap();

        proxy_rt.block_on(App::initialize(
                self.args.nodes,
                &proxy_rt,
                &config,
                &clients
        ));

        //
        // Setup and run
        // Run the automatic regeneration
        //
        self.regen(&clients).unwrap();
        

        let proxy_rt_copy = proxy_rt.clone();
        proxy_rt.block_on(tor::proxy::run(
            proxy_rt_copy,
            listen,
            clients,
        ))?;
        Ok(())
    }
}
