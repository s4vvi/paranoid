use clap::{Parser, builder::PossibleValuesParser};
use crate::globals::LOG_LEVELS;

/// Paranoid usage...
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Host to run on.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Entry port. 
    #[arg(long, default_value_t = 1337)]
    pub port: u16,

    /// Amount of nodes.
    #[arg(long, default_value_t = 2)]
    pub nodes: u16,

    /// The log level to use.
    #[arg(
        long,
        default_value = "info",
        value_parser = PossibleValuesParser::new(LOG_LEVELS)
    )]
    pub log_level: String,

    /// Coffee.
    #[arg(long, default_value_t = false)]
    pub coffee: bool,

    /// Node automatic regeneration rate.
    /// Random deviation as added per node.
    #[arg(long, default_value_t = 600)]
    pub base_regen_rate: u64,

    /// Max deviation for random node generation. 
    #[arg(long, default_value_t = 120)]
    pub max_regen_deviation: u64,
}
