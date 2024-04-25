use clap::Parser;
use anyhow::Result;

mod args;
mod tor;
mod app;
mod utils;
mod globals;

use args::Args;

fn main() -> Result<()> { 
    let cmdline = Args::parse();
    let mut app = app::App::new(cmdline);
    app.start()?;
    Ok(())
}
