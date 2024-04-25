use std::error::Error as StdError;
use std::fmt;
use console::style;
use log::Level;

use crate::globals;

//
// Basic utility funcitons
//
pub fn banner() {
    println!("{} {} - {}\n\n",
            style(globals::BANNER).bold().cyan(),
            style(globals::VERSION).bold(),
            style(globals::WEB_LINK).bold());
}

pub fn coffee() {
    println!("{} \n ur turn ^_^\n {}\n",
             style(globals::COFFEE).bold().cyan(),
             globals::BMC_LINK);
}

//
// Create things for logger
//
pub struct Logger;

impl log::Log for Logger {
   fn enabled(&self, _metadata: &log::Metadata) -> bool {
       true
   }

   fn log(&self, record: &log::Record) {
       if !self.enabled(record.metadata()) {
           return;
       }

       let level = match record.level() {
           Level::Info => style(record.level()).cyan(),
           Level::Warn => style(record.level()).yellow(),
           Level::Error => style(record.level()).red(),
           Level::Debug => style(record.level()).magenta(),
           Level::Trace => style(record.level()).blue(),
       };

       println!(
           "{}{}{} {}",
            style("[").dim(),
            level.bold(),
            style("]:").dim(),
            record.args()
        );
   }
   fn flush(&self) {}
}

//
// Create things for error handling
//
#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Message: {}", self.0)
    }
}

impl StdError for Error {}
