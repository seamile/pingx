mod cli;
mod pinger;
mod session;
mod utils;

use clap::Parser;
use cli::Cli;
use session::Session;

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let session = Session::new(args);

    if let Err(e) = session.run().await {
        eprintln!("pingx: {}", e);
        std::process::exit(1);
    }
}
