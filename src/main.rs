mod cli;
mod pinger;
mod session;
mod utils;
mod happy_eyeballs;

use clap::Parser;
use cli::Cli;
use session::Session;

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    if let Err(e) = utils::check_and_acquire_privileges(&args).await {
        eprintln!("pingx: {}", e);
        std::process::exit(1);
    }

    let session = Session::new(args);

    if let Err(e) = session.run().await {
        eprintln!("pingx: {}", e);
        std::process::exit(1);
    }
}
