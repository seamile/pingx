mod cli;
mod geoip;
mod happy_eyeballs;
mod pinger;
mod session;
mod utils;

use clap::{Parser, CommandFactory};
use cli::Cli;
use session::Session;

#[tokio::main]
async fn main() {
    if std::env::args().len() == 1 {
        let _ = Cli::command().print_help();
        return;
    }

    let args = Cli::parse();

    // GeoIP Fetch
    if args.fetch_geo {
        let mut geo_manager = match geoip::GeoIpManager::new() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("pingx: Failed to initialize GeoIP: {}", e);
                std::process::exit(1);
            }
        };

        if let Err(e) = geo_manager.fetch_geo_databases().await {
            eprintln!("pingx: GeoIP fetch failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // GeoIP Mode
    if args.geo {
        let mut geo_manager = match geoip::GeoIpManager::new() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("pingx: Failed to initialize GeoIP: {}", e);
                std::process::exit(1);
            }
        };

        if let Err(e) = geo_manager.ensure_databases_exist().await {
            eprintln!("pingx: GeoIP setup failed: {}", e);
            std::process::exit(1);
        }

        let mut records = Vec::new();
        for target in &args.targets {
            match utils::resolve_host(target, utils::IpVersion::Any).await {
                Ok(ips) => {
                    for ip in ips {
                        if let Some(record) = geo_manager.lookup(ip) {
                            records.push(record);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("pingx: Failed to resolve {}: {}", target, e);
                }
            }
        }

        if !records.is_empty() {
            geoip::print_geo_table(&records);
        }

        return;
    }

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
