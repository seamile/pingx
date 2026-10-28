mod cli;
mod config;
mod geoip;
mod happy_eyeballs;
mod helper;
mod pinger;
mod probe;
mod session;
mod traceroute;
mod utils;
#[cfg(windows)]
mod windivert;

use clap::{CommandFactory, Parser};
use cli::Cli;
use session::Session;

#[tokio::main]
async fn main() {
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if raw_args.get(1).and_then(|arg| arg.to_str()) == Some("helper") {
        if let Err(error) = helper::run_command(&raw_args[2..]).await {
            eprintln!("pingx: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    match helper::run_internal(&raw_args[1..]).await {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("pingx: {error:#}");
            std::process::exit(1);
        }
    }

    if raw_args.len() == 1 {
        let _ = Cli::command().print_help();
        return;
    }

    let args = Cli::parse_from(raw_args);

    #[cfg(windows)]
    if args.interface.is_some() {
        eprintln!("pingx: interface binding (-I) is not supported on Windows");
        std::process::exit(1);
    }

    #[cfg(not(windows))]
    if let Some(iface) = args.interface.as_deref()
        && utils::get_interface_ips(iface).is_empty()
    {
        eprintln!(
            "pingx: interface '{}' has no usable non-loopback address",
            iface
        );
        std::process::exit(1);
    }
    utils::set_bind_interface(args.interface.clone());

    if args.traceroute {
        if let Err(error) = args.trace_target() {
            eprintln!("pingx: {}", error);
            std::process::exit(2);
        }
        if !(1..=2).contains(&args.targets.len()) {
            eprintln!("pingx: traceroute mode requires a target and an optional packet size");
            std::process::exit(2);
        }
        if let Some(size) = args.targets.get(1) {
            let Ok(value) = size.parse::<usize>() else {
                eprintln!("pingx: traceroute packet size must be an integer");
                std::process::exit(2);
            };
            if value == 0 || value > u16::MAX as usize {
                eprintln!("pingx: traceroute packet size must be between 1 and 65535 bytes");
                std::process::exit(2);
            }
        }
        if args.quiet {
            eprintln!("pingx: traceroute output cannot be quiet");
            std::process::exit(2);
        }
        match helper::run_if_needed(&args).await {
            Ok(Some(code)) => std::process::exit(code),
            Ok(None) => {}
            Err(error) => {
                eprintln!("pingx: {error:#}");
                std::process::exit(1);
            }
        }
        if let Err(e) = utils::check_and_acquire_privileges(&args).await {
            eprintln!("pingx: {}", e);
            std::process::exit(1);
        }
        let session = traceroute::TraceSession::new(args);
        if let Err(e) = session.run().await {
            eprintln!("pingx: {}", e);
            std::process::exit(1);
        }
        return;
    }

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
            if let Some(json_arg) = &args.json {
                // JSON Output
                let json_output = if records.len() == 1 {
                    serde_json::to_string_pretty(&records[0]).unwrap()
                } else {
                    serde_json::to_string_pretty(&records).unwrap()
                };

                if let Some(path) = json_arg {
                    if let Err(error) = session::write_json_file(path, json_output.as_bytes()) {
                        eprintln!("pingx: {error:#}");
                        std::process::exit(1);
                    }
                } else {
                    // Write to stdout
                    println!("{}", json_output);
                }
            } else {
                geoip::print_geo_table(&records);
            }
        }

        return;
    }

    match helper::run_if_needed(&args).await {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("pingx: {error:#}");
            std::process::exit(1);
        }
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
