use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use ip2location::{DB, Record};
use reqwest::Client;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;

const DB_V4_FILENAME: &str = "IP2LOCATION-LITE-DB5.BIN";
const DB_V6_FILENAME: &str = "IP2LOCATION-LITE-DB5.IPV6.BIN";
const TOKEN_FILENAME: &str = "token";

pub struct GeoIpManager {
    db_v4: Option<DB>,
    db_v6: Option<DB>,
}

impl GeoIpManager {
    pub fn new() -> Result<Self> {
        let config_dir = get_config_dir()?;
        let db_v4_path = config_dir.join(DB_V4_FILENAME);
        let db_v6_path = config_dir.join(DB_V6_FILENAME);

        let db_v4 = if db_v4_path.exists() {
            Some(DB::from_file(&db_v4_path).map_err(|e| anyhow!("Failed to load IPv4 DB: {}", e))?)
        } else {
            None
        };

        let db_v6 = if db_v6_path.exists() {
            Some(DB::from_file(&db_v6_path).map_err(|e| anyhow!("Failed to load IPv6 DB: {}", e))?)
        } else {
            None
        };

        Ok(Self { db_v4, db_v6 })
    }

    pub async fn ensure_databases_exist(&mut self) -> Result<()> {
        let config_dir = get_config_dir()?;
        let db_v4_path = config_dir.join(DB_V4_FILENAME);
        let db_v6_path = config_dir.join(DB_V6_FILENAME);

        if db_v4_path.exists() && db_v6_path.exists() {
            return Ok(());
        }

        // If either is missing, trigger setup
        println!("{}", "GeoIP Database Missing".bold().red());
        println!("This feature requires IP2Location LITE DB5 databases.");
        println!("Please follow these steps:");
        println!("1. Register a free account at https://lite.ip2location.com/database-download");
        println!("2. Copy your 'Download Token' from the dashboard.");
        println!();

        let token_path = config_dir.join(TOKEN_FILENAME);
        let saved_token = if token_path.exists() {
            fs::read_to_string(&token_path).await.ok()
        } else {
            None
        };

        let token = if let Some(t) = saved_token {
            let t = t.trim().to_string();
            print!("Found saved token: {}. Use this? [Y/n]: ", t);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() == "n" {
                prompt_for_token()?
            } else {
                t
            }
        } else {
            prompt_for_token()?
        };

        // Create config dir if not exists
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir).await?;
        }

        // Save token
        fs::write(&token_path, &token).await?;

        // Download and Install
        self.download_and_install(&token, &config_dir).await?;

        // Reload DBs
        *self = Self::new()?;

        Ok(())
    }

    async fn download_and_install(&self, token: &str, config_dir: &Path) -> Result<()> {
        let client = Client::new();

        let v4_url = format!(
            "https://www.ip2location.com/download/?token={}&file=DB5LITEBIN",
            token
        );
        let v6_url = format!(
            "https://www.ip2location.com/download/?token={}&file=DB5LITEBINIPV6",
            token
        );

        println!("Downloading IPv4 Database...");
        let v4_zip = config_dir.join("db4.zip");
        download_file(&client, &v4_url, &v4_zip).await?;

        println!("Downloading IPv6 Database...");
        let v6_zip = config_dir.join("db6.zip");
        download_file(&client, &v6_url, &v6_zip).await?;

        println!("Extracting Databases...");
        // Unzip
        unzip_and_move(&v4_zip, DB_V4_FILENAME, config_dir)?;
        unzip_and_move(&v6_zip, DB_V6_FILENAME, config_dir)?;

        // Cleanup
        let _ = fs::remove_file(v4_zip).await;
        let _ = fs::remove_file(v6_zip).await;

        println!("{}", "Database setup complete.".green());
        Ok(())
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoRecord> {
        let record = match ip {
            IpAddr::V4(_) => {
                if let Some(ref db) = self.db_v4 {
                    db.ip_lookup(ip).ok()?
                } else {
                    return None;
                }
            }
            IpAddr::V6(_) => {
                if let Some(ref db) = self.db_v6 {
                    db.ip_lookup(ip).ok()?
                } else {
                    return None;
                }
            }
        };

        let r = if let Record::LocationDb(rec) = record {
            rec
        } else {
            return None;
        };

        // Check if invalid (0.0.0.0 lat/long often means invalid)
        if r.latitude.unwrap_or(0.0) == 0.0 && r.longitude.unwrap_or(0.0) == 0.0 {
            // It might be valid 0,0 but unlikely for a user IP.
            // However, we just return what we have.
        }

        Some(GeoRecord {
            ip,
            country: r
                .country
                .map(|c| c.long_name.to_string())
                .unwrap_or_default(),
            region: r.region.map(|s| s.to_string()).unwrap_or_default(),
            city: r.city.map(|s| s.to_string()).unwrap_or_default(),
            latitude: r.latitude.unwrap_or(0.0),
            longitude: r.longitude.unwrap_or(0.0),
        })
    }
}

pub struct GeoRecord {
    pub ip: IpAddr,
    pub country: String,
    pub region: String,
    pub city: String,
    pub latitude: f32,
    pub longitude: f32,
}

fn get_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
    Ok(home.join(".config").join("pingx"))
}

fn prompt_for_token() -> Result<String> {
    print!("Enter your Download Token: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let token = input.trim().to_string();
    if token.is_empty() {
        return Err(anyhow!("Token cannot be empty"));
    }
    Ok(token)
}

async fn download_file(client: &Client, url: &str, path: &Path) -> Result<()> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Failed to download: {}", resp.status()));
    }
    let content = resp.bytes().await?;
    fs::write(path, content).await?;
    Ok(())
}

fn unzip_and_move(zip_path: &Path, target_filename: &str, dest_dir: &Path) -> Result<()> {
    // We unzip to dest_dir
    // unzip -o zip_path -d dest_dir
    let status = Command::new("unzip")
        .arg("-o")
        .arg(zip_path)
        .arg("-d")
        .arg(dest_dir)
        .output()
        .context("Failed to execute unzip command")?;

    if !status.status.success() {
        return Err(anyhow!(
            "Unzip failed: {}",
            String::from_utf8_lossy(&status.stderr)
        ));
    }

    // The zip might contain the file directly or in a folder?
    // Usually LITE DB zip contains: IP2LOCATION-LITE-DB5.BIN directly.
    // We need to ensure the file exists.
    let expected_path = dest_dir.join(target_filename);
    if !expected_path.exists() {
        // Sometimes it might be lowercase or something?
        // Let's check for case-insensitive match if needed, but usually it's standard.
        // Or maybe check if it extracted to a subdir?
        // For now assume standard structure.
        return Err(anyhow!("Extracted file not found: {:?}", expected_path));
    }

    Ok(())
}

pub fn print_geo_table(records: &[GeoRecord]) {
    // Determine max widths
    let mut w_ip = 13; // "IP" length
    let mut w_country = 7; // "Country"
    let mut w_region = 6; // "Region"
    let mut w_city = 4; // "City"

    for r in records {
        w_ip = w_ip.max(r.ip.to_string().len());
        w_country = w_country.max(r.country.len());
        w_region = w_region.max(r.region.len());
        w_city = w_city.max(r.city.len());
    }

    // Print Header
    println!(
        "{} | {} | {} | {} | {} | {}",
        format!("{:<width$}", "IP", width = w_ip).bold(),
        format!("{:>width$}", "Country", width = w_country).bold(),
        format!("{:>width$}", "Region", width = w_region).bold(),
        format!("{:>width$}", "City", width = w_city).bold(),
        format!("{:>10}", "Longitude").bold(),
        format!("{:>9}", "Latitude").bold(),
    );

    // Print Rows
    for r in records {
        println!(
            "{:<w_ip$} | {:>w_country$} | {:>w_region$} | {:>w_city$} | {:>10.6} | {:>9.6}",
            r.ip,
            r.country,
            r.region,
            r.city,
            r.longitude,
            r.latitude,
            w_ip = w_ip,
            w_country = w_country,
            w_region = w_region,
            w_city = w_city
        );
    }
}
