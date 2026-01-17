pub mod country_brief;

use crate::config::ConfigManager;
use anyhow::{Result, anyhow};
use colored::Colorize;
use ip2location::{DB, Record};
use reqwest::Client;
use serde::Serialize;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tokio::fs;

pub struct GeoIpManager {
    config_manager: ConfigManager,
    db_v4: Option<DB>,
    db_v6: Option<DB>,
}

impl GeoIpManager {
    pub fn new() -> Result<Self> {
        let config_manager = ConfigManager::new()?;
        let config_dir = config_manager.get_config_dir();

        let db_v4 = if let Some(ref filename) = config_manager.config.ipv4_db {
            let path = config_dir.join(filename);
            if path.exists() {
                Some(DB::from_file(&path).map_err(|e| anyhow!("Failed to load IPv4 DB: {}", e))?)
            } else {
                None
            }
        } else {
            None
        };

        let db_v6 = if let Some(ref filename) = config_manager.config.ipv6_db {
            let path = config_dir.join(filename);
            if path.exists() {
                Some(DB::from_file(&path).map_err(|e| anyhow!("Failed to load IPv6 DB: {}", e))?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config_manager,
            db_v4,
            db_v6,
        })
    }

    pub async fn ensure_databases_exist(&mut self) -> Result<()> {
        let has_v4 = self.db_v4.is_some();
        let has_v6 = self.db_v6.is_some();

        if has_v4 && has_v6 {
            return Ok(());
        }

        let token = self.get_token_strategy().await?;

        // Download and Install
        if let Err(e) = self.download_and_install(&token, !has_v4, !has_v6).await {
            println!("{}", format!("Failed to download database: {}", e).red());
            println!("Please check if your token is valid.");
            return Err(e);
        }

        // Reload DBs
        *self = Self::new()?;

        Ok(())
    }

    pub async fn fetch_geo_databases(&mut self) -> Result<()> {
        println!("{}", "Fetching GeoIP Database...".bold().blue());

        let mut need_v4 = true;
        let mut need_v6 = true;
        let now = SystemTime::now();
        let config_dir = self.config_manager.get_config_dir();

        // Check IPv4
        if let Some(ref filename) = self.config_manager.config.ipv4_db {
            let path = config_dir.join(filename);
            if path.exists()
                && let Ok(metadata) = std::fs::metadata(&path)
                && let Ok(mtime) = metadata.modified()
                && let Ok(elapsed) = now.duration_since(mtime)
                && elapsed < Duration::from_secs(6 * 3600)
            {
                println!(
                    "{}",
                    format!(
                        "IPv4 Database is up-to-date (updated {:.1} hours ago).",
                        elapsed.as_secs_f64() / 3600.0
                    )
                    .green()
                );
                need_v4 = false;
            }
        }

        // Check IPv6
        if let Some(ref filename) = self.config_manager.config.ipv6_db {
            let path = config_dir.join(filename);
            if path.exists()
                && let Ok(metadata) = std::fs::metadata(&path)
                && let Ok(mtime) = metadata.modified()
                && let Ok(elapsed) = now.duration_since(mtime)
                && elapsed < Duration::from_secs(6 * 3600)
            {
                println!(
                    "{}",
                    format!(
                        "IPv6 Database is up-to-date (updated {:.1} hours ago).",
                        elapsed.as_secs_f64() / 3600.0
                    )
                    .green()
                );
                need_v6 = false;
            }
        }

        if !need_v4 && !need_v6 {
            return Ok(());
        }

        let token = self.get_token_strategy().await?;

        if let Err(e) = self.download_and_install(&token, need_v4, need_v6).await {
            println!("{}", format!("Fetch failed: {}", e).red());
            println!("Please check if your token is valid.");
            return Err(e);
        }

        // Reload DBs
        *self = Self::new()?;

        Ok(())
    }

    async fn get_token_strategy(&mut self) -> Result<String> {
        if let Some(ref t) = self.config_manager.config.token
            && !t.is_empty()
        {
            return Ok(t.clone());
        }

        // If missing or empty, prompt
        println!("{}", "GeoIP Download Token Missing".bold().red());
        println!("This feature requires IP2Location LITE DB5 databases.");
        println!("Please follow these steps:");
        println!("1. Register a free account at https://lite.ip2location.com/database-download");
        println!("2. Copy your 'Download Token' from the dashboard.");
        println!();

        let token = prompt_for_token()?;
        self.config_manager.config.token = Some(token.clone());
        self.config_manager.save()?;

        Ok(token)
    }

    async fn download_and_install(
        &mut self,
        token: &str,
        need_v4: bool,
        need_v6: bool,
    ) -> Result<()> {
        let client = Client::new();
        let config_dir = self.config_manager.get_config_dir();

        if need_v4 {
            let v4_url = format!(
                "https://www.ip2location.com/download/?token={}&file=DB5LITEBIN",
                token
            );
            println!("Downloading IPv4 Database...");
            let v4_zip = config_dir.join("db4.zip");
            download_file(&client, &v4_url, &v4_zip).await?;
            println!("Extracting IPv4 Database...");
            let filename = extract_zip(&v4_zip, &config_dir)?;
            self.config_manager.config.ipv4_db = Some(filename);
            let _ = fs::remove_file(v4_zip).await;
        }

        if need_v6 {
            let v6_url = format!(
                "https://www.ip2location.com/download/?token={}&file=DB5LITEBINIPV6",
                token
            );
            println!("Downloading IPv6 Database...");
            let v6_zip = config_dir.join("db6.zip");
            download_file(&client, &v6_url, &v6_zip).await?;
            println!("Extracting IPv6 Database...");
            let filename = extract_zip(&v6_zip, &config_dir)?;
            self.config_manager.config.ipv6_db = Some(filename);
            let _ = fs::remove_file(v6_zip).await;
        }

        self.config_manager.save()?;

        // Cleanup Garbage
        let garbage = vec!["LICENSE_LITE.TXT", "README_LITE.TXT"];
        for g in garbage {
            let p = config_dir.join(g);
            if p.exists() {
                let _ = fs::remove_file(p).await;
            }
        }

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

        Some(GeoRecord {
            ip,
            country: r
                .country
                .map(|c| {
                    let short = c.short_name;
                    let long = c.long_name;
                    self::country_brief::get_brief_name(&short)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| long.to_string())
                })
                .unwrap_or_default(),
            region: r.region.map(|s| s.to_string()).unwrap_or_default(),
            city: r.city.map(|s| s.to_string()).unwrap_or_default(),
            latitude: r.latitude.unwrap_or(0.0),
            longitude: r.longitude.unwrap_or(0.0),
        })
    }
}

#[derive(Serialize)]
pub struct GeoRecord {
    pub ip: IpAddr,
    pub country: String,
    pub region: String,
    pub city: String,
    pub latitude: f32,
    pub longitude: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_ip_manager_new_no_db() {
        // This test assumes databases might not exist in the test environment,
        // or checks graceful fallback.
        // Since we can't easily mock file system existence for integration tests without temp dirs,
        // we check if it returns Ok regardless (it returns Ok with None dbs).
        let manager = GeoIpManager::new();
        assert!(manager.is_ok());
        let _manager = manager.unwrap();
        // If DBs missing, these should be None
        // We can't assert strict None/Some because local dev env might have them.
        // But we can check lookup returns None if we force empty manager
        let empty_manager = GeoIpManager {
            config_manager: ConfigManager::new().unwrap(),
            db_v4: None,
            db_v6: None,
        };
        assert!(empty_manager.lookup("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn test_extract_zip_recursive() -> Result<()> {
        use std::io::Write;

        // Setup temp dir
        let temp_dir = std::env::temp_dir().join("pingx_test_extract");
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir)?;
        }
        std::fs::create_dir_all(&temp_dir)?;

        let zip_path = temp_dir.join("test.zip");
        let dest_dir = temp_dir.join("out");
        std::fs::create_dir_all(&dest_dir)?;

        // Create a ZIP file with nested structure
        // root/
        //   nested/
        //     DATA.TXT
        //     deep/
        //       TARGET.BIN
        {
            let file = std::fs::File::create(&zip_path)?;
            let mut zip = zip::ZipWriter::new(file);

            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("nested/DATA.TXT", options)?;
            zip.write_all(b"dummy data")?;

            // Case insensitive check: Target.Bin
            zip.start_file("nested/deep/Target.Bin", options)?;
            zip.write_all(b"DB CONTENT")?;

            zip.finish()?;
        }

        // Test extraction
        let extracted_name = extract_zip(&zip_path, &dest_dir)?;

        // Should return the filename found
        assert_eq!(extracted_name, "Target.Bin");

        // Check if file exists in dest_dir
        let extracted_path = dest_dir.join("Target.Bin");
        assert!(extracted_path.exists());

        let content = std::fs::read_to_string(extracted_path)?;
        assert_eq!(content, "DB CONTENT");

        // Cleanup
        std::fs::remove_dir_all(&temp_dir)?;
        Ok(())
    }
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
        if resp.status().as_u16() == 403 || resp.status().as_u16() == 401 {
            return Err(anyhow!(
                "Download failed (HTTP {}). Invalid Token?",
                resp.status()
            ));
        }
        return Err(anyhow!("Failed to download: {}", resp.status()));
    }
    let content = resp.bytes().await?;
    fs::write(path, content).await?;
    Ok(())
}

fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<String> {
    let mut file = File::open(zip_path)?;

    // Check Magic Number for PK Zip signature
    let mut magic = [0u8; 2];
    if file.read(&mut magic).is_ok() && (magic != [0x50, 0x4B]) {
        // Not a zip file, likely an error text
        file.rewind()?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let msg = if content.len() > 200 {
            format!("{}...", &content[..200])
        } else {
            content
        };
        return Err(anyhow!("Download Error: {}", msg.trim()));
    }
    file.rewind()?; // Reset for ZipArchive

    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();

        // Match *.bin or *.BIN
        if name.to_uppercase().ends_with(".BIN") {
            // Get just the filename if it's in a subdirectory
            let filename = Path::new(&name)
                .file_name()
                .ok_or_else(|| anyhow!("Invalid filename in zip: {}", name))?
                .to_str()
                .ok_or_else(|| anyhow!("Non-unicode filename in zip: {}", name))?
                .to_string();

            let dest_path = dest_dir.join(&filename);
            let mut outfile = File::create(&dest_path)?;
            io::copy(&mut file, &mut outfile)?;
            return Ok(filename);
        }
    }

    Err(anyhow!("No .bin database file found in archive"))
}

pub fn print_geo_table(records: &[GeoRecord]) {
    // Determine max widths
    // Ensure header is covered
    let mut w_ip = "IP".len();
    let mut w_country = "Country".len();
    let mut w_region = "Region".len();
    let mut w_city = "City".len();

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
        format!("{:>10}", "Latitude").bold(),
        format!("{:>10}", "Longitude").bold(),
    );

    // Print Rows
    for r in records {
        println!(
            "{:<w_ip$} | {:>w_country$} | {:>w_region$} | {:>w_city$} | {:>10.6} | {:>10.6}",
            r.ip,
            r.country,
            r.region,
            r.city,
            r.latitude,
            r.longitude,
            w_ip = w_ip,
            w_country = w_country,
            w_region = w_region,
            w_city = w_city
        );
    }
}
