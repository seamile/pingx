use anyhow::{Result, anyhow};
use colored::Colorize;
use ip2location::{DB, Record};
use reqwest::Client;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};
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

        let token = self.get_token_strategy(&config_dir, false).await?;

        // Download and Install
        if let Err(e) = self.download_and_install(&token, &config_dir, true, true).await {
            println!("{}", format!("Failed to download database: {}", e).red());
            println!("Please check if your token is valid.");
            println!("You can check/update your token at: {}", config_dir.join(TOKEN_FILENAME).display());
            return Err(e);
        }

        // Reload DBs
        *self = Self::new()?;

        Ok(())
    }

    pub async fn fetch_geo_databases(&mut self) -> Result<()> {
        let config_dir = get_config_dir()?;

        println!("{}", "Fetching GeoIP Database...".bold().blue());

        let mut need_v4 = true;
        let mut need_v6 = true;
        let now = SystemTime::now();

        // Check IPv4
        let db_v4_path = config_dir.join(DB_V4_FILENAME);
        if db_v4_path.exists()
            && let Ok(metadata) = std::fs::metadata(&db_v4_path)
                && let Ok(mtime) = metadata.modified()
                    && let Ok(elapsed) = now.duration_since(mtime)
                        && elapsed < Duration::from_secs(6 * 3600) {
                            println!("{}", format!("IPv4 Database is up-to-date (updated {:.1} hours ago).", elapsed.as_secs_f64() / 3600.0).green());
                            need_v4 = false;
                        }

        // Check IPv6
        let db_v6_path = config_dir.join(DB_V6_FILENAME);
        if db_v6_path.exists()
            && let Ok(metadata) = std::fs::metadata(&db_v6_path)
                && let Ok(mtime) = metadata.modified()
                    && let Ok(elapsed) = now.duration_since(mtime)
                        && elapsed < Duration::from_secs(6 * 3600) {
                            println!("{}", format!("IPv6 Database is up-to-date (updated {:.1} hours ago).", elapsed.as_secs_f64() / 3600.0).green());
                            need_v6 = false;
                        }

        if !need_v4 && !need_v6 {
            return Ok(());
        }

        let token = self.get_token_strategy(&config_dir, true).await?;

        if let Err(e) = self.download_and_install(&token, &config_dir, need_v4, need_v6).await {
             println!("{}", format!("Fetch failed: {}", e).red());
             println!("Please check if your token is valid.");
             return Err(e);
        }

        // Reload DBs
        *self = Self::new()?;

        Ok(())
    }

    async fn get_token_strategy(&self, config_dir: &Path, force_prompt_if_missing: bool) -> Result<String> {
        let token_path = config_dir.join(TOKEN_FILENAME);

        // Ensure config dir exists
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir).await?;
        }

        let saved_token = if token_path.exists() {
            fs::read_to_string(&token_path).await.ok().map(|s| s.trim().to_string())
        } else {
            None
        };

        // If we have a saved token, and we are NOT in a context that requires re-verification explicitly (unless failed),
        // we just use it.
        if let Some(t) = saved_token
            && !t.is_empty() {
                 if force_prompt_if_missing {
                    // Even if force prompt is requested, if we have a token, we might want to ask "Use this?"
                    // But requirement says: "If token file exists... direct use token".
                    // The "force prompt" context was usually for when a previous attempt failed.
                    // But here, let's stick to: if token exists, use it.
                    // Wait, if fetch_geo is called, we definitely want to use the stored token first without prompt.
                    return Ok(t);
                 }
                return Ok(t);
            }

        // If missing or empty, prompt
        println!("{}", "GeoIP Database/Token Missing".bold().red());
        println!("This feature requires IP2Location LITE DB5 databases.");
        println!("Please follow these steps:");
        println!("1. Register a free account at https://lite.ip2location.com/database-download");
        println!("2. Copy your 'Download Token' from the dashboard.");
        println!();

        let token = prompt_for_token()?;
        fs::write(&token_path, &token).await?;

        Ok(token)
    }

    async fn download_and_install(&self, token: &str, config_dir: &Path, need_v4: bool, need_v6: bool) -> Result<()> {
        let client = Client::new();

        if need_v4 {
            let v4_url = format!(
                "https://www.ip2location.com/download/?token={}&file=DB5LITEBIN",
                token
            );
            println!("Downloading IPv4 Database...");
            let v4_zip = config_dir.join("db4.zip");
            download_file(&client, &v4_url, &v4_zip).await?;
            println!("Extracting IPv4 Database...");
            extract_zip(&v4_zip, DB_V4_FILENAME, config_dir)?;
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
            extract_zip(&v6_zip, DB_V6_FILENAME, config_dir)?;
            let _ = fs::remove_file(v6_zip).await;
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_config_dir() {
        let dir = get_config_dir();
        assert!(dir.is_ok());
        let path = dir.unwrap();
        assert!(path.ends_with(".config/pingx"));
    }

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
        let empty_manager = GeoIpManager { db_v4: None, db_v6: None };
        assert!(empty_manager.lookup("8.8.8.8".parse().unwrap()).is_none());
    }
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
        if resp.status().as_u16() == 403 || resp.status().as_u16() == 401 {
             return Err(anyhow!("Download failed (HTTP {}). Invalid Token?", resp.status()));
        }
        return Err(anyhow!("Failed to download: {}", resp.status()));
    }
    let content = resp.bytes().await?;
    fs::write(path, content).await?;
    Ok(())
}

fn extract_zip(zip_path: &Path, target_filename: &str, dest_dir: &Path) -> Result<()> {
    let mut file = File::open(zip_path)?;

    // Check Magic Number for PK Zip signature
    let mut magic = [0u8; 2];
    if file.read(&mut magic).is_ok() && (magic != [0x50, 0x4B]) {
        // Not a zip file, likely an error text
        file.rewind()?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        // Truncate if too long (optional)
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
        let name = file.name().to_string(); // Clone name to avoid borrow issues if needed

        // We only extract the target file
        // The zip might contain the file in a subdir? Usually LITE DB is flat or single folder.
        // We match by checking if the filename ends with the target filename (case insensitive?)
        // The target filename is strict here: IP2LOCATION-LITE-DB5.BIN

        // Simple case: Exact match
        if name == target_filename || name.ends_with(&format!("/{}", target_filename)) {
            let dest_path = dest_dir.join(target_filename);
            let mut outfile = File::create(&dest_path)?;
            io::copy(&mut file, &mut outfile)?;
            return Ok(());
        }

        // Case-insensitive fallback?
        if name.eq_ignore_ascii_case(target_filename) {
             let dest_path = dest_dir.join(target_filename);
             let mut outfile = File::create(&dest_path)?;
             io::copy(&mut file, &mut outfile)?;
             return Ok(());
        }
    }

    Err(anyhow!("File {} not found in archive", target_filename))
}

pub fn print_geo_table(records: &[GeoRecord]) {
    // Determine max widths
    // Ensure header is covered
    let mut w_ip = "IP".len();
    let mut w_country = "Country".len();
    let mut w_region = "Region".len();
    let mut w_city = "City".len();
    // Fixed width for Lat/Long (header "Longitude" is 9, "Latitude" is 8)
    // Values are formatted as {:>10.6} and {:>9.6} which results in fixed width.
    // 10.6 -> 3 digits + 1 dot + 6 decimals = 10 chars. OK.
    // Longitude header is 9 chars.
    // Latitude header is 8 chars.

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
