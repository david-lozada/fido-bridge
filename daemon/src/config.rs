use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub daemon_name: String,
    pub listen_addr: String,
    pub listen_port: u16,
    pub vendor_id: u32,
    pub product_id: u32,
    /// SHA-256 hex fingerprints of paired phone certificates.
    pub paired_phones: Vec<PairedPhone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedPhone {
    pub name: String,
    pub fingerprint: String,
    pub paired_at: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            daemon_name: hostname(),
            listen_addr: "0.0.0.0".into(),
            listen_port: 17443,
            // FIDO Alliance reserved test VID/PID style private range
            vendor_id: 0x1209,
            product_id: 0xF1D0,
            paired_phones: Vec::new(),
        }
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "fedora".into())
}

pub fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("dev", "fidobridge", "fido-bridged")
        .context("could not resolve config directories")
}

pub fn config_path() -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().join("config.json"))
}

pub fn data_dir() -> Result<PathBuf> {
    let d = project_dirs()?.data_dir().to_path_buf();
    fs::create_dir_all(&d)?;
    Ok(d)
}

pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        let cfg = Config::default();
        save_config(&cfg)?;
        return Ok(cfg);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_config(cfg: &Config) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(cfg)?;
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn cert_paths() -> Result<(PathBuf, PathBuf)> {
    let d = data_dir()?;
    Ok((d.join("daemon-cert.pem"), d.join("daemon-key.pem")))
}

pub fn audit_log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("audit.log"))
}

pub fn is_phone_paired(cfg: &Config, fp: &str) -> bool {
    cfg.paired_phones
        .iter()
        .any(|p| p.fingerprint.eq_ignore_ascii_case(fp))
}

pub fn revoke_phone(cfg: &mut Config, fingerprint: &str) -> bool {
    let before = cfg.paired_phones.len();
    cfg.paired_phones
        .retain(|p| !p.fingerprint.eq_ignore_ascii_case(fingerprint));
    before != cfg.paired_phones.len()
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}
