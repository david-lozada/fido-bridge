use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use time::OffsetDateTime;

use crate::config::audit_log_path;

pub struct AuditLog {
    inner: Mutex<()>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }

    pub fn log(&self, request_id: &str, rp_id: &str, result: &str) {
        let _guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(path) = audit_log_path() else {
            return;
        };
        let ts = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".into());
        let line = format!("{ts}\tid={request_id}\trp={rp_id}\tresult={result}\n");
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
        tracing::info!(%request_id, %rp_id, %result, "audit");
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ensure_audit_file() -> Result<()> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)?;
    Ok(())
}
