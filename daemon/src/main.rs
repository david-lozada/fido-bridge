mod audit;
mod bridge;
mod config;
mod ctaphid;
mod dummy_phone;
mod local_ctap;
mod mdns;
mod pair;
mod protocol;
mod rate_limit;
mod tls;
mod uhid;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fido-bridged", version, about = "Phone WebAuthn biometric bridge for Fedora")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the daemon (virtual FIDO key + phone relay)
    Run,
    /// Show a QR code and wait for phone pairing
    Pair,
    /// List paired phones
    List,
    /// Revoke a paired phone by certificate fingerprint
    Revoke {
        fingerprint: String,
    },
    /// Dummy phone CLI for protocol testing
    DummyPhone {
        /// WebSocket URL (default wss://127.0.0.1:17443/ws)
        #[arg(long)]
        url: Option<String>,
        /// Path to pairing QR JSON to perform pairing then exit
        #[arg(long)]
        pair_json: Option<std::path::PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Run => {
            let cfg = config::load_config()?;
            bridge::run(cfg).await
        }
        Commands::Pair => {
            let cfg = config::load_config()?;
            pair::run_pairing(cfg).await
        }
        Commands::List => {
            let cfg = config::load_config()?;
            if cfg.paired_phones.is_empty() {
                println!("No paired phones.");
            } else {
                for p in &cfg.paired_phones {
                    println!("{}  {}  paired_at={}", p.fingerprint, p.name, p.paired_at);
                }
            }
            Ok(())
        }
        Commands::Revoke { fingerprint } => pair::revoke(&fingerprint),
        Commands::DummyPhone { url, pair_json } => dummy_phone::run(url, pair_json).await,
    }
}
