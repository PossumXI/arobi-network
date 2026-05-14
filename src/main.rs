mod agents;
mod api;
mod audit;
mod block;
mod compute;
mod config;
mod consensus;
mod crypto;
mod fs;
mod llm;
mod mempool;
mod node;
mod p2p;
mod peer;
mod poi;
mod rate_limit;
mod security;
mod store;

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use config::NodeConfig;
use crypto::Wallet;
use node::Node;
use peer::normalize_peer_endpoint;

// ─── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "arobi-network",
    about = "Arobi Network — Proof of Intelligence Blockchain Node",
    version = "3.2.6",
    long_about = None
)]
struct Cli {
    /// Data directory (chain, wallet). Defaults to ~/.arobi
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage your node wallet
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Start the Arobi Network node
    Start {
        /// P2P TCP port to listen on
        #[arg(long, default_value_t = 30333)]
        p2p_port: u16,

        /// HTTP API port (falls back to PORT env var for PaaS platforms like Railway)
        #[arg(long)]
        api_port: Option<u16>,

        /// Seed node addresses, e.g. 1.2.3.4:30333 (can be repeated)
        #[arg(long = "seed")]
        seeds: Vec<String>,

        /// Optional seed list file (defaults to <data-dir>/seeds.txt if present)
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Public endpoint(s) this node advertises to peers, e.g. p2p.example.org:30333
        #[arg(long = "advertise-addr")]
        advertise_addrs: Vec<String>,

        /// Optional advertise endpoint file (defaults to <data-dir>/advertise.txt if present)
        #[arg(long)]
        advertise_file: Option<PathBuf>,

        /// Peer redial interval in seconds (minimum 5s)
        #[arg(long, default_value_t = 30)]
        redial_secs: u64,

        /// Run as relay-only node — do not produce blocks
        #[arg(long)]
        no_mine: bool,
    },
}

fn load_peer_endpoints(file_path: &std::path::Path, label: &str) -> anyhow::Result<Vec<String>> {
    if !file_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read {label} file {}", file_path.display()))?;

    let mut out = Vec::new();
    for line in content.lines() {
        let original = line.trim();
        if original.is_empty() || original.starts_with('#') {
            continue;
        }

        match normalize_peer_endpoint(original) {
            Some(endpoint) => out.push(endpoint),
            None => {
                tracing::warn!(
                    "Skipping invalid {label} endpoint '{}' in {} (expected host:port)",
                    original,
                    file_path.display()
                );
            }
        }
    }
    Ok(out)
}

fn dedup_preserve_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[derive(Subcommand)]
enum WalletAction {
    /// Generate a new Ed25519 wallet and save it to <data-dir>/wallet.json
    New,
    /// Print the wallet address and public key stored in <data-dir>/wallet.json
    Show,
}

// ─── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Structured logging — RUST_LOG=debug for verbose output
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    // Resolve data directory
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .expect("Cannot determine home directory")
            .join(".arobi")
    });
    std::fs::create_dir_all(&data_dir).context("Failed to create data directory")?;

    let wallet_path = data_dir.join("wallet.json");

    match cli.command {
        // ── wallet new ────────────────────────────────────────────────────────
        Commands::Wallet {
            action: WalletAction::New,
        } => {
            if wallet_path.exists() {
                eprintln!(
                    "Wallet already exists at {}\n\
                     Delete it manually if you want to generate a new one \
                     (WARNING: this will lose your existing key).",
                    wallet_path.display()
                );
                std::process::exit(1);
            }
            let wallet = Wallet::generate();
            wallet
                .save_to_file(&wallet_path)
                .context("Failed to save wallet")?;
            println!("✅  New wallet generated!");
            println!("    Address : {}", wallet.address);
            println!("    Pub key : {}", wallet.verifying_key_hex);
            println!("    Saved to: {}", wallet_path.display());
            println!();
            println!("⚠️  Keep wallet.json safe — it contains your signing key.");
            println!();
            println!("Next steps:");
            println!("  1. Copy your address above into config.rs → genesis::FOUNDER_ADDRESS");
            println!("     (only required once, before the network launches)");
            println!(
                "  2. Start your node: arobi-network start --data-dir {}",
                data_dir.display()
            );
        }

        // ── wallet show ───────────────────────────────────────────────────────
        Commands::Wallet {
            action: WalletAction::Show,
        } => {
            let wallet = Wallet::load_from_file(&wallet_path).context(format!(
                "No wallet found at {}. Run `arobi-network wallet new` first.",
                wallet_path.display()
            ))?;
            println!("Wallet: {}", wallet_path.display());
            println!("  Address : {}", wallet.address);
            println!("  Pub key : {}", wallet.verifying_key_hex);
        }

        // ── start ─────────────────────────────────────────────────────────────
        Commands::Start {
            p2p_port,
            api_port,
            seeds,
            seed_file,
            advertise_addrs,
            advertise_file,
            redial_secs,
            no_mine,
        } => {
            // Railway/PaaS: PORT env var takes precedence. CLI arg overrides if provided.
            let api_port = api_port.unwrap_or_else(|| {
                std::env::var("PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(8099)
            });
            let mine = !no_mine;

            // Load wallet (required for mining, optional for relay nodes)
            let wallet = if wallet_path.exists() {
                Some(Wallet::load_from_file(&wallet_path).context("Failed to load wallet")?)
            } else {
                if mine {
                    eprintln!(
                        "No wallet found at {}.\n\
                         Run `arobi-network wallet new` to create one,\n\
                         or start with --no-mine to run as a relay node.",
                        wallet_path.display()
                    );
                    std::process::exit(1);
                }
                None
            };

            if let Some(ref w) = wallet {
                tracing::info!("Validator address: {}", w.address);
            }

            let default_seed_file = data_dir.join("seeds.txt");
            let seed_path = seed_file.unwrap_or(default_seed_file);
            let mut seed_nodes = load_peer_endpoints(&seed_path, "seed")?;
            for seed in seeds {
                match normalize_peer_endpoint(&seed) {
                    Some(addr) => seed_nodes.push(addr),
                    None => {
                        tracing::warn!(
                            "Ignoring --seed '{}' (expected host:port or ip:port)",
                            seed
                        );
                    }
                }
            }
            dedup_preserve_order(&mut seed_nodes);

            if !seed_nodes.is_empty() {
                tracing::info!("Bootstrap seeds (IP:port): {}", seed_nodes.join(", "));
            } else {
                tracing::warn!(
                    "No bootstrap seeds configured. Add entries to {} or pass --seed.",
                    seed_path.display()
                );
            }

            let default_advertise_file = data_dir.join("advertise.txt");
            let advertise_path = advertise_file.unwrap_or(default_advertise_file);
            let mut advertised_addrs = load_peer_endpoints(&advertise_path, "advertise")?;
            for advertise in advertise_addrs {
                match normalize_peer_endpoint(&advertise) {
                    Some(addr) => advertised_addrs.push(addr),
                    None => {
                        tracing::warn!(
                            "Ignoring --advertise-addr '{}' (expected host:port or ip:port)",
                            advertise
                        );
                    }
                }
            }
            dedup_preserve_order(&mut advertised_addrs);
            if !advertised_addrs.is_empty() {
                tracing::info!(
                    "Advertised P2P endpoint(s): {}",
                    advertised_addrs.join(", ")
                );
            } else {
                tracing::warn!(
                    "No advertised P2P endpoint configured. Peers can connect if seeded, but rejoin/discovery is less reliable.\n\
                     Add --advertise-addr and/or populate {}",
                    advertise_path.display()
                );
            }

            let redial_interval_secs = redial_secs.max(5);
            if redial_interval_secs != redial_secs {
                tracing::warn!(
                    "--redial-secs {} too low; using {}s minimum",
                    redial_secs,
                    redial_interval_secs
                );
            }

            let config = NodeConfig {
                data_dir,
                p2p_port,
                api_port,
                seed_nodes,
                advertised_addrs,
                redial_interval_secs,
                mine,
            };

            Node::new(config, wallet)?.run().await?;
        }
    }

    Ok(())
}
