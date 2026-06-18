mod commands;
mod config;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use config::load_config;

#[derive(Parser)]
#[command(name = "zlicenser-server", version, about = "ZAL Licenser server")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP server (default when no subcommand is given)
    Serve,
    /// Generate a new vendor Ed25519 keypair
    Keygen,
    /// Switch to a new signing key for all future grants
    RotateKey {
        /// Path to the new key file (32-byte raw Ed25519 seed)
        #[arg(long)]
        new_key_path: PathBuf,
    },
    /// Interactive wizard to configure SMTP email settings
    ConfigureEmail,
    /// Set the dashboard admin password
    ConfigureDashboardPassword,
    /// Database management subcommands
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
    /// Audit subcommands
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// Sign a base64-encoded challenge nonce with the vendor key
    SignChallenge {
        /// Base64-encoded challenge nonce
        nonce: String,
    },
}

#[derive(Subcommand)]
enum DbCommands {
    /// Apply pending schema migrations (safe to run repeatedly)
    Migrate,
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Verify the integrity of the security event log
    Verify,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let (cfg, config_path) = load_config(cli.config.clone())?;

    // Initialise logging before anything else
    init_logging(&cfg);

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => commands::serve(cfg).await,
        Commands::Keygen => commands::keygen(&config_path).await,
        Commands::RotateKey { new_key_path } => {
            commands::rotate_key(&new_key_path, &config_path).await
        }
        Commands::ConfigureEmail => commands::configure_email(&config_path).await,
        Commands::ConfigureDashboardPassword => {
            commands::configure_dashboard_password(&config_path).await
        }
        Commands::Db {
            command: DbCommands::Migrate,
        } => commands::db_migrate(&cfg).await,
        Commands::Audit {
            command: AuditCommands::Verify,
        } => commands::audit_verify(&cfg).await,
        Commands::SignChallenge { nonce } => commands::sign_challenge(&nonce, &cfg).await,
    }
}

fn init_logging(cfg: &config::AppConfig) {
    use tracing_subscriber::{fmt, EnvFilter};

    let level = cfg
        .log
        .as_ref()
        .and_then(|l| l.level.as_deref())
        .unwrap_or("info");

    let format = cfg
        .log
        .as_ref()
        .and_then(|l| l.format.as_deref())
        .unwrap_or("pretty");

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            fmt().json().with_env_filter(filter).init();
        }
        _ => {
            fmt().with_env_filter(filter).init();
        }
    }
}
