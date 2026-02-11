//! # CLI Commands
//!
//! Implementation of CLI commands for the Horizon application.

pub mod completions;
pub mod migrate;
pub mod validate;

use clap::{Args, Subcommand};

/// Available commands for the Horizon CLI
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the API server
    Serve(ServeArgs),

    /// Run database migrations
    Migrate(MigrateArgs),

    /// Generate shell completions
    Completions(CompletionsArgs),

    /// Verify configuration
    Validate,
}

/// Arguments for the serve command
#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Server host to bind to
    #[arg(long, env = "HORIZON_HOST", default_value = "0.0.0.0")]
    pub host: String,

    /// Server port to bind to
    #[arg(short, long, env = "HORIZON_PORT", default_value = "3000")]
    pub port: u16,

    /// Enable TLS/HTTPS
    #[arg(long, env = "HORIZON_TLS", requires_all = ["tls_cert", "tls_key"])]
    pub tls: bool,

    /// TLS certificate file path
    #[arg(long, env = "HORIZON_TLS_CERT", requires = "tls")]
    pub tls_cert: Option<String>,

    /// TLS key file path
    #[arg(long, env = "HORIZON_TLS_KEY", requires = "tls")]
    pub tls_key: Option<String>,
}

/// Arguments for the migrate command
#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// Run migrations in dry-run mode (no changes)
    #[arg(long)]
    pub dry_run: bool,

    /// Rollback the last migration
    #[arg(long)]
    pub rollback: bool,
}

/// Arguments for the completions command
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}
