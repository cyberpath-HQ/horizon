//! # Horizon CLI
//!
//! Command-line interface for Horizon CMDB.
//!
//! ## Usage
//!
//! ```bash
//! horizon serve    # Start the API server (runs migrations automatically)
//! horizon migrate  # Run database migrations
//! horizon --help   # Show help
//! ```

use clap::{Args, CommandFactory as _, Parser, Subcommand};
use error::{AppError, Result};
use migration::{Migrator, MigratorTrait as _};

/// Database configuration for CLI
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database host address
    pub host:      String,
    /// Database port number
    pub port:      u16,
    /// Database name
    pub database:  String,
    /// Database username
    pub username:  String,
    /// Database password
    pub password:  String,
    /// SSL mode
    pub ssl_mode:  String,
    /// Connection pool size
    pub pool_size: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host:      std::env::var("HORIZON_DATABASE_HOST").unwrap_or_else(|_| "localhost".to_owned()),
            port:      std::env::var("HORIZON_DATABASE_PORT")
                .unwrap_or_else(|_| "5432".to_owned())
                .parse()
                .unwrap_or(5432),
            database:  std::env::var("HORIZON_DATABASE_NAME").unwrap_or_else(|_| "horizon".to_owned()),
            username:  std::env::var("HORIZON_DATABASE_USER").unwrap_or_else(|_| "horizon".to_owned()),
            password:  std::env::var("HORIZON_DATABASE_PASSWORD").unwrap_or_else(|_| String::new()),
            ssl_mode:  std::env::var("HORIZON_DATABASE_SSL_MODE").unwrap_or_else(|_| "require".to_owned()),
            pool_size: std::env::var("HORIZON_DATABASE_POOL_SIZE")
                .unwrap_or_else(|_| "10".to_owned())
                .parse()
                .unwrap_or(10),
        }
    }
}

/// Builds the DATABASE_URL from DatabaseConfig
pub fn build_database_url(config: &DatabaseConfig) -> String {
    format!(
        "postgres://{}:{}@{}:{}/{}?sslmode={}",
        config.username, config.password, config.host, config.port, config.database,
        config.ssl_mode
    )
}

/// Horizon CMDB - Configuration Management Database
#[derive(Parser, Debug)]
#[command(name = "horizon")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level (debug, info, warn, error)
    #[arg(short = 'L', long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Output format (json, pretty, compact)
    #[arg(short, long, env = "HORIZON_LOG_FORMAT", default_value = "pretty")]
    log_format: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the API server
    Serve(ServeArgs),

    /// Run database migrations
    Migrate(MigrateArgs),

    /// Generate shell completions
    Completions(CompletionsArgs),

    /// Verify configuration
    Validate,
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Server host to bind to
    #[arg(long, env = "HORIZON_HOST", default_value = "0.0.0.0")]
    host: String,

    /// Server port to bind to
    #[arg(short, long, env = "HORIZON_PORT", default_value = "3000")]
    port: u16,

    /// Enable TLS/HTTPS
    #[arg(long, env = "HORIZON_TLS")]
    tls: bool,

    /// TLS certificate file path
    #[arg(long, env = "HORIZON_TLS_CERT", requires = "tls")]
    tls_cert: Option<String>,

    /// TLS key file path
    #[arg(long, env = "HORIZON_TLS_KEY", requires = "tls")]
    tls_key: Option<String>,
}

#[derive(Args, Debug)]
struct MigrateArgs {
    /// Run migrations in dry-run mode (no changes)
    #[arg(long)]
    dry_run: bool,

    /// Rollback the last migration
    #[arg(long)]
    rollback: bool,

    /// Create a new migration with the given name
    #[arg(long, requires = "migration_dir")]
    create: Option<String>,

    /// Directory for migration files
    #[arg(long, env = "HORIZON_MIGRATION_DIR")]
    migration_dir: Option<String>,

    /// Number of parallel migration threads
    #[arg(long, default_value = "4")]
    threads: u8,
}

#[derive(Args, Debug)]
struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    shell: clap_complete::Shell,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    logging::init(&cli.log_level, &cli.log_format, None)
        .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))?;

    logging::info!(target: "app", command = ?cli.command, "Horizon CLI starting...");

    match cli.command {
        Commands::Serve(args) => serve(&args).await?,
        Commands::Migrate(args) => migrate(&args).await?,
        Commands::Completions(args) => completions(&args)?,
        Commands::Validate => validate()?,
    }

    logging::info!(target: "app", "Horizon CLI completed successfully");
    Ok(())
}

async fn serve(_args: &ServeArgs) -> Result<()> {
    logging::info!(target: "serve", "Starting API server...");

    // Build database URL from configuration
    let config = DatabaseConfig::default();
    let database_url = build_database_url(&config);

    // Connect to database
    logging::info!(target: "serve", "Connecting to database...");
    let db = migration::connect_to_database(&database_url)
        .await
        .map_err(AppError::database)?;

    // Run migrations automatically on startup
    logging::info!(target: "serve", "Running database migrations...");
    Migrator::up(&db, None).await.map_err(AppError::database)?;

    logging::info!(target: "serve", "Database migrations completed successfully");

    // TODO: Implement server startup
    // - Set up Axum router
    // - Apply middleware
    // - Start listening

    logging::info!(target: "serve", "Server functionality to be implemented");
    Ok(())
}

async fn migrate(args: &MigrateArgs) -> Result<()> {
    logging::info!(target: "migrate",
        dry_run = %args.dry_run,
        rollback = %args.rollback,
        create = ?args.create,
        threads = %args.threads,
        "Running database migrations..."
    );

    // Build database URL from configuration
    let config = DatabaseConfig::default();
    let database_url = build_database_url(&config);

    // Connect to database
    let db = migration::connect_to_database(&database_url)
        .await
        .map_err(AppError::database)?;

    if args.dry_run {
        // Dry run mode - just show what would happen
        logging::info!(target: "migrate", "Dry run mode - migrations would be applied");

        // Get pending migrations
        let pending = migration::Migrator::get_pending_migrations(&db)
            .await
            .map_err(AppError::database)?;

        logging::info!(target: "migrate",
            pending_count = %pending.len(),
            "Pending migrations found"
        );

        for m in &pending {
            logging::info!(target: "migrate", migration = %m.name(), "Would apply");
        }

        return Ok(());
    }

    if args.rollback {
        // Rollback the last migration
        logging::info!(target: "migrate", "Rolling back the last migration...");

        migration::Migrator::down(&db, None)
            .await
            .map_err(AppError::database)?;

        logging::info!(target: "migrate", "Rollback completed successfully");
        return Ok(());
    }

    // Run migrations
    Migrator::up(&db, None).await.map_err(AppError::database)?;

    logging::info!(target: "migrate", "Migrations completed successfully");
    Ok(())
}

fn completions(args: &CompletionsArgs) -> Result<()> {
    clap_complete::generate(
        args.shell,
        &mut Cli::command(),
        "horizon",
        &mut std::io::stdout(),
    );
    Ok(())
}

fn validate() -> Result<()> {
    logging::info!(target: "validate", "Validating configuration...");

    // Check required environment variables
    let required_vars = [
        "HORIZON_DATABASE_HOST",
        "HORIZON_DATABASE_PORT",
        "HORIZON_DATABASE_NAME",
        "HORIZON_DATABASE_USER",
        "HORIZON_DATABASE_PASSWORD",
    ];

    let mut missing = Vec::new();
    for var in &required_vars {
        if std::env::var(var).is_err() {
            missing.push(var);
        }
    }

    if !missing.is_empty() {
        logging::error!(target: "validate", missing_vars = ?missing, "Missing required environment variables");
        return Err(AppError::validation(format!(
            "Missing required environment variables: {:?}",
            missing
        )));
    }

    logging::info!(target: "validate", "Configuration validation passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn test_cli_parse_serve() {
        let cli = Cli::parse_from(&["horizon", "serve", "--host", "127.0.0.1", "--port", "8080"]);
        match cli.command {
            Commands::Serve(args) => {
                assert_eq!(args.host, "127.0.0.1");
                assert_eq!(args.port, 8080);
                assert!(!args.tls);
            },
            _ => panic!("Expected Serve command"),
        }
    }

    #[test]
    fn test_cli_parse_validate() {
        let cli = Cli::parse_from(&["horizon", "validate"]);
        match cli.command {
            Commands::Validate => {},
            _ => panic!("Expected Validate command"),
        }
    }

    #[test]
    fn test_cli_default_values() {
        let cli = Cli::parse_from(&["horizon", "validate"]);
        assert_eq!(cli.log_level, "info");
        assert_eq!(cli.log_format, "pretty");
    }

    #[test]
    fn test_serve_args_tls() {
        let args = ServeArgs {
            host:     "0.0.0.0".to_string(),
            port:     3000,
            tls:      true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key:  Some("/path/to/key".to_string()),
        };
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key".to_string()));
    }

    #[test]
    fn test_migrate_rollback() {
        let cli = Cli::parse_from(&["horizon", "migrate", "--rollback"]);
        match cli.command {
            Commands::Migrate(args) => {
                assert!(args.rollback);
            },
            _ => panic!("Expected Migrate command"),
        }
    }

    #[test]
    fn test_migrate_create() {
        let cli = Cli::parse_from(&[
            "horizon",
            "migrate",
            "--create",
            "add_users_table",
            "--migration-dir",
            "/migrations",
        ]);
        match cli.command {
            Commands::Migrate(args) => {
                assert_eq!(args.create, Some("add_users_table".to_string()));
            },
            _ => panic!("Expected Migrate command"),
        }
    }

    #[test]
    fn test_cli_command_factory() {
        let cmd = Cli::command();
        assert!(cmd.get_name() == "horizon");
    }

    #[test]
    fn test_validate_returns_ok() {
        // Set required env vars
        unsafe {
            std::env::set_var("HORIZON_DATABASE_HOST", "localhost");
            std::env::set_var("HORIZON_DATABASE_PORT", "5432");
            std::env::set_var("HORIZON_DATABASE_NAME", "horizon");
            std::env::set_var("HORIZON_DATABASE_USER", "horizon");
            std::env::set_var("HORIZON_DATABASE_PASSWORD", "password");
        }

        let result = validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_vars() {
        // Clear env vars
        unsafe {
            std::env::remove_var("HORIZON_DATABASE_HOST");
            std::env::remove_var("HORIZON_DATABASE_PORT");
            std::env::remove_var("HORIZON_DATABASE_NAME");
            std::env::remove_var("HORIZON_DATABASE_USER");
            std::env::remove_var("HORIZON_DATABASE_PASSWORD");
        }

        let result = validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_serve_args_default() {
        let args = ServeArgs {
            host:     "0.0.0.0".to_string(),
            port:     3000,
            tls:      false,
            tls_cert: None,
            tls_key:  None,
        };
        assert_eq!(args.host, "0.0.0.0");
        assert_eq!(args.port, 3000);
        assert!(!args.tls);
    }

    #[test]
    fn test_migrate_args_default() {
        let args = MigrateArgs {
            dry_run:       false,
            rollback:      false,
            create:        None,
            migration_dir: None,
            threads:       4,
        };
        assert!(!args.dry_run);
        assert!(!args.rollback);
        assert!(args.create.is_none());
        assert_eq!(args.threads, 4);
    }

    #[test]
    fn test_build_database_url() {
        // Set test environment variables
        unsafe {
            std::env::set_var("HORIZON_DATABASE_HOST", "testhost");
            std::env::set_var("HORIZON_DATABASE_PORT", "5433");
            std::env::set_var("HORIZON_DATABASE_NAME", "testdb");
            std::env::set_var("HORIZON_DATABASE_USER", "testuser");
            std::env::set_var("HORIZON_DATABASE_PASSWORD", "testpass");
        }

        let config = DatabaseConfig::default();
        let url = build_database_url(&config);
        assert!(url.contains("postgres://testuser:testpass@testhost:5433/testdb"));
    }
}
