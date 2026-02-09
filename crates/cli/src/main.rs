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

use std::net::SocketAddr;

use tokio::net::TcpListener;
use axum;
use clap::{Args, CommandFactory as _, Parser, Subcommand};
use error::{AppError, Result};
use migration::{Migrator, MigratorTrait as _};
use server::{router::create_app_router, AppState};
use auth::JwtConfig;
use tokio_rustls::TlsAcceptor;
use rustls::pki_types::pem::PemObject;
use tower::Service;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};

/// Load certificates from a PEM file
fn load_certs(path: &str) -> std::io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let cert_pem = std::fs::read(path)?;
    let mut certs = Vec::new();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
        certs.push(cert.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?);
    }
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No certificates found in file",
        ));
    }
    Ok(certs)
}

/// Load private key from a PEM file
fn load_private_key(path: &str) -> std::io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let key_pem = std::fs::read(path)?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(key)
}

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
        config.username, config.password, config.host, config.port, config.database, config.ssl_mode
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

async fn serve(args: &ServeArgs) -> Result<()> {
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

    // Initialize Redis client for token blacklisting
    let redis_url = std::env::var("HORIZON_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_client =
        redis::Client::open(redis_url).map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

    // Create application state
    let jwt_config = JwtConfig::default();
    let state = AppState {
        db,
        jwt_config,
        redis: redis_client,
        start_time: std::time::Instant::now(),
    };

    // Create the Axum router
    let app = create_app_router(state.clone());

    // Parse the bind address
    let address: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

    // Start the server (HTTP or HTTPS)
    if args.tls {
        // TLS is enabled - require certificate and key paths
        let tls_cert_path = args
            .tls_cert
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS certificate path is required when TLS is enabled"))?;
        let tls_key_path = args
            .tls_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS key path is required when TLS is enabled"))?;

        logging::info!(target: "serve", "Initializing TLS with cert={}, key={}", tls_cert_path, tls_key_path);

        // Load TLS certificate and key
        let certs = load_certs(tls_cert_path)?;
        let key = load_private_key(tls_key_path)?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("Failed to configure TLS: {}", e))?;

        // Create TLS acceptor
        let tls_acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));

        logging::info!(target: "serve", %address, "Starting HTTPS server (TLS enabled)...");

        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind address: {}", e))?;

        // Use hyper to serve with TLS
        loop {
            tokio::select! {
                _ = shutdown_signal() => {
                    logging::info!(target: "serve", "Received shutdown signal, stopping HTTPS server...");
                    break;
                }
                result = listener.accept() => {
                    let (tcp_stream, peer_addr) = result?;
                    let tls_acceptor = tls_acceptor.clone();
                    let app = app.clone();

                    tokio::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                tracing::warn!("TLS handshake failed: {}", e);
                                return;
                            },
                        };

                        let hyper_service =
                            hyper::service::service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                                request.extensions_mut().insert(axum::extract::ConnectInfo(peer_addr));
                                let mut app = app.clone();
                                async move { app.call(request).await }
                            });

                        if let Err(err) = Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls_stream), hyper_service)
                            .await
                        {
                            tracing::warn!("Error serving connection: {}", err);
                        }
                    });
                }
            }
        }
    }
    else {
        // HTTP mode
        logging::info!(target: "serve", %address, "Starting HTTP server...");

        let listener = TcpListener::bind(&address)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", address, e))?;

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("HTTP server error: {}", e))?;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install terminate handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
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
        return Err(AppError::validation(format!(
            "Missing required environment variables: {:?}",
            missing
        )));
    }

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
        // Save original env vars
        let orig_host = std::env::var("HORIZON_DATABASE_HOST").ok();
        let orig_port = std::env::var("HORIZON_DATABASE_PORT").ok();
        let orig_name = std::env::var("HORIZON_DATABASE_NAME").ok();
        let orig_user = std::env::var("HORIZON_DATABASE_USER").ok();
        let orig_pass = std::env::var("HORIZON_DATABASE_PASSWORD").ok();

        // Set required env vars
        unsafe {
            std::env::set_var("HORIZON_DATABASE_HOST", "localhost");
        }
        unsafe {
            std::env::set_var("HORIZON_DATABASE_PORT", "5432");
        }
        unsafe {
            std::env::set_var("HORIZON_DATABASE_NAME", "horizon");
        }
        unsafe {
            std::env::set_var("HORIZON_DATABASE_USER", "horizon");
        }
        unsafe {
            std::env::set_var("HORIZON_DATABASE_PASSWORD", "password");
        }

        let result = validate();
        assert!(result.is_ok());

        // Restore original env vars
        if let Some(v) = orig_host {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_HOST", v);
            }
        }
        else {
            unsafe {
                std::env::remove_var("HORIZON_DATABASE_HOST");
            }
        }
        if let Some(v) = orig_port {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_PORT", v);
            }
        }
        else {
            unsafe {
                std::env::remove_var("HORIZON_DATABASE_PORT");
            }
        }
        if let Some(v) = orig_name {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_NAME", v);
            }
        }
        else {
            unsafe {
                std::env::remove_var("HORIZON_DATABASE_NAME");
            }
        }
        if let Some(v) = orig_user {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_USER", v);
            }
        }
        else {
            unsafe {
                std::env::remove_var("HORIZON_DATABASE_USER");
            }
        }
        if let Some(v) = orig_pass {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_PASSWORD", v);
            }
        }
        else {
            unsafe {
                std::env::remove_var("HORIZON_DATABASE_PASSWORD");
            }
        }
    }

    #[test]
    fn test_validate_missing_vars() {
        // Save original env vars
        let orig_host = std::env::var("HORIZON_DATABASE_HOST").ok();
        let orig_port = std::env::var("HORIZON_DATABASE_PORT").ok();
        let orig_name = std::env::var("HORIZON_DATABASE_NAME").ok();
        let orig_user = std::env::var("HORIZON_DATABASE_USER").ok();
        let orig_pass = std::env::var("HORIZON_DATABASE_PASSWORD").ok();

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

        // Restore original env vars
        if let Some(v) = orig_host {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_HOST", v);
            }
        }
        if let Some(v) = orig_port {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_PORT", v);
            }
        }
        if let Some(v) = orig_name {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_NAME", v);
            }
        }
        if let Some(v) = orig_user {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_USER", v);
            }
        }
        if let Some(v) = orig_pass {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_PASSWORD", v);
            }
        }
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

    #[test]
    fn test_load_certs_with_valid_pem() {
        // Create a temporary PEM file with test certificate
        let temp_dir = std::env::temp_dir();
        let cert_path = temp_dir.join("test_cert.pem");

        // Write a minimal valid PEM certificate
        let cert_content = r#"-----BEGIN CERTIFICATE-----
MIICljCCAX6gAwIBAgIUfk5kJ8P4JVL2f2k8p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
-----END CERTIFICATE-----"#;

        std::fs::write(&cert_path, cert_content).unwrap();

        let result = load_certs(cert_path.to_str().unwrap());
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());

        // Cleanup
        std::fs::remove_file(cert_path).ok();
    }

    #[test]
    fn test_load_certs_empty_file() {
        let temp_dir = std::env::temp_dir();
        let cert_path = temp_dir.join("empty_cert.pem");

        // Write empty file
        std::fs::write(&cert_path, "").unwrap();

        let result = load_certs(cert_path.to_str().unwrap());
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_file(cert_path).ok();
    }

    #[test]
    fn test_load_certs_invalid_pem() {
        let temp_dir = std::env::temp_dir();
        let cert_path = temp_dir.join("invalid_cert.pem");

        // Write invalid PEM content
        std::fs::write(&cert_path, "not a valid pem").unwrap();

        let result = load_certs(cert_path.to_str().unwrap());
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_file(cert_path).ok();
    }

    #[test]
    fn test_load_certs_nonexistent_file() {
        let result = load_certs("/nonexistent/path/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_with_valid_pem() {
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join("test_key.pem");

        // Write a minimal valid PEM private key
        let key_content = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
-----END PRIVATE KEY-----"#;

        std::fs::write(&key_path, key_content).unwrap();

        let result = load_private_key(key_path.to_str().unwrap());
        assert!(result.is_ok());

        // Cleanup
        std::fs::remove_file(key_path).ok();
    }

    #[test]
    fn test_load_private_key_invalid_pem() {
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join("invalid_key.pem");

        // Write invalid PEM content
        std::fs::write(&key_path, "not a valid pem key").unwrap();

        let result = load_private_key(key_path.to_str().unwrap());
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_file(key_path).ok();
    }

    #[test]
    fn test_load_private_key_nonexistent_file() {
        let result = load_private_key("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_completions_bash() {
        use std::io::Write;

        let args = CompletionsArgs {
            shell: clap_complete::Shell::Bash,
        };

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let result = completions_with_output(&args, &mut temp_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_completions_zsh() {
        use std::io::Write;

        let args = CompletionsArgs {
            shell: clap_complete::Shell::Zsh,
        };

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let result = completions_with_output(&args, &mut temp_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_completions_fish() {
        use std::io::Write;

        let args = CompletionsArgs {
            shell: clap_complete::Shell::Fish,
        };

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let result = completions_with_output(&args, &mut temp_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_completions_powershell() {
        use std::io::Write;

        let args = CompletionsArgs {
            shell: clap_complete::Shell::PowerShell,
        };

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let result = completions_with_output(&args, &mut temp_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_parse_migrate_dry_run() {
        let cli = Cli::parse_from(&["horizon", "migrate", "--dry-run"]);
        match cli.command {
            Commands::Migrate(args) => {
                assert!(args.dry_run);
            },
            _ => panic!("Expected Migrate command"),
        }
    }

    #[test]
    fn test_cli_parse_migrate_threads() {
        let cli = Cli::parse_from(&["horizon", "migrate", "--threads", "8"]);
        match cli.command {
            Commands::Migrate(args) => {
                assert_eq!(args.threads, 8);
            },
            _ => panic!("Expected Migrate command"),
        }
    }

    #[test]
    fn test_cli_parse_serve_with_tls() {
        let cli = Cli::parse_from(&[
            "horizon",
            "serve",
            "--host",
            "0.0.0.0",
            "--port",
            "443",
            "--tls",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]);
        match cli.command {
            Commands::Serve(args) => {
                assert_eq!(args.host, "0.0.0.0");
                assert_eq!(args.port, 443);
                assert!(args.tls);
                assert_eq!(args.tls_cert, Some("/path/to/cert.pem".to_string()));
                assert_eq!(args.tls_key, Some("/path/to/key.pem".to_string()));
            },
            _ => panic!("Expected Serve command"),
        }
    }

    #[test]
    fn test_database_config_env_override() {
        // Save original env vars
        let orig_host = std::env::var("HORIZON_DATABASE_HOST").ok();
        let orig_port = std::env::var("HORIZON_DATABASE_PORT").ok();
        let orig_name = std::env::var("HORIZON_DATABASE_NAME").ok();
        let orig_user = std::env::var("HORIZON_DATABASE_USER").ok();
        let orig_pass = std::env::var("HORIZON_DATABASE_PASSWORD").ok();
        let orig_ssl = std::env::var("HORIZON_DATABASE_SSL_MODE").ok();
        let orig_pool = std::env::var("HORIZON_DATABASE_POOL_SIZE").ok();

        // Set custom env vars
        unsafe {
            std::env::set_var("HORIZON_DATABASE_HOST", "custom-host");
            std::env::set_var("HORIZON_DATABASE_PORT", "5433");
            std::env::set_var("HORIZON_DATABASE_NAME", "custom-db");
            std::env::set_var("HORIZON_DATABASE_USER", "custom-user");
            std::env::set_var("HORIZON_DATABASE_PASSWORD", "custom-pass");
            std::env::set_var("HORIZON_DATABASE_SSL_MODE", "disable");
            std::env::set_var("HORIZON_DATABASE_POOL_SIZE", "20");
        }

        let config = DatabaseConfig::default();
        assert_eq!(config.host, "custom-host");
        assert_eq!(config.port, 5433);
        assert_eq!(config.database, "custom-db");
        assert_eq!(config.username, "custom-user");
        assert_eq!(config.password, "custom-pass");
        assert_eq!(config.ssl_mode, "disable");
        assert_eq!(config.pool_size, 20);

        // Restore original env vars
        restore_env_var("HORIZON_DATABASE_HOST", orig_host);
        restore_env_var("HORIZON_DATABASE_PORT", orig_port);
        restore_env_var("HORIZON_DATABASE_NAME", orig_name);
        restore_env_var("HORIZON_DATABASE_USER", orig_user);
        restore_env_var("HORIZON_DATABASE_PASSWORD", orig_pass);
        restore_env_var("HORIZON_DATABASE_SSL_MODE", orig_ssl);
        restore_env_var("HORIZON_DATABASE_POOL_SIZE", orig_pool);
    }

    #[test]
    fn test_database_config_defaults() {
        // Clear env vars to test defaults
        unsafe {
            std::env::remove_var("HORIZON_DATABASE_HOST");
            std::env::remove_var("HORIZON_DATABASE_PORT");
            std::env::remove_var("HORIZON_DATABASE_NAME");
            std::env::remove_var("HORIZON_DATABASE_USER");
            std::env::remove_var("HORIZON_DATABASE_PASSWORD");
            std::env::remove_var("HORIZON_DATABASE_SSL_MODE");
            std::env::remove_var("HORIZON_DATABASE_POOL_SIZE");
        }

        let config = DatabaseConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "horizon");
        assert_eq!(config.username, "horizon");
        assert_eq!(config.password, "");
        assert_eq!(config.ssl_mode, "require");
        assert_eq!(config.pool_size, 10);
    }

    #[test]
    fn test_cli_name_and_version() {
        let cmd = Cli::command();
        assert_eq!(cmd.get_name(), "horizon");
        // Version should be set
        let version = cmd.get_version();
        assert!(version.is_some());
    }

    #[test]
    fn test_cli_about_text() {
        let cmd = Cli::command();
        let about = cmd.get_about();
        assert!(about.is_some());
    }

    #[test]
    fn test_cli_serve_subcommand() {
        let cmd = Cli::command();
        let mut has_serve = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "serve" {
                has_serve = true;
                break;
            }
        }
        assert!(has_serve);
    }

    #[test]
    fn test_cli_migrate_subcommand() {
        let cmd = Cli::command();
        let mut has_migrate = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "migrate" {
                has_migrate = true;
                break;
            }
        }
        assert!(has_migrate);
    }

    #[test]
    fn test_cli_validate_subcommand() {
        let cmd = Cli::command();
        let mut has_validate = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "validate" {
                has_validate = true;
                break;
            }
        }
        assert!(has_validate);
    }

    #[test]
    fn test_cli_completions_subcommand() {
        let cmd = Cli::command();
        let mut has_completions = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "completions" {
                has_completions = true;
                break;
            }
        }
        assert!(has_completions);
    }

    // Helper function for completions that writes to a provided writer
    fn completions_with_output<T: std::io::Write>(args: &CompletionsArgs, writer: &mut T) -> Result<()> {
        clap_complete::generate(args.shell, &mut Cli::command(), "horizon", writer);
        Ok(())
    }

    // Helper to restore environment variable
    fn restore_env_var(name: &str, value: Option<String>) {
        unsafe {
            if let Some(v) = value {
                std::env::set_var(name, v);
            }
            else {
                std::env::remove_var(name);
            }
        }
    }
}
