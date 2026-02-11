//! # CLI Server
//!
//! Server startup and management for the Horizon CLI.

use std::net::SocketAddr;

use anyhow::anyhow;
use auth::JwtConfig;
use error::Result;
use migration::{Migrator, MigratorTrait as _};
use redis::Client as RedisClient;
use rustls::ServerConfig;
use server::{router::create_app_router, AppState};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::info;

use crate::{
    config::{parse_socket_addr, DatabaseConfig},
    tls::{load_certs, load_private_key},
};

/// Starts the API server with optional TLS support
///
/// # Arguments
///
/// * `config` - Database configuration
/// * `args` - Serve command arguments
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[allow(
    clippy::cognitive_complexity,
    clippy::integer_division_remainder_used,
    reason = "Complex server setup is intentional"
)]
pub async fn serve(config: &DatabaseConfig, args: &crate::commands::ServeArgs) -> Result<()> {
    info!(target: "serve", "Starting API server...");

    // Build database URL from configuration
    let database_url = crate::config::build_database_url(config);

    // Connect to database
    info!(target: "serve", "Connecting to database...");
    let db = migration::connect_to_database(&database_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to database: {}", e))?;

    // Run migrations automatically on startup
    info!(target: "serve", "Running database migrations...");
    Migrator::up(&db, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run database migrations: {}", e))?;
    info!(
        target: "serve",
        "Database migrations completed successfully"
    );

    // Initialize Redis client for token blacklisting
    let redis_url = std::env::var("HORIZON_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client =
        RedisClient::open(redis_url).map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

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
    let address = parse_socket_addr(&args.host, args.port)
        .map_err(|e| anyhow!("Invalid address {}:{}: {}", args.host, args.port, e))?;

    // Start the server (HTTP or HTTPS)
    if args.tls {
        serve_https(&app, &address, args).await
    }
    else {
        serve_http(&app, &address).await
    }
}

/// Serves the application over HTTPS
async fn serve_http(app: &axum::Router, address: &SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|e| anyhow!("Failed to bind to {}: {}", address, e))?;

    info!(target: "serve", %address, "Starting HTTP server...");

    Ok(axum::serve(
        listener,
        app.clone()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| anyhow!("HTTP server error: {}", e))?)
}

/// Serves the application over HTTPS with TLS
async fn serve_https(app: &axum::Router, address: &SocketAddr, args: &crate::commands::ServeArgs) -> Result<()> {
    // TLS is enabled - require certificate and key paths
    let tls_cert_path = args
        .tls_cert
        .as_ref()
        .ok_or_else(|| anyhow!("TLS certificate path is required when TLS is enabled"))?;
    let tls_key_path = args
        .tls_key
        .as_ref()
        .ok_or_else(|| anyhow!("TLS key path is required when TLS is enabled"))?;

    info!(
        target: "serve",
        "Initializing TLS with cert={}, key={}",
        tls_cert_path,
        tls_key_path
    );

    // Load TLS certificate and key
    let certs = load_certs(tls_cert_path).map_err(|e| anyhow!("Failed to load TLS certificate: {}", e))?;
    let key = load_private_key(tls_key_path).map_err(|e| anyhow!("Failed to load TLS private key: {}", e))?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("Failed to configure TLS: {}", e))?;

    // Create TLS acceptor
    let tls_acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));

    info!(target: "serve", %address, "Starting HTTPS server (TLS enabled)...");

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|e| anyhow!("Failed to bind address: {}", e))?;

    // Use hyper to serve with TLS
    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                info!(target: "serve", "Received shutdown signal, stopping HTTPS server...");
                break;
            }
            result = listener.accept() => {
                let (tcp_stream, peer_addr) = result
                    .map_err(|e| anyhow!("Failed to accept connection: {}", e))?;
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

                    if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper_service)
                    .await
                    {
                        tracing::warn!("Error serving connection: {}", err);
                    }
                });
            }
        }
    }

    Ok(())
}

/// Waits for shutdown signals (Ctrl+C or SIGTERM)
#[allow(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! macro triggers false positive"
)]
pub async fn shutdown_signal() {
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
