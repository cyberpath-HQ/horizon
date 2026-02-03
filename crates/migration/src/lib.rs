//! # Horizon Database Migration Infrastructure
//!
//! This module provides the database migration infrastructure for Horizon CMDB,
//! using Sea-ORM 2.x for PostgreSQL migrations with automatic version tracking.
//!
//! ## Features
//!
//! - Migration-driven database schema management
//! - Automatic migration version tracking via `seaql_migrations` table
//! - Up/Down migration support with transaction safety
//! - Seed data for enum values and default configurations
//! - Connection pooling with Tokio runtime
//!
//! ## Usage
//!
//! ```rust,ignore
//! use migration::{Migrator, MigratorTrait, SeaDb};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let db = SeaDb::new().await?;
//!     Migrator::up(&db, None).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Migration Files
//!
//! Migrations are located in `src/migrators/` directory and follow the naming
//! convention `mYYYYMMDD_name.rs`. Each migration implements the
//! `MigrationTrait` to define `up` and `down` operations.

use std::sync::Arc;

pub use sea_orm_migration::prelude::*;
use tokio::sync::RwLock;
use tracing::Instrument;
use uuid::Uuid;
/// Re-export common types for convenience
pub use sea_orm_migration::sea_orm as sea_orm_dep;
// Re-export error types for convenience
pub use ::error::{AppError, Result, SeedResult};
use sea_orm_migration::sea_orm::TransactionTrait;

/// The Migrator trait implementation
pub mod migrator;

pub use migrator::Migrator;

/// Database connection management
pub mod db;

/// Migration runners
pub mod runners;

/// Seed data management
pub mod seeds;

/// Entity definitions
pub mod entities;

/// Migration modules
pub mod migrators;

pub use entities::*;

// Use a thread-safe reference-counted pointer for the database connection
/// Thread-safe database connection pool wrapper
#[derive(Clone, Debug)]
pub struct SeaDb {
    /// The underlying Sea-ORM database connection
    pub(crate) inner: sea_orm_dep::DatabaseConnection,

    /// Connection pool metrics
    metrics: Arc<RwLock<DbMetrics>>,
}

/// Database connection metrics for monitoring
#[derive(Debug, Clone, Default)]
struct DbMetrics {
    /// Number of active connections
    active_connections:     u32,
    /// Number of idle connections
    idle_connections:       u32,
    /// Total connections in pool
    total_connections:      u32,
    /// Last migration version applied
    last_migration_version: Option<i32>,
    /// Timestamp of last connection
    last_activity:          Option<chrono::DateTime<chrono::Utc>>,
}

impl SeaDb {
    /// Creates a new database connection from environment variables
    ///
    /// Expects the following environment variables:
    /// - `HORIZON_DATABASE_HOST`: Database host address
    /// - `HORIZON_DATABASE_PORT`: Database port (default: 5432)
    /// - `HORIZON_DATABASE_NAME`: Database name
    /// - `HORIZON_DATABASE_USER`: Database username
    /// - `HORIZON_DATABASE_PASSWORD`: Database password
    /// - `HORIZON_DATABASE_SSL_MODE`: SSL mode (default: require)
    /// - `HORIZON_DATABASE_POOL_SIZE`: Connection pool size (default: 10)
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or environment variables are missing.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let db = SeaDb::new().await?;
    /// ```
    pub async fn new() -> Result<Self, AppError> { Self::from_config(&std::env::vars().collect::<Vec<_>>()).await }

    /// Creates a new database connection from a configuration vector
    ///
    /// # Arguments
    ///
    /// * `config` - A vector of (key, value) tuples from environment variables
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or configuration is invalid.
    pub async fn from_config(config: &[(String, String)]) -> Result<Self, AppError> {
        let host = Self::get_env(config, "HORIZON_DATABASE_HOST", "localhost")?;
        let port = Self::get_env(config, "HORIZON_DATABASE_PORT", "5432")?
            .parse::<u16>()
            .map_err(|_| AppError::config("Invalid database port"))?;
        let database = Self::get_env(config, "HORIZON_DATABASE_NAME", "horizon")?;
        let username = Self::get_env(config, "HORIZON_DATABASE_USER", "horizon")?;
        let password = Self::get_env(config, "HORIZON_DATABASE_PASSWORD", "")?;
        let ssl_mode = Self::get_env(config, "HORIZON_DATABASE_SSL_MODE", "require")?;
        let pool_size = Self::get_env(config, "HORIZON_DATABASE_POOL_SIZE", "10")?
            .parse::<u32>()
            .map_err(|_| AppError::config("Invalid pool size"))?;

        let connection_string = format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            username, password, host, port, database, ssl_mode
        );

        tracing::info!("Connecting to database {} on {}:{}", database, host, port);

        let connection = sea_orm_dep::Database::connect(&connection_string)
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to database: {}", e);
                AppError::database(format!("Connection failed: {}", e))
            })?;

        tracing::info!("Successfully connected to database");

        Ok(Self {
            inner:   connection,
            metrics: Arc::new(RwLock::new(DbMetrics::default())),
        })
    }

    /// Creates a new database connection from a connection string
    ///
    /// # Arguments
    ///
    /// * `connection_string` - PostgreSQL connection string
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let db = SeaDb::from_connection_string("postgres://user:pass@localhost/db").await?;
    /// ```
    pub async fn from_connection_string(connection_string: &str) -> Result<Self, AppError> {
        let connection = sea_orm_dep::Database::connect(connection_string)
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to database: {}", e);
                AppError::database(format!("Connection failed: {}", e))
            })?;

        tracing::info!("Successfully connected to database");

        Ok(Self {
            inner:   connection,
            metrics: Arc::new(RwLock::new(DbMetrics::default())),
        })
    }

    /// Gets an environment variable with a default value
    fn get_env(config: &[(String, String)], key: &str, default: &str) -> Result<String, AppError> {
        Ok(config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .or_else(|| std::env::var(key).ok())
            .unwrap_or_else(|| default.to_string()))
    }

    /// Executes a function within a database transaction
    ///
    /// # Arguments
    ///
    /// * `f` - The async function to execute within the transaction
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction fails or the function returns an error.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = db.transaction(|tx| async move {
    ///     // Perform database operations
    ///     Ok(result)
    /// }).await?;
    /// ```
    pub async fn transaction<F, T>(&self, f: F) -> Result<T, AppError>
    where
        F: std::future::Future<Output = Result<T, AppError>>,
    {
        let transaction = self.inner.begin().await.map_err(AppError::from)?;

        let result = f.await;

        match result {
            Ok(value) => {
                transaction.commit().await.map_err(AppError::from)?;
                Ok(value)
            },
            Err(e) => {
                transaction.rollback().await.ok();
                Err(e)
            },
        }
    }

    /// Gets the underlying database connection
    ///
    /// # Returns
    ///
    /// A reference to the Sea-ORM database connection.
    pub fn get_connection(&self) -> &sea_orm_dep::DatabaseConnection { &self.inner }

    /// Gets the migration executor for this database
    ///
    /// # Returns
    ///
    /// A reference to the migrator for executing migrations.
    pub fn get_migrator(&self) -> &migrator::Migrator { &migrator::Migrator }

    /// Updates connection metrics
    async fn update_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.last_activity = Some(chrono::Utc::now());
    }

    /// Gets current connection metrics
    pub async fn get_metrics(&self) -> DbMetricsSnapshot {
        let metrics = self.metrics.read().await.clone();
        DbMetricsSnapshot {
            active_connections:     metrics.active_connections,
            idle_connections:       metrics.idle_connections,
            total_connections:      metrics.total_connections,
            last_migration_version: metrics.last_migration_version,
            last_activity:          metrics.last_activity,
        }
    }
}

/// Snapshot of database connection metrics
#[derive(Debug, Clone)]
pub struct DbMetricsSnapshot {
    /// Number of active connections
    pub active_connections:     u32,
    /// Number of idle connections
    pub idle_connections:       u32,
    /// Total connections in pool
    pub total_connections:      u32,
    /// Last migration version applied
    pub last_migration_version: Option<i32>,
    /// Timestamp of last connection
    pub last_activity:          Option<chrono::DateTime<chrono::Utc>>,
}

/// Generates a unique migration ID
///
/// # Returns
///
/// A UUID v4 string for unique migration identification.
pub fn generate_migration_id() -> String { Uuid::new_v4().to_string() }
