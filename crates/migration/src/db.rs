//! # Database Connection Management
//!
//! This module provides database connection utilities and management functions
//! for establishing and maintaining PostgreSQL connections using Sea-ORM.

use sea_orm_migration::prelude::*;
use ::error::AppError;

use crate::SeaDb;

/// Database connection configuration
///
/// This struct holds all configuration options for establishing a database connection.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database host address
    pub host:              String,
    /// Database port number
    pub port:              u16,
    /// Database name
    pub database:          String,
    /// Database username
    pub username:          String,
    /// Database password
    pub password:          String,
    /// SSL mode for connection
    pub ssl_mode:          SslMode,
    /// Maximum connections in pool
    pub pool_size:         u32,
    /// Connection timeout in seconds
    pub connect_timeout:   u64,
    /// Statement timeout in seconds
    pub statement_timeout: Option<u64>,
}

/// SSL mode options for PostgreSQL connections
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum SslMode {
    /// No SSL - only use for development
    #[default]
    Disable,
    /// Prefer SSL if available
    Prefer,
    /// Require SSL connection
    Require,
    /// Verify SSL certificate
    VerifyCa,
    /// Verify full SSL certificate chain
    VerifyFull,
}

impl SslMode {
    /// Converts the SSL mode to a PostgreSQL connection string value
    pub fn as_str(&self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
            SslMode::VerifyCa => "verify-ca",
            SslMode::VerifyFull => "verify-full",
        }
    }
}

impl DatabaseConfig {
    /// Creates a new configuration with default values
    ///
    /// # Returns
    ///
    /// A new `DatabaseConfig` with default host (localhost), port (5432),
    /// and empty credentials.
    #[must_use]
    pub fn new() -> Self {
        Self {
            host:              "localhost".to_string(),
            port:              5432,
            database:          "horizon".to_string(),
            username:          "horizon".to_string(),
            password:          String::new(),
            ssl_mode:          SslMode::Require,
            pool_size:         10,
            connect_timeout:   30,
            statement_timeout: None,
        }
    }

    /// Sets the database host
    ///
    /// # Arguments
    ///
    /// * `host` - The database host address
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// Sets the database port
    ///
    /// # Arguments
    ///
    /// * `port` - The database port number
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the database name
    ///
    /// # Arguments
    ///
    /// * `database` - The database name
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_database(mut self, database: &str) -> Self {
        self.database = database.to_string();
        self
    }

    /// Sets the database username
    ///
    /// # Arguments
    ///
    /// * `username` - The database username
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_username(mut self, username: &str) -> Self {
        self.username = username.to_string();
        self
    }

    /// Sets the database password
    ///
    /// # Arguments
    ///
    /// * `password` - The database password
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    /// Sets the SSL mode
    ///
    /// # Arguments
    ///
    /// * `ssl_mode` - The SSL mode to use
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_ssl_mode(mut self, ssl_mode: SslMode) -> Self {
        self.ssl_mode = ssl_mode;
        self
    }

    /// Sets the connection pool size
    ///
    /// # Arguments
    ///
    /// * `pool_size` - Maximum number of connections in the pool
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_pool_size(mut self, pool_size: u32) -> Self {
        self.pool_size = pool_size;
        self
    }

    /// Sets the connection timeout
    ///
    /// # Arguments
    ///
    /// * `timeout` - Connection timeout in seconds
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: u64) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the statement timeout
    ///
    /// # Arguments
    ///
    /// * `timeout` - Statement timeout in seconds (None for no timeout)
    ///
    /// # Returns
    ///
    /// The updated configuration for method chaining.
    #[must_use]
    pub fn with_statement_timeout(mut self, timeout: Option<u64>) -> Self {
        self.statement_timeout = timeout;
        self
    }

    /// Builds the PostgreSQL connection string
    ///
    /// # Returns
    ///
    /// A PostgreSQL connection string for use with Sea-ORM.
    #[must_use]
    pub fn build_connection_string(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            self.username,
            self.password,
            self.host,
            self.port,
            self.database,
            self.ssl_mode.as_str()
        )
    }

    /// Creates a database connection from this configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(&self) -> Result<SeaDb, AppError> {
        SeaDb::from_connection_string(&self.build_connection_string()).await
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self { Self::new() }
}

/// Loads database configuration from environment variables
///
/// Reads the following environment variables:
/// - `HORIZON_DATABASE_HOST` (default: "localhost")
/// - `HORIZON_DATABASE_PORT` (default: "5432")
/// - `HORIZON_DATABASE_NAME` (default: "horizon")
/// - `HORIZON_DATABASE_USER` (default: "horizon")
/// - `HORIZON_DATABASE_PASSWORD` (default: "")
/// - `HORIZON_DATABASE_SSL_MODE` (default: "require")
/// - `HORIZON_DATABASE_POOL_SIZE` (default: "10")
/// - `HORIZON_DATABASE_CONNECT_TIMEOUT` (default: "30")
/// - `HORIZON_DATABASE_STATEMENT_TIMEOUT` (optional)
///
/// # Returns
///
/// A configured `DatabaseConfig` instance.
#[must_use]
pub fn load_config_from_env() -> DatabaseConfig {
    let get_env = |key: &str, default: &str| std::env::var(key).unwrap_or_else(|_| default.to_string());

    let get_env_u16 = |key: &str, default: &str| -> u16 {
        get_env(key, default)
            .parse()
            .unwrap_or_else(|_| default.parse().unwrap())
    };

    let get_env_u32 = |key: &str, default: &str| -> u32 {
        get_env(key, default)
            .parse()
            .unwrap_or_else(|_| default.parse().unwrap())
    };

    let get_env_u64 = |key: &str, default: &str| -> u64 {
        get_env(key, default)
            .parse()
            .unwrap_or_else(|_| default.parse().unwrap())
    };

    let ssl_mode = match get_env("HORIZON_DATABASE_SSL_MODE", "require").as_str() {
        "disable" => SslMode::Disable,
        "prefer" => SslMode::Prefer,
        "require" => SslMode::Require,
        "verify-ca" => SslMode::VerifyCa,
        "verify-full" => SslMode::VerifyFull,
        _ => SslMode::Require,
    };

    let statement_timeout = std::env::var("HORIZON_DATABASE_STATEMENT_TIMEOUT")
        .ok()
        .map(|v| v.parse().ok())
        .flatten();

    DatabaseConfig::new()
        .with_host(&get_env("HORIZON_DATABASE_HOST", "localhost"))
        .with_port(get_env_u16("HORIZON_DATABASE_PORT", "5432"))
        .with_database(&get_env("HORIZON_DATABASE_NAME", "horizon"))
        .with_username(&get_env("HORIZON_DATABASE_USER", "horizon"))
        .with_password(&get_env("HORIZON_DATABASE_PASSWORD", ""))
        .with_ssl_mode(ssl_mode)
        .with_pool_size(get_env_u32("HORIZON_DATABASE_POOL_SIZE", "10"))
        .with_connect_timeout(get_env_u64("HORIZON_DATABASE_CONNECT_TIMEOUT", "30"))
        .with_statement_timeout(statement_timeout)
}

/// Creates a database connection using environment variables
///
/// This is a convenience function that loads configuration from environment
/// variables and establishes a database connection.
///
/// # Errors
///
/// Returns an error if the connection fails or environment variables are missing.
///
/// # Example
///
/// ```rust,ignore
/// use migration::db::connect_from_env;
///
/// let db = connect_from_env().await?;
/// ```
pub async fn connect_from_env() -> Result<SeaDb, AppError> {
    let config = load_config_from_env();
    config.connect().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_default() {
        let config = DatabaseConfig::new();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "horizon");
        assert_eq!(config.username, "horizon");
        assert_eq!(config.password, "");
        assert_eq!(config.pool_size, 10);
    }

    #[test]
    fn test_database_config_builder() {
        let config = DatabaseConfig::new()
            .with_host("db.example.com")
            .with_port(5433)
            .with_database("test_db")
            .with_username("test_user")
            .with_password("test_pass")
            .with_ssl_mode(SslMode::Prefer)
            .with_pool_size(20);

        assert_eq!(config.host, "db.example.com");
        assert_eq!(config.port, 5433);
        assert_eq!(config.database, "test_db");
        assert_eq!(config.username, "test_user");
        assert_eq!(config.password, "test_pass");
        assert_eq!(config.ssl_mode, SslMode::Prefer);
        assert_eq!(config.pool_size, 20);
    }

    #[test]
    fn test_connection_string() {
        let config = DatabaseConfig::new()
            .with_host("localhost")
            .with_port(5432)
            .with_database("horizon")
            .with_username("user")
            .with_password("pass")
            .with_ssl_mode(SslMode::Require);

        let conn_str = config.build_connection_string();
        assert!(conn_str.contains("postgres://user:pass@localhost:5432/horizon?sslmode=require"));
    }

    #[test]
    fn test_ssl_mode_as_str() {
        assert_eq!(SslMode::Disable.as_str(), "disable");
        assert_eq!(SslMode::Prefer.as_str(), "prefer");
        assert_eq!(SslMode::Require.as_str(), "require");
        assert_eq!(SslMode::VerifyCa.as_str(), "verify-ca");
        assert_eq!(SslMode::VerifyFull.as_str(), "verify-full");
    }
}
