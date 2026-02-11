//! # Database Configuration
//!
//! Database configuration handling for the CLI, reading from environment variables.

use std::net::SocketAddr;

/// Database configuration for CLI
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database host address
    pub host:     String,
    /// Database port number
    pub port:     u16,
    /// Database name
    pub database: String,
    /// Database username
    pub username: String,
    /// Database password
    pub password: String,
    /// SSL mode
    pub ssl_mode: String,
}

/// Errors that can occur when parsing database configuration.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseConfigError {
    /// The port number could not be parsed as a valid number.
    #[error("Invalid port number: {value}")]
    InvalidPort {
        /// The invalid port value that was provided.
        value: String,
    },
}

impl DatabaseConfig {
    /// Creates a new DatabaseConfig from environment variables.
    ///
    /// Returns `Err` if any required environment variable has an invalid format.
    pub fn from_env() -> Result<Self, DatabaseConfigError> {
        let port_str = std::env::var("HORIZON_DATABASE_PORT").unwrap_or_else(|_| "5432".to_owned());
        let port = port_str.parse::<u16>().map_err(|_e| {
            DatabaseConfigError::InvalidPort {
                value: port_str.clone(),
            }
        })?;

        Ok(Self {
            host: std::env::var("HORIZON_DATABASE_HOST").unwrap_or_else(|_| "localhost".to_owned()),
            port,
            database: std::env::var("HORIZON_DATABASE_NAME").unwrap_or_else(|_| "horizon".to_owned()),
            username: std::env::var("HORIZON_DATABASE_USER").unwrap_or_else(|_| "horizon".to_owned()),
            password: std::env::var("HORIZON_DATABASE_PASSWORD").unwrap_or_else(|_| String::new()),
            ssl_mode: std::env::var("HORIZON_DATABASE_SSL_MODE").unwrap_or_else(|_| "require".to_owned()),
        })
    }
}

/// Builds the DATABASE_URL from DatabaseConfig
///
/// # Arguments
///
/// * `config` - The database configuration to use
///
/// # Returns
///
/// A PostgreSQL connection URL string.
pub fn build_database_url(config: &DatabaseConfig) -> String {
    // Percent-encode username and password for PostgreSQL URI
    let encoded_username = percent_encode_username_password(&config.username);
    let encoded_password = percent_encode_username_password(&config.password);
    format!(
        "postgres://{}:{}@{}:{}/{}?sslmode={}",
        encoded_username, encoded_password, config.host, config.port, config.database, config.ssl_mode
    )
}

/// Simple percent-encoding for username/password in PostgreSQL URIs
/// Encodes @, :, /, ?, #, [, ], and % as required
fn percent_encode_username_password(s: &str) -> String {
    s.chars().fold(String::new(), |mut acc, c| {
        match c {
            '@' => acc.push_str("%40"),
            ':' => acc.push_str("%3A"),
            '/' => acc.push_str("%2F"),
            '?' => acc.push_str("%3F"),
            '#' => acc.push_str("%23"),
            '[' => acc.push_str("%5B"),
            ']' => acc.push_str("%5D"),
            '%' => acc.push_str("%25"),
            c => acc.push(c),
        }
        acc
    })
}

/// Parses a host and port into a SocketAddr.
///
/// # Arguments
///
/// * `host` - The host string to parse
/// * `port` - The port number
///
/// # Returns
///
/// A `Result` containing the parsed `SocketAddr` or an error if parsing fails.
pub fn parse_socket_addr(host: &str, port: u16) -> Result<SocketAddr, std::net::AddrParseError> {
    // IPv6 addresses must be wrapped in brackets when appending a port
    // e.g., "::1" becomes "[::1]:3000"
    let addr_str = if host.contains(':') {
        format!("[{}]:{}", host, port)
    }
    else {
        format!("{}:{}", host, port)
    };
    addr_str.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_database_url() {
        let config = DatabaseConfig {
            host:     "localhost".to_string(),
            port:     5432,
            database: "horizon".to_string(),
            username: "horizon".to_string(),
            password: "secret".to_string(),
            ssl_mode: "require".to_string(),
        };

        let url = build_database_url(&config);
        assert_eq!(
            url,
            "postgres://horizon:secret@localhost:5432/horizon?sslmode=require"
        );
    }

    #[test]
    fn test_build_database_url_special_chars() {
        let config = DatabaseConfig {
            host:     "localhost".to_string(),
            port:     5432,
            database: "test_db".to_string(),
            username: "user@domain".to_string(),
            password: "pass:word@123".to_string(),
            ssl_mode: "require".to_string(),
        };

        let url = build_database_url(&config);
        assert_eq!(
            url,
            "postgres://user%40domain:pass%3Aword%40123@localhost:5432/test_db?sslmode=require"
        );
    }

    #[test]
    fn test_build_database_url_empty_password() {
        let config = DatabaseConfig {
            host:     "localhost".to_string(),
            port:     5432,
            database: "test".to_string(),
            username: "user".to_string(),
            password: String::new(),
            ssl_mode: "require".to_string(),
        };

        let url = build_database_url(&config);
        assert_eq!(url, "postgres://user:@localhost:5432/test?sslmode=require");
    }

    #[test]
    fn test_parse_socket_addr() {
        let addr = parse_socket_addr("0.0.0.0", 3000);
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().to_string(), "0.0.0.0:3000");
    }

    #[test]
    fn test_parse_socket_addr_localhost() {
        let addr = parse_socket_addr("127.0.0.1", 8080);
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_socket_addr_ipv6() {
        let addr = parse_socket_addr("::1", 3000);
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().to_string(), "[::1]:3000");
    }

    #[test]
    fn test_parse_socket_addr_ipv6_full() {
        let addr = parse_socket_addr("2001:db8::1", 8080);
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().to_string(), "[2001:db8::1]:8080");
    }
}
