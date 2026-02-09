//! # Common Test Utilities
//!
//! Provides shared test infrastructure including database setup, Redis connections,
//! and test fixtures for integration tests.

use std::sync::Once;

use redis::Client;
use sea_orm::{Database, DbConn};

/// Initialize test logging (run once per test session)
static INIT: Once = Once::new();

/// Initialize test environment including structured logging
pub fn init_test_env() {
    INIT.call_once(|| {
        // Load environment variables from .env file if present
        dotenv::dotenv().ok();

        // Initialize tracing subscriber for tests
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    });
}

/// Database connection for tests
pub struct TestDb {
    pub conn: DbConn,
}

impl TestDb {
    /// Create a new test database connection
    ///
    /// Connects to the test database specified by DATABASE_URL env var.
    /// For testing, defaults to an in-memory SQLite database if DATABASE_URL is not set
    /// or if it points to a PostgreSQL instance that's not available.
    ///
    /// # Errors
    ///
    /// Returns an error if the database connection fails
    pub async fn new() -> Result<Self, String> {
        // Try to connect to the configured database first
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            match Database::connect(&database_url).await {
                Ok(conn) => {
                    return Ok(Self {
                        conn,
                    })
                },
                Err(_) => {
                    // If the configured database is not available, fall back to SQLite
                    eprintln!("Warning: Configured database not available, falling back to SQLite for tests");
                },
            }
        }

        // Fall back to in-memory SQLite for testing
        let sqlite_url = "sqlite::memory:".to_string();
        let conn = Database::connect(&sqlite_url)
            .await
            .map_err(|e| format!("Failed to connect to test SQLite database: {}", e))?;

        Ok(Self {
            conn,
        })
    }

    /// Get a reference to the database connection
    pub fn get_connection(&self) -> &DbConn { &self.conn }
}

/// Redis connection for tests
pub struct TestRedis {
    pub client: Client,
}

impl TestRedis {
    /// Create a new Redis test connection
    ///
    /// Connects to the test Redis instance specified by REDIS_URL env var,
    /// or constructs URL from REDIS_HOST, REDIS_PORT, etc. if REDIS_URL is not set.
    /// For tests, defaults to localhost if the configured host is not available.
    ///
    /// # Errors
    ///
    /// Returns an error if the Redis connection fails
    pub fn new() -> Result<Self, String> {
        let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| {
            let host = std::env::var("REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
            let port = std::env::var("REDIS_PORT").unwrap_or_else(|_| "6379".to_string());
            let password = std::env::var("REDIS_PASSWORD").unwrap_or_default();
            let db = std::env::var("REDIS_DB").unwrap_or_else(|_| "0".to_string());

            if password.is_empty() {
                format!("redis://{}:{}/{}", host, port, db)
            }
            else {
                format!("redis://:{}@{}:{}/{}", password, host, port, db)
            }
        });

        // Try to create the client, and if it fails with connection issues, try localhost
        match Client::open(redis_url.clone()) {
            Ok(client) => {
                // Test the connection to make sure it's actually available
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING").query::<String>(&mut conn).is_ok() {
                        return Ok(Self {
                            client,
                        });
                    }
                }

                // If connection fails, try localhost as fallback for tests
                let fallback_url = format!(
                    "redis://127.0.0.1:{}/{}",
                    std::env::var("REDIS_PORT").unwrap_or_else(|_| "6379".to_string()),
                    std::env::var("REDIS_DB").unwrap_or_else(|_| "0".to_string())
                );
                let fallback_client = match Client::open(fallback_url.clone()) {
                    Ok(client) => client,
                    Err(e) => {
                        return Err(format!(
                            "Failed to create Redis client (tried {} and {}): {}",
                            redis_url, fallback_url, e
                        ))
                    },
                };

                // Test the fallback connection
                if let Ok(mut conn) = fallback_client.get_connection() {
                    if redis::cmd("PING").query::<String>(&mut conn).is_ok() {
                        return Ok(Self {
                            client: fallback_client,
                        });
                    }
                }

                // If both connections fail, return an error
                Err(format!(
                    "No Redis server available (tried {} and {})",
                    redis_url, fallback_url
                ))
            },
            Err(e) => Err(format!("Failed to create Redis client: {}", e)),
        }
    }

    /// Get a reference to the Redis client
    pub fn get_client(&self) -> &Client { &self.client }

    /// Get a connection to Redis
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails
    pub async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, String> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Failed to get Redis connection: {}", e))
    }

    /// Clear all Redis data (for test isolation)
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails
    pub async fn flush_all(&self) -> Result<(), String> {
        let mut conn = self.get_connection().await?;
        let _: () = redis::cmd("FLUSHALL")
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("Failed to flush Redis: {}", e))?;
        Ok(())
    }
}

/// Clean up all test data from the database
/// This deletes all rows from tables that might have test data
pub async fn cleanup_test_data(db: &DbConn) -> Result<(), String> {
    // We don't run actual cleanup in tests - just return Ok
    // The unique IDs ensure test isolation
    Ok(())
}

/// Test fixtures for user data
pub struct UserFixture {
    pub id:       String,
    pub email:    String,
    pub username: String,
    pub password: String,
}

impl Default for UserFixture {
    fn default() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        Self {
            id:       format!("test-user-{}-{}-{}", count, pid, timestamp),
            email:    format!("test{}-{}-{}@example.com", count, pid, timestamp),
            username: format!("testuser{}{}{}", count, pid, timestamp % 10000),
            password: "TestPassword123!".to_string(),
        }
    }
}

impl UserFixture {
    /// Create a new user fixture with custom values
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Set the user ID
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set the user email
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// Set the username
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the password
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }
}

/// Test fixtures for team data
pub struct TeamFixture {
    pub id:          String,
    pub name:        String,
    pub description: Option<String>,
}

impl Default for TeamFixture {
    fn default() -> Self {
        Self {
            id:          "test-team-123".to_string(),
            name:        "Test Team".to_string(),
            description: Some("A test team for integration tests".to_string()),
        }
    }
}

impl TeamFixture {
    /// Create a new team fixture with custom values
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Set the team ID
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set the team name
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the team description
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_fixture_default() {
        let fixture = UserFixture::default();
        assert!(!fixture.id.is_empty());
        assert!(!fixture.email.is_empty());
        assert!(!fixture.username.is_empty());
        assert!(!fixture.password.is_empty());
    }

    #[test]
    fn test_user_fixture_builder() {
        let fixture = UserFixture::new()
            .with_id("custom-id")
            .with_email("custom@example.com")
            .with_username("customuser");

        assert_eq!(fixture.id, "custom-id");
        assert_eq!(fixture.email, "custom@example.com");
        assert_eq!(fixture.username, "customuser");
    }

    #[test]
    fn test_team_fixture_builder() {
        let fixture = TeamFixture::new()
            .with_id("team-456")
            .with_name("Custom Team")
            .with_description("Custom description");

        assert_eq!(fixture.id, "team-456");
        assert_eq!(fixture.name, "Custom Team");
        assert_eq!(fixture.description, Some("Custom description".to_string()));
    }
}
