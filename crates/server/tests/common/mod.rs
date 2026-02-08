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
    /// Connects to the test PostgreSQL database specified by DATABASE_URL env var.
    /// The database should be created and migrations should be run before calling this.
    ///
    /// # Errors
    ///
    /// Returns an error if the database connection fails
    pub async fn new() -> Result<Self, String> {
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL environment variable not set".to_string())?;

        let conn = Database::connect(&database_url)
            .await
            .map_err(|e| format!("Failed to connect to test database: {}", e))?;

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
    /// Connects to the test Redis instance specified by REDIS_URL env var.
    ///
    /// # Errors
    ///
    /// Returns an error if the Redis connection fails
    pub fn new() -> Result<Self, String> {
        let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let client = Client::open(redis_url).map_err(|e| format!("Failed to create Redis client: {}", e))?;

        Ok(Self {
            client,
        })
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

/// Test fixtures for user data
pub struct UserFixture {
    pub id:       String,
    pub email:    String,
    pub username: String,
    pub password: String,
}

impl Default for UserFixture {
    fn default() -> Self {
        Self {
            id:       "test-user-123".to_string(),
            email:    "test@example.com".to_string(),
            username: "testuser".to_string(),
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
