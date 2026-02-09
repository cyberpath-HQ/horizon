//! # Common Test Utilities
//!
//! Provides shared test infrastructure using real PostgreSQL and Redis.
//! Tests assume Docker services are running (see docker-compose.yml).

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

/// Get database connection using DATABASE_URL from environment
pub async fn get_real_db() -> Result<DbConn, String> {
    init_test_env();

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set for tests. Make sure Docker is running.")?;

    Database::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))
}

/// Get Redis client using REDIS_URL or constructed from environment
pub fn get_real_redis() -> Result<Client, String> {
    init_test_env();

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

    Client::open(redis_url).map_err(|e| format!("Failed to create Redis client: {}", e))
}

/// Database connection for tests (uses real PostgreSQL)
pub struct TestDb {
    pub conn: DbConn,
}

impl TestDb {
    /// Create a new test database connection using real PostgreSQL
    pub async fn new() -> Result<Self, String> {
        let conn = get_real_db().await?;
        Ok(Self {
            conn,
        })
    }

    /// Get a reference to the database connection
    pub fn get_connection(&self) -> &DbConn { &self.conn }
}

/// Redis connection for tests (uses real Redis)
pub struct TestRedis {
    pub client: Client,
}

impl TestRedis {
    /// Create a new Redis test connection using real Redis
    pub fn new() -> Result<Self, String> {
        let client = get_real_redis()?;
        Ok(Self {
            client,
        })
    }

    /// Get a reference to the Redis client
    pub fn get_client(&self) -> &Client { &self.client }

    /// Get a connection to Redis
    pub async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, String> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Failed to get Redis connection: {}", e))
    }

    /// Clear all Redis data (for test isolation)
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
pub async fn cleanup_test_data(db: &DbConn) -> Result<(), String> {
    // Tests use UUID-based IDs for isolation, cleanup happens per-test or via test infrastructure
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
        // Use UUID for guaranteed uniqueness across test runs
        let uuid = uuid::Uuid::new_v4();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self {
            id:       format!("test-user-{}", uuid),
            email:    format!("test-{}@example.com", uuid),
            username: format!("testuser_{}", uuid.simple()),
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
        let uuid = uuid::Uuid::new_v4();
        Self {
            id:          format!("test-team-{}", uuid),
            name:        format!("Test Team {}", uuid.simple()),
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
