//! # Token Blacklist Service
//!
//! Manages Redis-based token blacklisting for immediate token invalidation.

use chrono::{DateTime, Utc};
use redis::{AsyncCommands, RedisResult};
use tracing::debug;
use error::Result;

/// Token blacklist service for managing revoked tokens in Redis
#[derive(Clone, Debug)]
pub struct TokenBlacklist {
    /// Redis client connection
    client: redis::Client,
}

impl TokenBlacklist {
    /// Create a new token blacklist service
    #[must_use]
    pub fn new(client: redis::Client) -> Self {
        Self {
            client,
        }
    }

    /// Add a token to the blacklist
    ///
    /// # Arguments
    ///
    /// * `token_hash` - BLAKE3 hash of the token to blacklist
    /// * `expires_at` - When the token naturally expires (for TTL)
    ///
    /// # Errors
    ///
    /// Returns an error if Redis operation fails
    pub async fn blacklist_token(&self, token_hash: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        // Calculate TTL in seconds from now until token expires
        let now = Utc::now();
        let ttl_seconds = if expires_at > now {
            (expires_at - now).num_seconds()
        }
        else {
            // Token already expired, but blacklist it for a short time anyway
            300i64 // 5 minutes
        };

        // Use SET with EX for automatic expiration
        let key = format!("blacklist:token:{}", token_hash);
        let _: () = conn.set_ex(key, "revoked", ttl_seconds as u64).await?;

        debug!(token_hash = %token_hash, ttl_seconds, "Token added to blacklist");

        Ok(())
    }

    /// Check if a token is blacklisted
    ///
    /// # Arguments
    ///
    /// * `token_hash` - BLAKE3 hash of the token to check
    ///
    /// # Errors
    ///
    /// Returns an error if Redis operation fails
    pub async fn is_blacklisted(&self, token_hash: &str) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("blacklist:token:{}", token_hash);
        let result: RedisResult<Option<String>> = conn.get(key).await;

        match result {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => {
                Err(error::AppError::database(format!(
                    "Redis blacklist check failed: {}",
                    e
                )))
            },
        }
    }

    /// Remove a token from the blacklist (for testing/admin purposes)
    ///
    /// # Arguments
    ///
    /// * `token_hash` - BLAKE3 hash of the token to remove
    ///
    /// # Errors
    ///
    /// Returns an error if Redis operation fails
    pub async fn remove_from_blacklist(&self, token_hash: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("blacklist:token:{}", token_hash);
        let _: () = conn.del(key).await?;

        debug!(token_hash = %token_hash, "Token removed from blacklist");

        Ok(())
    }

    /// Get blacklist statistics
    ///
    /// # Errors
    ///
    /// Returns an error if Redis operation fails
    pub async fn stats(&self) -> Result<BlacklistStats> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        // Count keys matching the blacklist pattern
        let pattern = "blacklist:token:*";
        let keys: Vec<String> = conn.keys(pattern).await?;
        let total_tokens = keys.len();

        Ok(BlacklistStats {
            total_tokens,
        })
    }

    /// Cleanup expired blacklist entries
    ///
    /// This method actively scans the blacklist for expired entries and removes them.
    /// While Redis automatically handles TTL expiration, this method ensures
    /// cleanup and returns the count of removed entries for monitoring purposes.
    ///
    /// # Errors
    ///
    /// Returns an error if Redis operation fails
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let mut deleted_count = 0u64;
        let pattern = "blacklist:token:*";

        // Use Redis SCAN to iterate through all blacklist keys
        let mut cursor = 0u64;

        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;

            // Check each key and delete if expired
            for key in &keys {
                // Use TTL command to check remaining time
                let ttl: RedisResult<i64> = conn.ttl(key).await;

                match ttl {
                    Ok(ttl_value) => {
                        if ttl_value <= 0 {
                            // TTL is 0 or negative, key should be expired
                            let _: () = conn.del(key).await?;
                            deleted_count += 1;
                        }
                        // If ttl_value > 0, key still has time remaining
                    },
                    Err(e) => {
                        debug!(key = %key, error = %e, "Error checking TTL during cleanup");
                        continue;
                    },
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        tracing::info!(deleted_count = %deleted_count, "Expired tokens cleaned from blacklist");

        Ok(deleted_count)
    }
}

/// Statistics about the token blacklist
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlacklistStats {
    /// Total number of tokens currently blacklisted
    pub total_tokens: usize,
}

/// Hash a JWT token for blacklisting
///
/// # Arguments
///
/// * `token` - The raw JWT token string
///
/// # Returns
///
/// BLAKE3 hash of the token suitable for Redis keys
#[must_use]
pub fn hash_token_for_blacklist(token: &str) -> String { blake3::hash(token.as_bytes()).to_hex().to_string() }

#[cfg(test)]
mod tests {
    use redis::Client;

    use super::*;

    async fn setup_test_redis() -> Client {
        // For tests, we'll use a mock or skip if Redis not available
        // In real tests, you'd set up a test Redis instance
        Client::open("redis://127.0.0.1:6379").expect("Failed to create Redis client")
    }

    #[tokio::test]
    async fn test_token_hashing() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test.signature";
        let hash1 = hash_token_for_blacklist(token);
        let hash2 = hash_token_for_blacklist(token);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (32 bytes hex encoded)
        assert_eq!(hash1.len(), 64);
    }

    // Note: Redis integration tests would require a running Redis instance
    // These are commented out to avoid test failures in CI
    // #[tokio::test]
    // async fn test_blacklist_operations() {
    // let client = setup_test_redis().await;
    // let blacklist = TokenBlacklist::new(client);
    //
    // let token = "test.jwt.token";
    // let token_hash = hash_token_for_blacklist(token);
    // let expires_at = Utc::now() + chrono::Duration::hours(1);
    //
    // Initially not blacklisted
    // assert!(!blacklist.is_blacklisted(&token_hash).await.unwrap());
    //
    // Blacklist the token
    // blacklist.blacklist_token(&token_hash, expires_at).await.unwrap();
    //
    // Now it should be blacklisted
    // assert!(blacklist.is_blacklisted(&token_hash).await.unwrap());
    //
    // Remove from blacklist
    // blacklist.remove_from_blacklist(&token_hash).await.unwrap();
    //
    // Should no longer be blacklisted
    // assert!(!blacklist.is_blacklisted(&token_hash).await.unwrap());
    // }
}
