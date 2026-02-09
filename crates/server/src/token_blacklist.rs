//! # Token Blacklist Service
//!
//! Manages Redis-based token blacklisting for immediate token invalidation.

use std::collections::HashSet;

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

        // Count keys matching the blacklist pattern using SCAN to avoid blocking
        let pattern = "blacklist:token:*";
        let mut total_tokens = 0u64;
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

            total_tokens += keys.len() as u64;
            cursor = next_cursor;

            if cursor == 0 {
                break;
            }
        }

        Ok(BlacklistStats {
            total_tokens: total_tokens as usize,
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
    use super::*;

    // ==================== token hash tests ====================

    #[test]
    fn test_hash_token_deterministic() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test";
        let hash1 = hash_token_for_blacklist(token);
        let hash2 = hash_token_for_blacklist(token);

        // Same input should always produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_format() {
        let token = "test.jwt.token";
        let hash = hash_token_for_blacklist(token);

        // Hash should be 64 characters (32 bytes hex encoded with BLAKE3)
        assert_eq!(hash.len(), 64);

        // Hash should only contain hex characters (0-9, a-f)
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_empty_string() {
        let token = "";
        let hash = hash_token_for_blacklist(token);

        // Empty string should still produce valid hash
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_sensitive_to_changes() {
        let token1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test.signature";
        let token2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test.signaturE"; // Changed last char

        let hash1 = hash_token_for_blacklist(token1);
        let hash2 = hash_token_for_blacklist(token2);

        // Different tokens should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_long_string() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjIwMDAwMDAwMDAsImlzcyI6ImF1dGgiLCJhdWQiOiJhcGkifQ.verylongsignaturewithalotofcharacterstomakethetokenevenlargerandtestthatfunctioncanhandlelonginputs";
        let hash = hash_token_for_blacklist(token);

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_with_special_chars() {
        let token = "!@#$%^&*()_+-=[]{}|;:',.<>?/\\`~";
        let hash = hash_token_for_blacklist(token);

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_with_unicode() {
        let token = "token_with_unicode_🎉_emoji_and_中文";
        let hash = hash_token_for_blacklist(token);

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_whitespace() {
        let token = "token   with   spaces\tand\ttabs\nand\nnewlines";
        let hash = hash_token_for_blacklist(token);

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_case_sensitivity() {
        let token_lower = "eyj0exaiojsijEyfHb21j0eXaiojsjnv4.test.signature";
        let token_upper = "EYJ0EXAIOJSIJEYB0EXB1OJSJNV4.TEST.SIGNATURE";

        let hash_lower = hash_token_for_blacklist(token_lower);
        let hash_upper = hash_token_for_blacklist(token_upper);

        // Different case = different tokens = different hashes
        assert_ne!(hash_lower, hash_upper);
    }

    #[test]
    fn test_hash_token_multiple_calls_unique() {
        // Different tokens should all produce different hashes
        let tokens = vec![
            "token1.signature.here",
            "token2.signature.here",
            "token3.signature.here",
            "token4.signature.here",
            "token5.signature.here",
        ];

        let hashes: Vec<_> = tokens.iter().map(|t| hash_token_for_blacklist(t)).collect();

        // All hashes should be unique
        let mut deduped = hashes.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(hashes.len(), deduped.len());
    }

    // ==================== blacklist stats tests ====================

    #[test]
    fn test_blacklist_stats_structure() {
        let stats = BlacklistStats {
            total_tokens: 42,
        };

        assert_eq!(stats.total_tokens, 42);
    }

    #[test]
    fn test_blacklist_stats_zero() {
        let stats = BlacklistStats {
            total_tokens: 0,
        };

        assert_eq!(stats.total_tokens, 0);
    }

    #[test]
    fn test_blacklist_stats_large_number() {
        let stats = BlacklistStats {
            total_tokens: 1_000_000_000,
        };

        assert_eq!(stats.total_tokens, 1_000_000_000);
    }

    #[test]
    fn test_blacklist_stats_clone() {
        let stats1 = BlacklistStats {
            total_tokens: 100,
        };
        let stats2 = stats1.clone();

        // Cloned stats should have same value
        assert_eq!(stats1.total_tokens, stats2.total_tokens);
        assert_eq!(stats1, stats2);
    }

    #[test]
    fn test_blacklist_stats_equality() {
        let stats1 = BlacklistStats {
            total_tokens: 50,
        };
        let stats2 = BlacklistStats {
            total_tokens: 50,
        };
        let stats3 = BlacklistStats {
            total_tokens: 51,
        };

        assert_eq!(stats1, stats2);
        assert_ne!(stats1, stats3);
    }

    #[test]
    fn test_blacklist_stats_debug_format() {
        let stats = BlacklistStats {
            total_tokens: 25,
        };
        let debug_str = format!("{:?}", stats);

        assert!(debug_str.contains("BlacklistStats"));
        assert!(debug_str.contains("25"));
    }

    // ==================== token blacklist structure tests ====================

    #[test]
    fn test_token_blacklist_new() {
        // Create a client that would connect to Redis (note: actual Redis might not be available)
        // But we can test that the constructor works with a valid client
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let blacklist = TokenBlacklist::new(client);

        // TokenBlacklist should be cloneable and debuggable
        let _cloned = blacklist.clone();
    }

    #[test]
    fn test_token_blacklist_clone() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let blacklist1 = TokenBlacklist::new(client.clone());
        let blacklist2 = blacklist1.clone();

        // Both instances should be valid TokenBlacklist instances
        // They should be separate clones but represent the same service
        let _debug1 = format!("{:?}", blacklist1);
        let _debug2 = format!("{:?}", blacklist2);
    }

    #[test]
    fn test_token_blacklist_debug_format() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let blacklist = TokenBlacklist::new(client);
        let debug_str = format!("{:?}", blacklist);

        // Debug format should contain TokenBlacklist
        assert!(debug_str.contains("TokenBlacklist"));
    }

    // ==================== integration-style tests (unit level) ====================

    #[test]
    fn test_hash_token_consistency_across_multiple_calls() {
        let token = "test.example.token";
        let mut hashes = Vec::new();

        // Call hash function many times
        for _ in 0 .. 100 {
            hashes.push(hash_token_for_blacklist(token));
        }

        // All hashes should be identical for same input
        assert!(hashes.iter().all(|h| h == &hashes[0]));
    }

    #[test]
    fn test_hash_token_collision_resistance() {
        // Test that slightly different tokens produce completely different hashes
        let base = "base.token.string";
        let mut variations = vec![];

        for i in 0 .. 10 {
            let variant = format!("{}.{}", base, i);
            variations.push(hash_token_for_blacklist(&variant));
        }

        // Check that all hashes are unique
        for i in 0 .. variations.len() {
            for j in (i + 1) .. variations.len() {
                assert_ne!(
                    variations[i], variations[j],
                    "Hashes for variant {} and {} should be different",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_hash_token_entropy() {
        // Generate hashes from many different tokens
        let mut hashes = HashSet::new();

        for i in 0 .. 50 {
            let token = format!("token_{}_unique_input", i);
            let hash = hash_token_for_blacklist(&token);
            hashes.insert(hash);
        }

        // All 50 hashes should be unique
        assert_eq!(
            hashes.len(),
            50,
            "Expected 50 unique hashes, got {}",
            hashes.len()
        );
    }

    #[test]
    fn test_blacklist_stats_field_independence() {
        let stats1 = BlacklistStats {
            total_tokens: 10,
        };
        let stats2 = BlacklistStats {
            total_tokens: 20,
        };

        // Modifying one shouldn't affect the other
        assert_ne!(stats1.total_tokens, stats2.total_tokens);
        assert_ne!(stats1, stats2);
    }

    #[test]
    fn test_hash_token_key_format_compatibility() {
        let token = "test.jwt.token";
        let hash = hash_token_for_blacklist(token);

        // Hash should be suitable for use in Redis keys
        // Redis keys can contain any binary data, but hex strings are safe
        let redis_key = format!("blacklist:token:{}", hash);

        // Key should be valid length and format
        assert!(redis_key.len() > 0);
        assert!(redis_key.contains("blacklist:token:"));
        assert_eq!(redis_key.len(), "blacklist:token:".len() + 64);
    }
}
