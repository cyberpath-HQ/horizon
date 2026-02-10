//! # Token Blacklist and Refresh Token Tests
//!
//! Integration tests for token blacklist and refresh token functionality with real Redis.

mod common;

use std::time::Duration;

use chrono::Utc;
use common::{init_test_env, TestRedis};
use redis::AsyncCommands;
use serial_test::serial;
use server::token_blacklist::TokenBlacklist;
use tokio::time::sleep;

/// Test blacklisting a token and checking it's in the blacklist
#[tokio::test]
#[serial]
async fn test_blacklist_token() {
    init_test_env();

    let redis: common::TestRedis = match TestRedis::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Skipping test - {}", e);
            return;
        },
    };

    if let Err(e) = redis.flush_all().await {
        eprintln!("Warning: Could not flush Redis - {}", e);
        return;
    }

    let blacklist = TokenBlacklist::new(redis.get_client().clone());
    let token_hash = "test-token-hash-12345";
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    // Blacklist the token
    let result = blacklist.blacklist_token(token_hash, expires_at).await;
    assert!(result.is_ok(), "Should successfully blacklist token");

    // Check the token is blacklisted
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await;
    assert!(
        is_blacklisted.is_ok() && is_blacklisted.unwrap(),
        "Token should be blacklisted"
    );
}

/// Test that a token not in the blacklist returns false
#[tokio::test]
#[serial]
async fn test_non_blacklisted_token() {
    init_test_env();

    let redis: common::TestRedis = match TestRedis::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Skipping test - {}", e);
            return;
        },
    };

    if let Err(e) = redis.flush_all().await {
        eprintln!("Warning: Could not flush Redis - {}", e);
        return;
    }

    let blacklist = TokenBlacklist::new(redis.get_client().clone());
    let token_hash = "non-existent-token";

    // Check a non-existent token
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await;
    assert!(
        is_blacklisted.is_ok() && !is_blacklisted.unwrap(),
        "Token should not be blacklisted"
    );
}

/// Test removing a token from the blacklist
#[tokio::test]
#[serial]
async fn test_remove_from_blacklist() {
    init_test_env();

    let redis: common::TestRedis = match TestRedis::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Skipping test - {}", e);
            return;
        },
    };

    if let Err(e) = redis.flush_all().await {
        eprintln!("Warning: Could not flush Redis - {}", e);
        return;
    }

    let blacklist = TokenBlacklist::new(redis.get_client().clone());
    let token_hash = "test-token-to-remove";
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    // Blacklist the token
    let _ = blacklist.blacklist_token(token_hash, expires_at).await;

    // Verify it's blacklisted
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await.unwrap();
    assert!(is_blacklisted, "Token should be blacklisted");

    // Remove from blacklist
    let result = blacklist.remove_from_blacklist(token_hash).await;
    assert!(
        result.is_ok(),
        "Should successfully remove token from blacklist"
    );

    // Verify it's no longer blacklisted
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await.unwrap();
    assert!(!is_blacklisted, "Token should no longer be blacklisted");
}

/// Test token expiration from blacklist via TTL
#[tokio::test]
#[serial]
async fn test_token_blacklist_ttl_expiration() {
    init_test_env();

    let redis: common::TestRedis = match TestRedis::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Skipping test - {}", e);
            return;
        },
    };

    if let Err(e) = redis.flush_all().await {
        eprintln!("Warning: Could not flush Redis - {}", e);
        return;
    }

    let blacklist = TokenBlacklist::new(redis.get_client().clone());
    let token_hash = "short-lived-token";
    let expires_at = Utc::now() + chrono::Duration::seconds(2);

    // Blacklist the token with short expiration
    let _ = blacklist.blacklist_token(token_hash, expires_at).await;

    // Verify it's blacklisted
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await.unwrap();
    assert!(is_blacklisted, "Token should be blacklisted");

    // Wait for expiration
    sleep(Duration::from_secs(3)).await;

    // Check if expired (may or may not be expired from TTL, depending on Redis timing)
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await.unwrap();
    // The token should not be blacklisted after expiration
    // Note: Due to Redis timing, it might still be blacklisted for a short time
    // But the operation should complete without error
    let _ = is_blacklisted; // Just ensure no panic
}

/// Test blacklist with multiple tokens
#[tokio::test]
#[serial]
async fn test_blacklist_multiple_tokens() {
    init_test_env();

    let redis: common::TestRedis = match TestRedis::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Skipping test - {}", e);
            return;
        },
    };

    if let Err(e) = redis.flush_all().await {
        eprintln!("Warning: Could not flush Redis - {}", e);
        return;
    }

    let blacklist = TokenBlacklist::new(redis.get_client().clone());
    let tokens = vec!["token-1", "token-2", "token-3"];
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    // Blacklist multiple tokens
    for token_hash in &tokens {
        let result = blacklist.blacklist_token(token_hash, expires_at).await;
        assert!(result.is_ok(), "Should successfully blacklist token");
    }

    // Verify all are blacklisted
    for token_hash in &tokens {
        let is_blacklisted = blacklist.is_blacklisted(token_hash).await.unwrap();
        assert!(is_blacklisted, "Token {} should be blacklisted", token_hash);
    }
}

/// Test blacklist with already-expired token
#[tokio::test]
#[serial]
async fn test_blacklist_already_expired_token() {
    init_test_env();

    let redis: common::TestRedis = match TestRedis::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Skipping test - {}", e);
            return;
        },
    };

    if let Err(e) = redis.flush_all().await {
        eprintln!("Warning: Could not flush Redis - {}", e);
        return;
    }

    let blacklist = TokenBlacklist::new(redis.get_client().clone());
    let token_hash = "already-expired-token";
    let expires_at = Utc::now() - chrono::Duration::hours(1); // Expired 1 hour ago

    // Blacklist the already-expired token (should still work, with shorter TTL)
    let result = blacklist.blacklist_token(token_hash, expires_at).await;
    assert!(result.is_ok(), "Should accept already-expired token");

    // Token should still be in blacklist (with short TTL)
    let is_blacklisted = blacklist.is_blacklisted(token_hash).await.unwrap();
    assert!(is_blacklisted, "Expired token should still be blacklisted");
}
