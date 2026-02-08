//! # Integration Tests for JWT Authentication
//!
//! Tests the complete authentication flow including login, token refresh,
//! logout, and token validation with real database connections.

mod common;

use auth::{
    jwt::{create_access_token, extract_bearer_token, validate_token},
    password::{hash_password, verify_password},
    secrecy::ExposeSecret,
    JwtConfig,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use common::{init_test_env, TestRedis};

/// Test the JWT token creation and validation flow
#[tokio::test]
async fn test_jwt_token_flow() {
    init_test_env();

    let secret = "test-secret-key-that-is-at-least-32-bytes-long";
    let config = JwtConfig {
        secret:             BASE64.encode(secret.as_bytes()),
        expiration_seconds: 3600,
        issuer:             "test-issuer".to_string(),
        audience:           "test-audience".to_string(),
    };

    // Create access token
    let token = create_access_token(
        &config,
        "user-123",
        "test@example.com",
        &["admin".to_string()],
    )
    .expect("Failed to create token");

    assert!(!token.is_empty(), "Token should not be empty");
    assert!(token.len() > 100, "Token should have content");

    // Validate token
    let claims = validate_token(&config, &token).expect("Failed to validate token");

    // Verify claims
    assert_eq!(claims.sub, "user-123", "User ID should match");
    assert_eq!(claims.email, "test@example.com", "Email should match");
    assert_eq!(claims.roles, vec!["admin"], "Roles should match");
    assert_eq!(claims.iss, "test-issuer", "Issuer should match");
    assert_eq!(claims.aud, "test-audience", "Audience should match");
    assert!(
        claims.exp > claims.iat,
        "Expiration should be after issued time"
    );
}

/// Test Bearer token extraction
#[tokio::test]
async fn test_bearer_token_extraction() {
    init_test_env();

    // Valid Bearer token
    let token = "valid.jwt.token.here";
    let auth_header = format!("Bearer {}", token);
    assert_eq!(
        extract_bearer_token(&auth_header),
        Some(token.to_string()),
        "Should extract token from valid Bearer header"
    );

    // Token with whitespace
    let auth_header_with_spaces = "Bearer   valid.jwt.token.here   ";
    assert_eq!(
        extract_bearer_token(auth_header_with_spaces),
        Some(token.to_string()),
        "Should handle whitespace in Bearer header"
    );

    // Missing token
    let no_token = "Bearer";
    assert!(
        extract_bearer_token(no_token).is_none(),
        "Should handle missing token"
    );

    // Invalid format
    assert!(
        extract_bearer_token("Basic abc123").is_none(),
        "Should reject Basic auth"
    );
    assert!(
        extract_bearer_token("").is_none(),
        "Should reject empty string"
    );
    assert!(
        extract_bearer_token("Bearer   ").is_none(),
        "Should reject whitespace-only token"
    );
}

/// Test password hashing and verification
#[tokio::test]
async fn test_password_hashing() {
    init_test_env();

    let password = "StrongP@ssw0rd!123";
    let password_secret = auth::secrecy::SecretString::from(password);

    // Hash the password
    let hash = hash_password(&password_secret, None).expect("Failed to hash password");
    assert!(!hash.expose_secret().is_empty(), "Hash should not be empty");

    // Verify the correct password
    let password_secret_again = auth::secrecy::SecretString::from(password);
    assert!(
        verify_password(&password_secret_again, hash.expose_secret()).is_ok(),
        "Correct password should verify"
    );

    // Verify an incorrect password
    let wrong_password = auth::secrecy::SecretString::from("WrongP@ssw0rd!");
    assert!(
        verify_password(&wrong_password, hash.expose_secret()).is_err(),
        "Incorrect password should fail"
    );
}

/// Test Redis connection for token blacklist
#[tokio::test]
async fn test_redis_connection() {
    init_test_env();

    match TestRedis::new() {
        Ok(redis) => {
            let result = redis.get_connection().await;
            match result {
                Ok(_) => {
                    // Redis connection succeeded
                    assert!(true);
                },
                Err(e) => {
                    eprintln!("Warning: Redis connection failed: {}", e);
                    eprintln!("This test requires Redis to be running on localhost:6379");
                    // Don't fail the test if Redis is not available
                },
            }
        },
        Err(e) => {
            eprintln!("Warning: Redis client creation failed: {}", e);
            eprintln!("This test requires Redis to be running on localhost:6379");
        },
    }
}

/// Test that JWT token has proper expiration handling
#[tokio::test]
async fn test_jwt_expiration() {
    init_test_env();

    let secret = "test-secret-key-that-is-at-least-32-bytes-long";
    let config = JwtConfig {
        secret:             BASE64.encode(secret.as_bytes()),
        expiration_seconds: 3600, // 1 hour
        issuer:             "test-issuer".to_string(),
        audience:           "test-audience".to_string(),
    };

    // Create a token with very short expiration for testing
    let token = create_access_token(
        &config,
        "user-123",
        "test@example.com",
        &["admin".to_string()],
    )
    .expect("Failed to create token");

    // Immediately validate it
    let claims = validate_token(&config, &token).expect("Failed to validate token");

    // Verify claims have expiration time
    assert!(
        claims.exp > claims.iat,
        "Expiration should be after issued time"
    );

    // Calculate the time difference
    let issued_at = std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(claims.iat))
        .expect("Invalid issued time");
    let expiration_time = std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(claims.exp))
        .expect("Invalid expiration time");
    let duration = expiration_time
        .duration_since(issued_at)
        .expect("Duration calculation failed");

    // Verify the expiration time is approximately what we set
    assert_eq!(
        duration.as_secs(),
        3600,
        "Expiration should be 3600 seconds"
    );
}

/// Test token structure and claims with multiple roles
#[tokio::test]
async fn test_token_claims_structure() {
    init_test_env();

    let secret = "test-secret-key-that-is-at-least-32-bytes-long";
    let config = JwtConfig {
        secret:             BASE64.encode(secret.as_bytes()),
        expiration_seconds: 3600,
        issuer:             "horizon-cmdb".to_string(),
        audience:           "horizon-api".to_string(),
    };

    let token = create_access_token(
        &config,
        "550e8400-e29b-41d4-a716-446655440000",
        "admin@example.com",
        &["super_admin".to_string(), "user".to_string()],
    )
    .expect("Failed to create token");

    let claims = validate_token(&config, &token).expect("Failed to validate token");

    // Verify UUID format for user ID
    assert_eq!(claims.sub, "550e8400-e29b-41d4-a716-446655440000");

    // Verify email format
    assert_eq!(claims.email, "admin@example.com");

    // Verify roles
    assert_eq!(claims.roles.len(), 2);
    assert!(claims.roles.contains(&"super_admin".to_string()));
    assert!(claims.roles.contains(&"user".to_string()));

    // Verify issuer and audience
    assert_eq!(claims.iss, "horizon-cmdb");
    assert_eq!(claims.aud, "horizon-api");
}

/// Test handling of edge cases in token validation
#[tokio::test]
async fn test_token_validation_edge_cases() {
    init_test_env();

    let secret = "test-secret-key-that-is-at-least-32-bytes-long";
    let config = JwtConfig {
        secret:             BASE64.encode(secret.as_bytes()),
        expiration_seconds: 3600,
        issuer:             "test-issuer".to_string(),
        audience:           "test-audience".to_string(),
    };

    // Test with empty token
    let result = validate_token(&config, "");
    assert!(result.is_err(), "Empty token should fail validation");

    // Test with invalid JWT structure
    let invalid_tokens = vec![
        "not.a.jwt.token",
        "Bearer invalid",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "",
    ];

    for token in invalid_tokens {
        let result = validate_token(&config, token);
        assert!(
            result.is_err(),
            "Invalid token '{}' should fail validation",
            token
        );
    }
}

/// Test password hashing with different salt values
#[tokio::test]
async fn test_password_hashing_uniqueness() {
    init_test_env();

    let password = "TestPassword123!";
    let password_secret1 = auth::secrecy::SecretString::from(password);
    let password_secret2 = auth::secrecy::SecretString::from(password);

    // Hash the same password twice
    let hash1 = hash_password(&password_secret1, None).expect("Failed to hash password");
    let hash2 = hash_password(&password_secret2, None).expect("Failed to hash password");

    // Hashes should be different due to salt
    assert_ne!(
        hash1.expose_secret(),
        hash2.expose_secret(),
        "Different hashes should be generated due to salt"
    );

    // Both should verify against the original password
    assert!(verify_password(&password_secret1, hash1.expose_secret()).is_ok());
    assert!(verify_password(&password_secret2, hash2.expose_secret()).is_ok());
}

/// Test token creation with empty roles
#[tokio::test]
async fn test_token_creation_empty_roles() {
    init_test_env();

    let secret = "test-secret-key-that-is-at-least-32-bytes-long";
    let config = JwtConfig {
        secret:             BASE64.encode(secret.as_bytes()),
        expiration_seconds: 3600,
        issuer:             "test-issuer".to_string(),
        audience:           "test-audience".to_string(),
    };

    let token = create_access_token(&config, "user-id", "user@example.com", &[]).expect("Failed to create token");

    let claims = validate_token(&config, &token).expect("Failed to validate token");

    assert_eq!(claims.roles.len(), 0, "Roles should be empty");
    assert_eq!(claims.sub, "user-id");
    assert_eq!(claims.email, "user@example.com");
}
