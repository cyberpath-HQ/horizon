//! # Refresh Token Service
//!
//! Handles storage, retrieval, and management of JWT refresh tokens.

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sea_orm::{prelude::*, Set};

use crate::AppError;

/// Refresh token model for database operations
#[derive(Debug, Clone)]
pub struct RefreshToken {
    /// Database ID
    pub id:         i32,
    /// User ID this token belongs to
    pub user_id:    uuid::Uuid,
    /// Hashed token value
    pub token_hash: String,
    /// When this token expires
    pub expires_at: DateTime<Utc>,
    /// When this token was revoked (soft delete)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Creates a new refresh token for a user
///
/// # Arguments
///
/// * `db` - Database connection
/// * `user_id` - The user ID
/// * `token_value` - The raw token value to hash and store
/// * `expires_in_seconds` - How long until the token expires
///
/// # Errors
///
/// Returns an error if database operations fail.
pub async fn create_refresh_token(
    db: &sea_orm::DbConn,
    user_id: uuid::Uuid,
    token_value: &str,
    expires_in_seconds: u64,
) -> crate::Result<RefreshToken> {
    // Hash the token using BLAKE3
    let token_hash = blake3::hash(token_value.as_bytes()).to_hex().to_string();

    // Calculate expiration time
    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in_seconds as i64);

    // Create the active model
    // Note: created_at and updated_at are automatically managed by database defaults
    let active_model = entity::refresh_tokens::ActiveModel {
        user_id: Set(user_id),
        token_hash: Set(token_hash.clone()),
        expires_at: Set(expires_at.naive_utc()),
        revoked_at: Set(None),
        ..Default::default()
    };

    // Insert into database
    let model = active_model
        .insert(db)
        .await
        .map_err(|e| AppError::database(format!("Failed to create refresh token: {}", e)))?;

    Ok(RefreshToken {
        id: model.id,
        user_id: model.user_id,
        token_hash,
        expires_at,
        revoked_at: None,
        created_at: model.created_at.and_utc(),
        updated_at: model.updated_at.and_utc(),
    })
}

/// Validates a refresh token and returns the associated user ID
///
/// # Arguments
///
/// * `db` - Database connection
/// * `token_value` - The raw token value to validate
///
/// # Errors
///
/// Returns an error if the token is invalid, expired, or revoked.
pub async fn validate_refresh_token(db: &sea_orm::DbConn, token_value: &str) -> crate::Result<uuid::Uuid> {
    // Hash the token to compare with stored hash
    let token_hash = blake3::hash(token_value.as_bytes()).to_hex().to_string();

    // Find the token in the database
    let token_model = entity::refresh_tokens::Entity::find()
        .filter(entity::refresh_tokens::Column::TokenHash.eq(token_hash))
        .filter(entity::refresh_tokens::Column::RevokedAt.is_null())
        .one(db)
        .await
        .map_err(|e| AppError::database(format!("Failed to query refresh token: {}", e)))?
        .ok_or_else(|| AppError::auth("Invalid refresh token".to_string()))?;

    // Check if token is expired
    let now = Utc::now().naive_utc();
    if token_model.expires_at < now {
        return Err(AppError::auth("Refresh token has expired".to_string()));
    }

    Ok(token_model.user_id)
}

/// Revokes a refresh token (marks as revoked)
///
/// # Arguments
///
/// * `db` - Database connection
/// * `token_value` - The raw token value to revoke
///
/// # Errors
///
/// Returns an error if database operations fail.
pub async fn revoke_refresh_token(db: &sea_orm::DbConn, token_value: &str) -> crate::Result<()> {
    // Hash the token to find it
    let token_hash = blake3::hash(token_value.as_bytes()).to_hex().to_string();

    // Update the token to mark it as revoked
    let update_result = entity::refresh_tokens::Entity::update_many()
        .col_expr(
            entity::refresh_tokens::Column::RevokedAt,
            Expr::value(Some(Utc::now().naive_utc())),
        )
        .col_expr(
            entity::refresh_tokens::Column::UpdatedAt,
            Expr::value(Utc::now().naive_utc()),
        )
        .filter(entity::refresh_tokens::Column::TokenHash.eq(token_hash))
        .exec(db)
        .await
        .map_err(|e| AppError::database(format!("Failed to revoke refresh token: {}", e)))?;

    if update_result.rows_affected == 0 {
        return Err(AppError::auth("Refresh token not found".to_string()));
    }

    Ok(())
}

/// Revokes all refresh tokens for a user
///
/// # Arguments
///
/// * `db` - Database connection
/// * `user_id` - The user ID whose tokens should be revoked
///
/// # Errors
///
/// Returns an error if database operations fail.
pub async fn revoke_all_user_tokens(db: &sea_orm::DbConn, user_id: uuid::Uuid) -> crate::Result<()> {
    entity::refresh_tokens::Entity::update_many()
        .col_expr(
            entity::refresh_tokens::Column::RevokedAt,
            Expr::value(Some(Utc::now().naive_utc())),
        )
        .col_expr(
            entity::refresh_tokens::Column::UpdatedAt,
            Expr::value(Utc::now().naive_utc()),
        )
        .filter(entity::refresh_tokens::Column::UserId.eq(user_id))
        .filter(entity::refresh_tokens::Column::RevokedAt.is_null())
        .exec(db)
        .await
        .map_err(|e| AppError::database(format!("Failed to revoke user tokens: {}", e)))?;

    Ok(())
}

/// Cleans up expired refresh tokens
///
/// # Arguments
///
/// * `db` - Database connection
///
/// # Errors
///
/// Returns an error if database operations fail.
pub async fn cleanup_expired_tokens(db: &sea_orm::DbConn) -> crate::Result<u64> {
    let now = Utc::now().naive_utc();

    let delete_result = entity::refresh_tokens::Entity::delete_many()
        .filter(entity::refresh_tokens::Column::ExpiresAt.lt(now))
        .exec(db)
        .await
        .map_err(|e| AppError::database(format!("Failed to cleanup expired tokens: {}", e)))?;

    Ok(delete_result.rows_affected)
}

/// Generates a secure random refresh token value
///
/// # Returns
///
/// A URL-safe base64-encoded random string suitable for use as a refresh token.
pub fn generate_refresh_token() -> String {
    // Generate 32 bytes of random data (256 bits)
    let random_bytes = rand::random::<[u8; 32]>();
    // Encode as URL-safe base64
    general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
}

#[cfg(test)]
mod tests {
    use sea_orm::{Database, DatabaseConnection};

    use super::*;

    async fn setup_test_db() -> DatabaseConnection {
        // Use SQLite for tests
        Database::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to test database")
    }

    #[tokio::test]
    async fn test_generate_refresh_token() {
        let token1 = generate_refresh_token();
        let token2 = generate_refresh_token();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Token should be URL-safe base64 (no padding, URL-safe chars)
        assert!(token1
            .chars()
            .all(|c| { c.is_alphanumeric() || c == '-' || c == '_' }));

        // Should be 43 characters (32 bytes base64 encoded without padding)
        assert_eq!(token1.len(), 43);
    }

    #[tokio::test]
    async fn test_refresh_token_hashing() {
        let token_value = "test-token-value";
        let hash1 = blake3::hash(token_value.as_bytes()).to_hex().to_string();
        let hash2 = blake3::hash(token_value.as_bytes()).to_hex().to_string();

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (32 bytes hex encoded)
        assert_eq!(hash1.len(), 64);
    }
}
