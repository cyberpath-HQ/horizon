//! # API Key Handlers
//!
//! HTTP request handlers for API key management endpoints including
//! creation, listing, rotation, revocation, permission management, and usage stats.

use axum::Json;
use chrono::Utc;
use entity::{
    api_key_usage_log::{Column as UsageColumn, Entity as UsageEntity},
    api_keys::{Column as KeyColumn, Entity as ApiKeysEntity},
    users::Entity as UsersEntity,
};
use error::{AppError, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use tracing::info;
use validator::Validate;

use crate::{
    dto::{
        api_keys::{
            ApiKeyDetail,
            ApiKeyListQuery,
            ApiKeyListResponse,
            ApiKeyUsageEntry,
            ApiKeyUsageResponse,
            ApiKeyUsageStats,
            CreateApiKeyRequest,
            CreateApiKeyResponse,
            RotateApiKeyResponse,
            UpdateApiKeyPermissionsRequest,
        },
        auth::SuccessResponse,
        users::PaginationInfo,
    },
    middleware::auth::AuthenticatedUser,
    utils::escape_like_wildcards,
    AppState,
};

/// Maximum allowed expiration time in seconds (100 years)
/// This prevents integer overflow and excessive memory allocation
const MAX_EXPIRATION_SECONDS: u64 = 100 * 365 * 24 * 60 * 60;

/// Length of the raw API key in bytes (before hex encoding)
const API_KEY_BYTES: usize = 32;

/// Prefix length for display purposes
const API_KEY_PREFIX_LEN: usize = 8;

/// API key string prefix
const API_KEY_PREFIX: &str = "hzn_";

/// Create a new API key for the authenticated user
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - Create API key request
///
/// # Returns
///
/// The created API key with the full key value (shown only once)
pub async fn create_api_key_handler(
    state: &AppState,
    user: AuthenticatedUser,
    req: CreateApiKeyRequest,
) -> Result<Json<CreateApiKeyResponse>> {
    // Validate the request first
    req.validate()?;

    // Generate a cryptographically random API key
    let raw_key = generate_api_key();
    let key_hash = hash_api_key(&raw_key);
    let key_prefix = raw_key[.. API_KEY_PREFIX_LEN.min(raw_key.len())].to_string();

    let permissions = req.permissions.unwrap_or(serde_json::json!({}));

    // Safely calculate expiration time with overflow protection
    let expires_at = req.expires_in_seconds.map(|secs| {
        // Validate that secs is within safe bounds
        let safe_secs = if secs > MAX_EXPIRATION_SECONDS {
            tracing::warn!(
                user_id = %user.id,
                requested_secs = secs,
                max_secs = MAX_EXPIRATION_SECONDS,
                "Expiration time exceeds maximum, using maximum allowed"
            );
            MAX_EXPIRATION_SECONDS
        }
        else {
            secs
        };

        // Convert to i64 safely (we've validated it's within bounds)
        let i64_secs = safe_secs as i64;
        let duration = chrono::Duration::seconds(i64_secs);
        (Utc::now() + duration).naive_utc()
    });

    let now = Utc::now().naive_utc();
    let api_key = entity::api_keys::ActiveModel {
        user_id: Set(user.id.clone()),
        name: Set(req.name.clone()),
        key_hash: Set(key_hash),
        key_prefix: Set(key_prefix.clone()),
        permissions: Set(permissions.clone()),
        expires_at: Set(expires_at),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let created = api_key
        .insert(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to create API key: {}", e)))?;

    info!(
        api_key_id = %created.id,
        user_id = %user.id,
        name = %req.name,
        "API key created"
    );

    Ok(Json(CreateApiKeyResponse {
        success: true,
        api_key: api_key_model_to_detail(&created),
        key:     raw_key,
    }))
}

/// List API keys for the authenticated user
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `query` - Query parameters for pagination and search
///
/// # Returns
///
/// Paginated API key list (without raw key values)
pub async fn list_api_keys_handler(
    state: &AppState,
    user: AuthenticatedUser,
    query: ApiKeyListQuery,
) -> Result<Json<ApiKeyListResponse>> {
    let page = query.page();
    let per_page = query.per_page();

    let mut base_query = ApiKeysEntity::find().filter(KeyColumn::UserId.eq(&user.id));

    if let Some(ref search) = query.search {
        let escaped_search = escape_like_wildcards(search);
        let pattern = format!("%{}%", escaped_search);
        base_query = base_query.filter(
            Condition::any()
                .add(KeyColumn::Name.like(&pattern))
                .add(KeyColumn::KeyPrefix.like(&pattern)),
        );
    }

    let total = base_query
        .clone()
        .count(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to count API keys: {}", e)))?;

    let total_pages = if total == 0 {
        0
    }
    else {
        total.div_ceil(per_page)
    };

    let keys = base_query
        .order_by_desc(KeyColumn::CreatedAt)
        .paginate(&state.db, per_page)
        .fetch_page(page.saturating_sub(1))
        .await
        .map_err(|e| AppError::database(format!("Failed to fetch API keys: {}", e)))?;

    let key_details: Vec<ApiKeyDetail> = keys.iter().map(api_key_model_to_detail).collect();

    Ok(Json(ApiKeyListResponse {
        success:    true,
        api_keys:   key_details,
        pagination: PaginationInfo {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get a single API key by ID
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `key_id` - API key ID
///
/// # Returns
///
/// API key detail (without raw key value)
pub async fn get_api_key_handler(
    state: &AppState,
    user: AuthenticatedUser,
    key_id: &str,
) -> Result<Json<ApiKeyDetail>> {
    let api_key = find_user_api_key(state, &user.id, key_id).await?;
    Ok(Json(api_key_model_to_detail(&api_key)))
}

/// Delete (revoke) an API key
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `key_id` - API key ID
///
/// # Returns
///
/// Success response
pub async fn delete_api_key_handler(
    state: &AppState,
    user: AuthenticatedUser,
    key_id: &str,
) -> Result<Json<SuccessResponse>> {
    let api_key = find_user_api_key(state, &user.id, key_id).await?;

    entity::api_keys::Entity::delete_by_id(&api_key.id)
        .exec(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to delete API key: {}", e)))?;

    info!(api_key_id = %key_id, user_id = %user.id, "API key revoked");

    Ok(Json(SuccessResponse {
        success: true,
        message: "API key revoked successfully".to_string(),
    }))
}

/// Rotate an API key (generates a new key, replaces the old one)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `key_id` - API key ID to rotate
///
/// # Returns
///
/// Rotated API key with the new raw key value (shown only once)
pub async fn rotate_api_key_handler(
    state: &AppState,
    user: AuthenticatedUser,
    key_id: &str,
) -> Result<Json<RotateApiKeyResponse>> {
    let api_key = find_user_api_key(state, &user.id, key_id).await?;

    // Generate a new key
    let new_raw_key = generate_api_key();
    let new_key_hash = hash_api_key(&new_raw_key);
    let new_key_prefix = new_raw_key[.. API_KEY_PREFIX_LEN.min(new_raw_key.len())].to_string();

    let mut active_model: entity::api_keys::ActiveModel = api_key.into();
    active_model.key_hash = Set(new_key_hash);
    active_model.key_prefix = Set(new_key_prefix);
    active_model.updated_at = Set(Utc::now().naive_utc());

    let updated = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to rotate API key: {}", e)))?;

    info!(api_key_id = %key_id, user_id = %user.id, "API key rotated");

    Ok(Json(RotateApiKeyResponse {
        success: true,
        api_key: api_key_model_to_detail(&updated),
        key:     new_raw_key,
    }))
}

/// Update API key permissions
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `key_id` - API key ID
/// * `req` - Permissions update request
///
/// # Returns
///
/// Updated API key detail
pub async fn update_api_key_permissions_handler(
    state: &AppState,
    user: AuthenticatedUser,
    key_id: &str,
    req: UpdateApiKeyPermissionsRequest,
) -> Result<Json<ApiKeyDetail>> {
    let api_key = find_user_api_key(state, &user.id, key_id).await?;

    let mut active_model: entity::api_keys::ActiveModel = api_key.into();
    active_model.permissions = Set(req.permissions);
    active_model.updated_at = Set(Utc::now().naive_utc());

    let updated = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update API key permissions: {}", e)))?;

    info!(api_key_id = %key_id, user_id = %user.id, "API key permissions updated");

    Ok(Json(api_key_model_to_detail(&updated)))
}

/// Get usage statistics for an API key
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `key_id` - API key ID
///
/// # Returns
///
/// Usage statistics response
pub async fn get_api_key_usage_handler(
    state: &AppState,
    user: AuthenticatedUser,
    key_id: &str,
) -> Result<Json<ApiKeyUsageResponse>> {
    let _ = find_user_api_key(state, &user.id, key_id).await?;

    let now = Utc::now();
    let _now_tz = now.with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());
    let day_ago = (now - chrono::Duration::hours(24)).with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());
    let week_ago = (now - chrono::Duration::days(7)).with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());

    // Total requests
    let total_requests = UsageEntity::find()
        .filter(UsageColumn::ApiKeyId.eq(key_id))
        .count(&state.db)
        .await
        .unwrap_or(0);

    // Requests last 24h
    let requests_last_24h = UsageEntity::find()
        .filter(UsageColumn::ApiKeyId.eq(key_id))
        .filter(UsageColumn::CreatedAt.gte(day_ago))
        .count(&state.db)
        .await
        .unwrap_or(0);

    // Requests last 7 days
    let requests_last_7d = UsageEntity::find()
        .filter(UsageColumn::ApiKeyId.eq(key_id))
        .filter(UsageColumn::CreatedAt.gte(week_ago))
        .count(&state.db)
        .await
        .unwrap_or(0);

    // Recent usage entries (last 50)
    let recent = UsageEntity::find()
        .filter(UsageColumn::ApiKeyId.eq(key_id))
        .order_by_desc(UsageColumn::CreatedAt)
        .paginate(&state.db, 50)
        .fetch_page(0)
        .await
        .unwrap_or_default();

    let recent_usage: Vec<ApiKeyUsageEntry> = recent
        .into_iter()
        .map(|entry| {
            ApiKeyUsageEntry {
                endpoint:    entry.endpoint,
                method:      entry.method,
                status_code: entry.status_code,
                ip_address:  entry.ip_address,
                created_at:  entry.created_at.to_string(),
            }
        })
        .collect();

    Ok(Json(ApiKeyUsageResponse {
        success: true,
        usage:   ApiKeyUsageStats {
            total_requests,
            requests_last_24h,
            requests_last_7d,
            recent_usage,
        },
    }))
}

/// Log API key usage to the audit log
///
/// # Arguments
///
/// * `state` - Application state
/// * `api_key_id` - The API key ID
/// * `endpoint` - The endpoint accessed
/// * `method` - The HTTP method
/// * `ip_address` - The client IP address
/// * `user_agent` - The client user agent
/// * `status_code` - The HTTP response status code
pub async fn log_api_key_usage(
    state: &AppState,
    api_key_id: &str,
    endpoint: &str,
    method: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    status_code: i16,
) -> Result<()> {
    let now = Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());

    let log_entry = entity::api_key_usage_log::ActiveModel {
        api_key_id: Set(api_key_id.to_string()),
        endpoint: Set(endpoint.to_string()),
        method: Set(method.to_string()),
        ip_address: Set(ip_address.map(|s| s.to_string())),
        user_agent: Set(user_agent.map(|s| s.to_string())),
        status_code: Set(status_code),
        created_at: Set(now),
        ..Default::default()
    };

    log_entry
        .insert(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to log API key usage: {}", e)))?;

    // Also update last_used_at on the API key itself
    if let Ok(Some(key)) = ApiKeysEntity::find_by_id(api_key_id).one(&state.db).await {
        let mut active_model: entity::api_keys::ActiveModel = key.into();
        active_model.last_used_at = Set(Some(Utc::now().naive_utc()));
        active_model.last_used_ip = Set(ip_address.map(|s| s.to_string()));
        active_model.updated_at = Set(Utc::now().naive_utc());
        let _ = active_model.update(&state.db).await;
    }

    Ok(())
}

/// Generate a cryptographically random API key
///
/// # Returns
///
/// A hex-encoded API key string with "hzn_" prefix
fn generate_api_key() -> String {
    use rand::RngCore;
    let mut buf = [0u8; API_KEY_BYTES];
    rand::rng().fill_bytes(&mut buf);
    let hex_str: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}{}", API_KEY_PREFIX, hex_str)
}

/// Hash an API key using BLAKE3 for storage
///
/// # Arguments
///
/// * `key` - The raw API key string
///
/// # Returns
///
/// The BLAKE3 hash as a hex string
pub fn hash_api_key(key: &str) -> String { blake3::hash(key.as_bytes()).to_hex().to_string() }

/// Find an API key belonging to a specific user
///
/// # Arguments
///
/// * `state` - Application state
/// * `user_id` - The user ID
/// * `key_id` - The API key ID
///
/// # Returns
///
/// The API key model
async fn find_user_api_key(state: &AppState, user_id: &str, key_id: &str) -> Result<entity::api_keys::Model> {
    let api_key = ApiKeysEntity::find_by_id(key_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("API key not found"))?;

    if api_key.user_id != user_id {
        return Err(AppError::not_found("API key not found"));
    }

    Ok(api_key)
}

/// Authenticate a request using an API key
///
/// Looks up the API key by prefix, then verifies the full hash.
/// Also checks that the key is not expired and the user is active.
///
/// # Arguments
///
/// * `state` - Application state
/// * `raw_key` - The raw API key from the X-API-Key header
///
/// # Returns
///
/// A tuple of (api_key_model, user_model) if authentication succeeds
pub async fn authenticate_api_key(
    state: &AppState,
    raw_key: &str,
) -> Result<(entity::api_keys::Model, entity::users::Model)> {
    let key_hash = hash_api_key(raw_key);

    // Find the API key by hash
    let api_key = ApiKeysEntity::find()
        .filter(KeyColumn::KeyHash.eq(&key_hash))
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::unauthorized("Invalid API key"))?;

    // Check expiration
    if let Some(expires_at) = api_key.expires_at &&
        expires_at < Utc::now().naive_utc()
    {
        return Err(AppError::unauthorized("API key has expired"));
    }

    // Load the associated user
    let user = UsersEntity::find_by_id(&api_key.user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::unauthorized("User associated with API key not found"))?;

    // Verify the user account is active
    if user.status != entity::sea_orm_active_enums::UserStatus::Active {
        return Err(AppError::unauthorized(
            "User account associated with this API key is not active",
        ));
    }

    Ok((api_key, user))
}

/// Check if an API key has the required permissions for an endpoint
///
/// Permissions JSON format:
/// ```json
/// {
///   "endpoints": ["*"] or ["/api/v1/specific/*"],
///   "methods": ["*"] or ["GET", "POST"],
///   "scopes": ["read", "write", "admin"]
/// }
/// ```
///
/// If `endpoints` is `["*"]` or missing, all endpoints are allowed.
/// If `methods` is `["*"]` or missing, all methods are allowed.
///
/// # Arguments
///
/// * `permissions` - The API key's permissions JSON
/// * `endpoint` - The request endpoint path
/// * `method` - The HTTP method
///
/// # Returns
///
/// `true` if the API key has permission for the endpoint and method
pub fn check_api_key_permissions(permissions: &serde_json::Value, endpoint: &str, method: &str) -> bool {
    // Check endpoint permissions
    if let Some(endpoints) = permissions.get("endpoints").and_then(|v| v.as_array()) {
        let endpoint_allowed = endpoints.iter().any(|e| {
            if let Some(pattern) = e.as_str() {
                if pattern == "*" {
                    return true;
                }
                // Support glob-like matching with trailing *
                if let Some(prefix) = pattern.strip_suffix('*') {
                    return endpoint.starts_with(prefix);
                }
                pattern == endpoint
            }
            else {
                false
            }
        });
        if !endpoint_allowed {
            return false;
        }
    }
    // No `endpoints` key = all endpoints allowed

    // Check method permissions
    if let Some(methods) = permissions.get("methods").and_then(|v| v.as_array()) {
        let method_allowed = methods.iter().any(|m| {
            if let Some(m_str) = m.as_str() {
                m_str == "*" || m_str.eq_ignore_ascii_case(method)
            }
            else {
                false
            }
        });
        if !method_allowed {
            return false;
        }
    }
    // No `methods` key = all methods allowed

    // Block user management endpoints unless explicitly granted
    if is_user_management_endpoint(endpoint) {
        let has_admin_scope = permissions
            .get("scopes")
            .and_then(|v| v.as_array())
            .map(|scopes| {
                scopes
                    .iter()
                    .any(|s| s.as_str() == Some("admin") || s.as_str() == Some("user_management"))
            })
            .unwrap_or(false);
        if !has_admin_scope {
            return false;
        }
    }

    true
}

/// Check if an endpoint is a user management endpoint
///
/// These endpoints require explicit `admin` or `user_management` scope.
///
/// # Arguments
///
/// * `endpoint` - The request endpoint path
///
/// # Returns
///
/// `true` if the endpoint is a user management endpoint
fn is_user_management_endpoint(endpoint: &str) -> bool {
    let protected_patterns = ["/api/v1/users", "/api/v1/teams", "/api/v1/auth/api-keys"];
    protected_patterns.iter().any(|p| endpoint.starts_with(p))
}

/// Convert an API key model to a detail response DTO
fn api_key_model_to_detail(key: &entity::api_keys::Model) -> ApiKeyDetail {
    ApiKeyDetail {
        id:           key.id.clone(),
        name:         key.name.clone(),
        key_prefix:   key.key_prefix.clone(),
        permissions:  key.permissions.clone(),
        expires_at:   key.expires_at.map(|dt| dt.to_string()),
        last_used_at: key.last_used_at.map(|dt| dt.to_string()),
        last_used_ip: key.last_used_ip.clone(),
        created_at:   key.created_at.to_string(),
        user_id:      key.user_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== API Key Generation Tests ====================

    #[test]
    fn test_generate_api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with(API_KEY_PREFIX));
        // hzn_ + 64 hex chars (32 bytes * 2)
        assert_eq!(key.len(), API_KEY_PREFIX.len() + API_KEY_BYTES * 2);
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_api_key_randomness() {
        let keys: Vec<String> = (0 .. 100).map(|_| generate_api_key()).collect();
        let unique_keys: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(
            unique_keys.len(),
            100,
            "All generated keys should be unique"
        );
    }

    #[test]
    fn test_generate_api_key_hex_encoding() {
        let key = generate_api_key();
        let hex_part = &key[API_KEY_PREFIX.len() ..];
        for ch in hex_part.chars() {
            assert!(
                ch.is_ascii_hexdigit(),
                "Key should only contain hex digits after prefix"
            );
        }
    }

    // ==================== API Key Hashing Tests ====================

    #[test]
    fn test_hash_api_key_deterministic() {
        let key = "hzn_abcdef1234567890";
        let hash1 = hash_api_key(key);
        let hash2 = hash_api_key(key);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_api_key_different_inputs() {
        let hash1 = hash_api_key("key_a");
        let hash2 = hash_api_key("key_b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_api_key_not_reversible() {
        let key = "hzn_secret_key_123";
        let hash = hash_api_key(key);
        assert_ne!(hash, key);
        assert!(!key.contains(&hash)); // Original key should not be in hash
    }

    #[test]
    fn test_hash_api_key_length() {
        let key = generate_api_key();
        let hash = hash_api_key(&key);
        // BLAKE3 produces 256-bit hash, hex-encoded = 64 chars
        assert_eq!(hash.len(), 64);
    }

    // ==================== Permission Checking Tests ====================

    #[test]
    fn test_check_permissions_all_allowed() {
        let perms = serde_json::json!({});
        assert!(check_api_key_permissions(&perms, "/api/v1/anything", "GET"));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/anything",
            "POST"
        ));
    }

    #[test]
    fn test_check_permissions_wildcard_endpoints() {
        let perms = serde_json::json!({"endpoints": ["*"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/anything", "GET"));
        assert!(check_api_key_permissions(&perms, "/health", "GET"));
        assert!(check_api_key_permissions(&perms, "/", "DELETE"));
    }

    #[test]
    fn test_check_permissions_specific_endpoint_exact_match() {
        let perms = serde_json::json!({"endpoints": ["/api/v1/health"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "GET"));
        assert!(!check_api_key_permissions(&perms, "/api/v1/health/", "GET"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/health/detail",
            "GET"
        ));
    }

    #[test]
    fn test_check_permissions_endpoint_glob() {
        let perms = serde_json::json!({"endpoints": ["/api/v1/assets/*"]});
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/assets/123",
            "GET"
        ));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/assets/123/detail",
            "GET"
        ));
        assert!(!check_api_key_permissions(&perms, "/api/v1/other", "GET"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v2/assets/123",
            "GET"
        ));
    }

    #[test]
    fn test_check_permissions_multiple_endpoint_patterns() {
        // Note: endpoints under /api/v1/users, /api/v1/teams, /api/v1/auth/api-keys require admin scope
        let perms = serde_json::json!({
            "endpoints": ["/api/v1/health", "/api/v1/assets/*"],
            "scopes": ["admin"]
        });
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "GET"));
        assert!(check_api_key_permissions(&perms, "/api/v1/assets/1", "GET"));
        assert!(!check_api_key_permissions(&perms, "/api/v1/other", "GET"));
    }

    #[test]
    fn test_check_permissions_method_restricted() {
        let perms = serde_json::json!({"methods": ["GET"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "GET"));
        assert!(!check_api_key_permissions(&perms, "/api/v1/health", "POST"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/health",
            "DELETE"
        ));
    }

    #[test]
    fn test_check_permissions_multiple_methods() {
        let perms = serde_json::json!({"methods": ["GET", "POST"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "GET"));
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "POST"));
        assert!(!check_api_key_permissions(&perms, "/api/v1/health", "PUT"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/health",
            "DELETE"
        ));
    }

    #[test]
    fn test_check_permissions_method_wildcard() {
        let perms = serde_json::json!({"methods": ["*"]});
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/health",
            "DELETE"
        ));
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "PUT"));
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "PATCH"));
    }

    #[test]
    fn test_check_permissions_case_insensitive_method() {
        let perms = serde_json::json!({"methods": ["GET", "POST"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "get"));
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "Get"));
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "POST"));
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "post"));
    }

    #[test]
    fn test_check_permissions_user_management_blocked_no_scope() {
        // User management endpoints require admin/user_management scope
        let perms = serde_json::json!({});
        assert!(!check_api_key_permissions(&perms, "/api/v1/users", "GET"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/users/me",
            "GET"
        ));
        assert!(!check_api_key_permissions(&perms, "/api/v1/teams", "GET"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/teams/123/members",
            "POST"
        ));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/auth/api-keys",
            "POST"
        ));
    }

    #[test]
    fn test_check_permissions_user_management_blocked_with_other_scope() {
        let perms = serde_json::json!({"scopes": ["read", "write"]});
        assert!(!check_api_key_permissions(&perms, "/api/v1/users", "GET"));
        assert!(!check_api_key_permissions(&perms, "/api/v1/teams", "POST"));
    }

    #[test]
    fn test_check_permissions_user_management_with_admin_scope() {
        let perms = serde_json::json!({"scopes": ["admin"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/users", "GET"));
        assert!(check_api_key_permissions(&perms, "/api/v1/users/me", "GET"));
        assert!(check_api_key_permissions(&perms, "/api/v1/teams", "POST"));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/teams/123/members",
            "DELETE"
        ));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/auth/api-keys",
            "CREATE"
        ));
    }

    #[test]
    fn test_check_permissions_user_management_with_specific_scope() {
        let perms = serde_json::json!({"scopes": ["user_management"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/users", "GET"));
        assert!(check_api_key_permissions(&perms, "/api/v1/teams", "POST"));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/auth/api-keys",
            "DELETE"
        ));
    }

    #[test]
    fn test_check_permissions_combined_restrictions() {
        let perms = serde_json::json!({
            "endpoints": ["/api/v1/assets/*"],
            "methods": ["GET", "POST"]
        });
        assert!(check_api_key_permissions(&perms, "/api/v1/assets/1", "GET"));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/assets/1",
            "POST"
        ));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/assets/1",
            "DELETE"
        ));
        assert!(!check_api_key_permissions(&perms, "/api/v1/other", "GET"));
    }

    #[test]
    fn test_check_permissions_endpoint_with_trailing_wildcard_variations() {
        // Note: /api/v1/teams and /api/v1/users are protected endpoints
        let perms = serde_json::json!({"endpoints": ["/api/v1/*"], "scopes": ["admin"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/assets", "GET"));
        assert!(check_api_key_permissions(&perms, "/api/v1/assets/1", "GET"));
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/teams/1/members",
            "GET"
        ));
        assert!(!check_api_key_permissions(&perms, "/api/v2/assets", "GET"));
        assert!(!check_api_key_permissions(&perms, "/health", "GET"));
    }

    #[test]
    fn test_check_permissions_empty_arrays() {
        let perms = serde_json::json!({"endpoints": [], "methods": []});
        // Empty arrays should not match anything
        assert!(!check_api_key_permissions(&perms, "/api/v1/health", "GET"));
    }

    #[test]
    fn test_check_permissions_invalid_json_structure() {
        // Non-array values should be ignored
        let perms = serde_json::json!({
            "endpoints": "not_an_array",
            "methods": 123
        });
        // Should default to allowing everything
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "GET"));
    }

    // ==================== User Management Endpoint Detection Tests ====================

    #[test]
    fn test_is_user_management_endpoint_users() {
        assert!(is_user_management_endpoint("/api/v1/users"));
        assert!(is_user_management_endpoint("/api/v1/users/"));
        assert!(is_user_management_endpoint("/api/v1/users/me"));
        assert!(is_user_management_endpoint("/api/v1/users/123"));
        assert!(is_user_management_endpoint("/api/v1/users/123/profile"));
    }

    #[test]
    fn test_is_user_management_endpoint_teams() {
        assert!(is_user_management_endpoint("/api/v1/teams"));
        assert!(is_user_management_endpoint("/api/v1/teams/"));
        assert!(is_user_management_endpoint("/api/v1/teams/123"));
        assert!(is_user_management_endpoint("/api/v1/teams/123/members"));
    }

    #[test]
    fn test_is_user_management_endpoint_api_keys() {
        assert!(is_user_management_endpoint("/api/v1/auth/api-keys"));
        assert!(is_user_management_endpoint("/api/v1/auth/api-keys/"));
        assert!(is_user_management_endpoint("/api/v1/auth/api-keys/rotate"));
    }

    #[test]
    fn test_is_user_management_endpoint_false() {
        assert!(!is_user_management_endpoint("/api/v1/health"));
        assert!(!is_user_management_endpoint("/api/v1/assets"));
        assert!(!is_user_management_endpoint("/api/v1/assets/123"));
        assert!(!is_user_management_endpoint("/api/v1/incidents"));
        assert!(!is_user_management_endpoint("/health"));
        assert!(!is_user_management_endpoint("/"));
    }

    #[test]
    fn test_is_user_management_endpoint_similar_names() {
        // These should match because they start with the protected patterns
        assert!(is_user_management_endpoint("/api/v1/users_content"));
        assert!(is_user_management_endpoint("/api/v1/teams_admin"));
    }

    // ==================== API Key Model to Detail Conversion Tests ====================

    #[test]
    fn test_api_key_model_to_detail_full() {
        let now = chrono::NaiveDateTime::default();
        let model = entity::api_keys::Model {
            id:           "ak_test".to_string(),
            user_id:      "usr_test".to_string(),
            name:         "test key".to_string(),
            key_hash:     "somehash".to_string(),
            key_prefix:   "hzn_abcd".to_string(),
            permissions:  serde_json::json!({"scopes": ["read"]}),
            expires_at:   Some(now),
            last_used_at: Some(now),
            last_used_ip: Some("192.168.1.1".to_string()),
            created_at:   now,
            updated_at:   now,
        };

        let detail = api_key_model_to_detail(&model);
        assert_eq!(detail.id, "ak_test");
        assert_eq!(detail.name, "test key");
        assert_eq!(detail.key_prefix, "hzn_abcd");
        assert_eq!(detail.user_id, "usr_test");
        assert!(detail.expires_at.is_some());
        assert!(detail.last_used_at.is_some());
        assert_eq!(detail.last_used_ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_api_key_model_to_detail_minimal() {
        let now = chrono::NaiveDateTime::default();
        let model = entity::api_keys::Model {
            id:           "ak_minimal".to_string(),
            user_id:      "usr_test".to_string(),
            name:         "minimal key".to_string(),
            key_hash:     "hash".to_string(),
            key_prefix:   "hzn_xyz".to_string(),
            permissions:  serde_json::json!({}),
            expires_at:   None,
            last_used_at: None,
            last_used_ip: None,
            created_at:   now,
            updated_at:   now,
        };

        let detail = api_key_model_to_detail(&model);
        assert_eq!(detail.id, "ak_minimal");
        assert!(detail.expires_at.is_none());
        assert!(detail.last_used_at.is_none());
        assert!(detail.last_used_ip.is_none());
    }

    // ==================== API Key List Query Tests ====================

    #[test]
    fn test_api_key_list_query_defaults() {
        let q = ApiKeyListQuery {
            page:     None,
            per_page: None,
            search:   None,
        };
        assert_eq!(q.page(), 1);
        assert_eq!(q.per_page(), 20);
        assert_eq!(q.search, None);
    }

    #[test]
    fn test_api_key_list_query_custom_values() {
        let q = ApiKeyListQuery {
            page:     Some(5),
            per_page: Some(50),
            search:   Some("test_key".to_string()),
        };
        assert_eq!(q.page(), 5);
        assert_eq!(q.per_page(), 50);
        assert_eq!(q.search, Some("test_key".to_string()));
    }

    #[test]
    fn test_api_key_list_query_page_clamp_minimum() {
        let q = ApiKeyListQuery {
            page:     Some(0),
            per_page: None,
            search:   None,
        };
        assert_eq!(q.page(), 1, "Page 0 should be clamped to 1");
    }

    #[test]
    fn test_api_key_list_query_per_page_clamp_maximum() {
        let q = ApiKeyListQuery {
            page:     None,
            per_page: Some(999),
            search:   None,
        };
        assert_eq!(q.per_page(), 100, "Per page 999 should be clamped to 100");
    }

    #[test]
    fn test_api_key_list_query_per_page_clamp_minimum() {
        let q = ApiKeyListQuery {
            page:     None,
            per_page: Some(1),
            search:   None,
        };
        assert_eq!(q.per_page(), 1, "Per page 1 should be allowed");
    }

    #[test]
    fn test_api_key_list_query_search_with_special_chars() {
        let q = ApiKeyListQuery {
            page:     None,
            per_page: None,
            search:   Some("test@#$%".to_string()),
        };
        assert_eq!(q.search, Some("test@#$%".to_string()));
    }

    // ==================== Edge Cases & Security Tests ====================

    #[test]
    fn test_permissions_endpoint_matching_precedence() {
        // More specific patterns should be checked, and protected endpoints need admin scope
        let perms = serde_json::json!({
            "endpoints": ["/api/v1/health", "/api/v1/assets/*"],
            "scopes": ["admin"]
        });

        // Exact match works for non-protected endpoint
        assert!(check_api_key_permissions(&perms, "/api/v1/health", "GET"));

        // Glob match works for non-protected endpoint
        assert!(check_api_key_permissions(
            &perms,
            "/api/v1/assets/123",
            "GET"
        ));

        // Unauthorized endpoint (not in permissions)
        assert!(!check_api_key_permissions(&perms, "/api/v1/teams", "GET"));
    }

    #[test]
    fn test_api_key_generation_sufficient_entropy() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();
        let key3 = generate_api_key();

        // Keys should be different (extremely unlikely to collide randomly)
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);

        // Should maintain 32 bytes of entropy
        let hex_part1 = &key1[API_KEY_PREFIX.len() ..];
        assert_eq!(hex_part1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_api_key_security_properties() {
        let key = generate_api_key();
        let hash1 = hash_api_key(&key);
        let hash2 = hash_api_key(&key);

        // Deterministic
        assert_eq!(hash1, hash2);

        // Not reversible (cryptographic property)
        assert_ne!(hash1, key);

        // Good distribution (even minor changes produce completely different hash)
        let modified_key = format!("{}X", key);
        let hash3 = hash_api_key(&modified_key);
        assert_ne!(
            hash1, hash3,
            "Different keys should produce different hashes"
        );
    }

    #[test]
    fn test_permissions_with_mixed_case_endpoint_path() {
        // Endpoint paths are case-sensitive
        let perms = serde_json::json!({"endpoints": ["/api/v1/Assets/*"]});
        assert!(check_api_key_permissions(&perms, "/api/v1/Assets/1", "GET"));
        assert!(!check_api_key_permissions(
            &perms,
            "/api/v1/assets/1",
            "GET"
        )); // Different case
    }

    // ==================== Expiration Validation Security Tests ====================

    #[test]
    fn test_create_api_key_request_normal_expiration() {
        // Normal expiration time (1 hour)
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: Some(3600),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_create_api_key_request_max_expiration() {
        // Maximum allowed expiration (100 years in seconds)
        let max_secs = 100 * 365 * 24 * 60 * 60;
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: Some(max_secs),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_create_api_key_request_expiration_too_large() {
        // Expiration exceeds maximum (100 years + 1 second)
        let max_secs_plus_one = 100 * 365 * 24 * 60 * 60 + 1;
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: Some(max_secs_plus_one),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_create_api_key_request_no_expiration() {
        // No expiration (key never expires)
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_create_api_key_request_min_expiration() {
        // Minimum expiration (1 second)
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: Some(1),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_create_api_key_request_expiration_zero() {
        // Zero expiration should be invalid
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: Some(0),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_max_expiration_constant() {
        // Verify the MAX_EXPIRATION_SECONDS constant is correct
        let expected = 100 * 365 * 24 * 60 * 60; // 100 years in seconds
        assert_eq!(MAX_EXPIRATION_SECONDS, expected);
    }

    #[test]
    fn test_create_api_key_request_expiration_very_large_value() {
        // Test with u64::MAX to ensure no overflow
        let req = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        None,
            expires_in_seconds: Some(u64::MAX),
        };
        // This should fail validation because it exceeds MAX_EXPIRATION_SECONDS
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_create_api_key_request_name_validation() {
        // Test name validation still works
        let req_empty_name = CreateApiKeyRequest {
            name:               "".to_string(),
            permissions:        None,
            expires_in_seconds: Some(3600),
        };
        assert!(req_empty_name.validate().is_err());

        let req_valid_name = CreateApiKeyRequest {
            name:               "Valid Name".to_string(),
            permissions:        None,
            expires_in_seconds: Some(3600),
        };
        assert!(req_valid_name.validate().is_ok());
    }

    #[test]
    fn test_create_api_key_request_combined_validation() {
        // Test that all validations work together
        let req_valid = CreateApiKeyRequest {
            name:               "Test Key".to_string(),
            permissions:        Some(serde_json::json!({"scopes": ["read"]})),
            expires_in_seconds: Some(86400), // 24 hours
        };
        assert!(req_valid.validate().is_ok());

        let req_invalid = CreateApiKeyRequest {
            name:               "".to_string(), // Invalid name
            permissions:        None,
            expires_in_seconds: Some(u64::MAX), // Invalid expiration
        };
        assert!(req_invalid.validate().is_err());
    }
}
