//! # API Router Configuration
//!
//! Configures API routes for the Horizon application.

use axum::{
    extract::{Extension, Path, Query, State},
    http::HeaderMap,
    middleware,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use error::Result;
use redis::AsyncCommands;
use tracing::error;

use crate::AppState;

/// Creates the API router with all routes
///
/// Combines public and protected routes with proper state management
/// and applies rate limiting and authentication middleware
pub fn create_router(state: AppState) -> Router {
    // Protected routes that require authentication
    let protected_routes = Router::new()
        // Auth session management
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/auth/refresh", post(refresh_handler))
        .route("/api/v1/auth/sessions", get(sessions_handler))
        .route("/api/v1/auth/sessions/{id}", delete(delete_session_handler))
        .route("/api/v1/auth/sessions", delete(delete_all_sessions_handler))
        // MFA endpoints
        .route("/api/v1/auth/mfa/enable", post(mfa_enable_handler))
        .route("/api/v1/auth/mfa/verify-setup", post(mfa_verify_setup_handler))
        .route("/api/v1/auth/mfa/disable", post(mfa_disable_handler))
        .route("/api/v1/auth/mfa/regenerate-backup-codes", post(mfa_regenerate_backup_codes_handler))
        .route("/api/v1/auth/mfa/status", get(mfa_status_handler))
        // User endpoints
        .route("/api/v1/users/me", get(get_my_profile_handler))
        .route("/api/v1/users/me", put(update_my_profile_handler))
        .route("/api/v1/users", get(list_users_handler))
        // Team endpoints
        .route("/api/v1/teams", post(create_team_handler))
        .route("/api/v1/teams", get(list_teams_handler))
        .route("/api/v1/teams/{id}", get(get_team_handler))
        .route("/api/v1/teams/{id}", put(update_team_handler))
        .route("/api/v1/teams/{id}", delete(delete_team_handler))
        .route("/api/v1/teams/{id}/members", get(list_team_members_handler))
        .route("/api/v1/teams/{id}/members", post(add_team_member_handler))
        .route("/api/v1/teams/{id}/members/{member_id}", put(update_team_member_handler))
        .route("/api/v1/teams/{id}/members/{member_id}", delete(remove_team_member_handler))
        // API key endpoints
        .route("/api/v1/auth/api-keys", post(create_api_key_handler))
        .route("/api/v1/auth/api-keys", get(list_api_keys_handler))
        .route("/api/v1/auth/api-keys/{id}", get(get_api_key_handler))
        .route("/api/v1/auth/api-keys/{id}", delete(delete_api_key_handler))
        .route("/api/v1/auth/api-keys/{id}/rotate", post(rotate_api_key_handler))
        .route("/api/v1/auth/api-keys/{id}/permissions", put(update_api_key_permissions_handler))
        .route("/api/v1/auth/api-keys/{id}/usage", get(get_api_key_usage_handler))
        // Layers execute bottom-up: auth (JWT) runs first, then api_key_auth
        .layer(middleware::from_fn(crate::middleware::api_key_auth::api_key_auth_middleware))
        .layer(middleware::from_fn(crate::middleware::auth::auth_middleware));

    // Public routes that don't require authentication
    let public_routes = Router::new()
        .route("/api/v1/auth/setup", post(setup_handler))
        .route("/api/v1/auth/login", post(login_handler))
        // MFA verification during login (uses mfa_token from login response, not session auth)
        .route("/api/v1/auth/mfa/verify", post(mfa_verify_login_handler))
        .route("/api/v1/auth/mfa/verify-backup", post(mfa_verify_backup_code_handler));

    // Health check route
    let health_route = Router::new().route("/health", get(health_check_handler));

    // Combine all routes
    let all_routes = public_routes
        .merge(protected_routes)
        .merge(health_route)
        .with_state(state);

    // Apply rate limiting to all routes
    all_routes.layer(middleware::from_fn(
        crate::middleware::rate_limit::rate_limit_middleware,
    ))
}

// ==================== AUTH HANDLERS ====================

/// Wrapper handler for setup endpoint that uses State extractor
async fn setup_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::dto::auth::SetupRequest>,
) -> Result<Json<crate::dto::auth::AuthSuccessResponse>> {
    crate::auth::handlers::setup_handler_inner(&state, req).await
}

/// Wrapper handler for login endpoint that uses State extractor
async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::auth::LoginRequest>,
) -> Result<Json<crate::dto::auth::AuthSuccessResponse>> {
    crate::auth::handlers::login_handler_inner(&state, req, headers).await
}

/// Wrapper handler for logout endpoint that uses State extractor
async fn logout_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::handlers::logout_handler_inner(&state, request).await
}

/// Wrapper handler for refresh endpoint that uses State extractor
async fn refresh_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::dto::auth::RefreshRequest>,
) -> Result<Json<crate::dto::auth::AuthSuccessResponse>> {
    crate::auth::handlers::refresh_handler_inner(&state, req).await
}

/// Wrapper handler for getting user sessions
async fn sessions_handler(
    State(state): State<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::auth::sessions::SessionsResponse>> {
    crate::auth::sessions::get_sessions_handler(&state, authenticated_user).await
}

/// Wrapper handler for deleting a specific session
async fn delete_session_handler(
    State(state): State<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(session_id): Path<String>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::sessions::delete_session_handler(&state, authenticated_user, Path(session_id)).await
}

/// Wrapper handler for deleting all user sessions (logout everywhere)
async fn delete_all_sessions_handler(
    State(state): State<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::sessions::delete_all_sessions_handler(&state, authenticated_user).await
}

// ==================== MFA HANDLERS ====================

/// Enable MFA for the authenticated user
async fn mfa_enable_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaEnableRequest>,
) -> Result<Json<crate::dto::mfa::MfaSetupResponse>> {
    crate::auth::mfa::mfa_enable_handler(&state, user, req).await
}

/// Verify TOTP code to finalize MFA setup
async fn mfa_verify_setup_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaVerifyRequest>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::mfa::mfa_verify_setup_handler(&state, user, req).await
}

/// Verify MFA during login (public endpoint, uses mfa_token)
async fn mfa_verify_login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::mfa::MfaVerifyRequest>,
) -> Result<Json<crate::dto::mfa::MfaVerifyResponse>> {
    let mfa_token = headers
        .get("authorization")
        .and_then(|h: &axum::http::HeaderValue| h.to_str().ok())
        .and_then(|s: &str| s.strip_prefix("Bearer "))
        .ok_or_else(|| error::AppError::unauthorized("MFA token is required in Authorization header"))?;
    crate::auth::mfa::mfa_verify_login_handler(&state, mfa_token, req).await
}

/// Verify MFA using a backup code during login (public endpoint, uses mfa_token)
async fn mfa_verify_backup_code_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::mfa::MfaBackupCodeRequest>,
) -> Result<Json<crate::dto::mfa::MfaVerifyResponse>> {
    let mfa_token = headers
        .get("authorization")
        .and_then(|h: &axum::http::HeaderValue| h.to_str().ok())
        .and_then(|s: &str| s.strip_prefix("Bearer "))
        .ok_or_else(|| error::AppError::unauthorized("MFA token is required in Authorization header"))?;
    crate::auth::mfa::mfa_verify_backup_code_handler(&state, mfa_token, req).await
}

/// Disable MFA for the authenticated user
async fn mfa_disable_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaDisableRequest>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::mfa::mfa_disable_handler(&state, user, req).await
}

/// Regenerate backup codes
async fn mfa_regenerate_backup_codes_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaVerifyRequest>,
) -> Result<Json<crate::dto::mfa::MfaBackupCodesResponse>> {
    crate::auth::mfa::mfa_regenerate_backup_codes_handler(&state, user, req).await
}

/// Get MFA status
async fn mfa_status_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::mfa::MfaStatusResponse>> {
    crate::auth::mfa::mfa_status_handler(&state, user).await
}

// ==================== USER HANDLERS ====================

/// Get my profile
async fn get_my_profile_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::users::UserProfileResponse>> {
    crate::auth::users::get_my_profile_handler(&state, user).await
}

/// Update my profile
async fn update_my_profile_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::users::UpdateUserProfileRequest>,
) -> Result<Json<crate::dto::users::UserProfileResponse>> {
    crate::auth::users::update_my_profile_handler(&state, user, req).await
}

/// List users (admin only)
async fn list_users_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Query(query): Query<crate::dto::users::UserListQuery>,
) -> Result<Json<crate::dto::users::UserListResponse>> {
    crate::auth::users::list_users_handler(&state, user, query).await
}

// ==================== TEAM HANDLERS ====================

/// Create a new team
async fn create_team_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::teams::CreateTeamRequest>,
) -> Result<Json<crate::dto::teams::TeamResponse>> {
    crate::auth::teams::create_team_handler(&state, user, req).await
}

/// List teams
async fn list_teams_handler(
    State(state): State<AppState>,
    Extension(_authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Query(query): Query<crate::dto::teams::TeamListQuery>,
) -> Result<Json<crate::dto::teams::TeamListResponse>> {
    crate::auth::teams::list_teams_handler(&state, _authenticated_user, query).await
}

/// Get a team by ID
async fn get_team_handler(
    State(state): State<AppState>,
    Extension(_authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::teams::TeamResponse>> {
    crate::auth::teams::get_team_handler(&state, _authenticated_user, &id).await
}

/// Update a team
async fn update_team_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
    Json(req): Json<crate::dto::teams::UpdateTeamRequest>,
) -> Result<Json<crate::dto::teams::TeamResponse>> {
    crate::auth::teams::update_team_handler(&state, user, &id, req).await
}

/// Delete a team
async fn delete_team_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::teams::delete_team_handler(&state, user, &id).await
}

/// List team members
async fn list_team_members_handler(
    State(state): State<AppState>,
    Extension(_authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::teams::TeamMembersResponse>> {
    crate::auth::teams::list_team_members_handler(&state, _authenticated_user, &id).await
}

/// Add a team member
async fn add_team_member_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
    Json(req): Json<crate::dto::teams::AddTeamMemberRequest>,
) -> Result<Json<crate::dto::teams::TeamMemberResponse>> {
    crate::auth::teams::add_team_member_handler(&state, user, &id, req).await
}

/// Update a team member's role
async fn update_team_member_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path((id, member_id)): Path<(String, String)>,
    Json(req): Json<crate::dto::teams::UpdateTeamMemberRequest>,
) -> Result<Json<crate::dto::teams::TeamMemberResponse>> {
    crate::auth::teams::update_team_member_handler(&state, user, &id, &member_id, req).await
}

/// Remove a team member
async fn remove_team_member_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path((id, member_id)): Path<(String, String)>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::teams::remove_team_member_handler(&state, user, &id, &member_id).await
}

// ==================== API KEY HANDLERS ====================

/// Create a new API key
async fn create_api_key_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::api_keys::CreateApiKeyRequest>,
) -> Result<Json<crate::dto::api_keys::CreateApiKeyResponse>> {
    crate::auth::api_keys::create_api_key_handler(&state, user, req).await
}

/// List API keys
async fn list_api_keys_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Query(query): Query<crate::dto::api_keys::ApiKeyListQuery>,
) -> Result<Json<crate::dto::api_keys::ApiKeyListResponse>> {
    crate::auth::api_keys::list_api_keys_handler(&state, user, query).await
}

/// Get a single API key detail
async fn get_api_key_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::api_keys::ApiKeyDetail>> {
    crate::auth::api_keys::get_api_key_handler(&state, user, &id).await
}

/// Delete (revoke) an API key
async fn delete_api_key_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::api_keys::delete_api_key_handler(&state, user, &id).await
}

/// Rotate an API key
async fn rotate_api_key_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::api_keys::RotateApiKeyResponse>> {
    crate::auth::api_keys::rotate_api_key_handler(&state, user, &id).await
}

/// Update API key permissions
async fn update_api_key_permissions_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
    Json(req): Json<crate::dto::api_keys::UpdateApiKeyPermissionsRequest>,
) -> Result<Json<crate::dto::api_keys::ApiKeyDetail>> {
    crate::auth::api_keys::update_api_key_permissions_handler(&state, user, &id, req).await
}

/// Get API key usage statistics
async fn get_api_key_usage_handler(
    State(state): State<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::api_keys::ApiKeyUsageResponse>> {
    crate::auth::api_keys::get_api_key_usage_handler(&state, user, &id).await
}

// ==================== INFRASTRUCTURE ====================

/// Health check handler that performs actual system checks
///
/// Performs comprehensive health checks including:
/// - Database connectivity (PostgreSQL)
/// - Redis connectivity and basic operations
/// - System metrics (process info, version)
///
/// Returns overall system health status based on component status.
/// If any critical component is unhealthy, the overall status becomes "unhealthy".
async fn health_check_handler(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let request_start = std::time::Instant::now();
    let mut status = "healthy";
    let mut checks = serde_json::json!({
        "status": status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {},
        "uptime_seconds": state.start_time.elapsed().as_secs()
    });

    let checks_obj = checks["checks"].as_object_mut().unwrap();

    // Database connectivity check (PostgreSQL)
    let db_status = match state.db.ping().await {
        Ok(_) => "healthy",
        Err(e) => {
            status = "unhealthy";
            error!("Database health check failed: {}", e);
            "unhealthy"
        },
    };
    checks_obj.insert(
        "database".to_string(),
        serde_json::json!({
            "status": db_status,
            "type": "postgresql",
            "latency_ms": "N/A" // Will be populated in enhanced version
        }),
    );

    // Redis connectivity check
    let redis_status = match state.redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let test_key = "health_check_test";
            let test_value = "ok";

            // Test set operation
            match conn.set_ex::<_, _, ()>(test_key, test_value, 5).await {
                Ok(()) => {
                    // Test get operation
                    match conn.get::<_, Option<String>>(test_key).await {
                        Ok(Some(val)) if val == test_value => "healthy",
                        Ok(_) => {
                            status = "degraded";
                            error!("Redis health check get returned wrong value");
                            "degraded"
                        },
                        Err(e) => {
                            status = "unhealthy";
                            error!("Redis health check get failed: {}", e);
                            "unhealthy"
                        },
                    }
                },
                Err(e) => {
                    status = "unhealthy";
                    error!("Redis health check set failed: {}", e);
                    "unhealthy"
                },
            }
        },
        Err(e) => {
            status = "unhealthy";
            error!("Redis connection failed: {}", e);
            "unhealthy"
        },
    };
    checks_obj.insert(
        "redis".to_string(),
        serde_json::json!({
            "status": redis_status,
            "type": "redis",
            "latency_ms": "N/A" // Will be populated in enhanced version
        }),
    );

    // System metrics
    checks_obj.insert(
        "system".to_string(),
        serde_json::json!({
            "status": "healthy",
            "process_id": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
            "environment": if cfg!(debug_assertions) { "development" } else { "production" }
        }),
    );

    // Update overall status
    checks["status"] = status.into();

    Ok(Json(checks))
}

/// Creates the main application router
///
/// Includes health checks, security headers middleware, and all API routes.
///
/// # Arguments
///
/// * `state` - Application state containing DB pool and config
///
/// # Returns
///
/// Main router with health checks and API routes
pub fn create_app_router(state: AppState) -> Router {
    create_router(state).layer(middleware::from_fn(
        crate::middleware::security_headers::security_headers_middleware,
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use tower::ServiceExt;

    use super::*;

    /// Create a minimal health-check router for testing
    fn test_health_router() -> Router {
        use redis::Client;
        use sea_orm::DatabaseConnection;

        use crate::{AppState, JwtConfig};

        // Create test JWT config with hardcoded secret for tests
        let jwt_config = JwtConfig {
            secret:             "test_jwt_secret_for_router_tests".to_string(),
            expiration_seconds: 3600,
            issuer:             "horizon-test".to_string(),
            audience:           "horizon-api-test".to_string(),
        };

        // Create minimal test state (tests will mock the actual checks)
        let db = DatabaseConnection::default(); // This won't be used in tests
        let redis = Client::open("redis://127.0.0.1:6379").unwrap();
        let state = AppState {
            db,
            jwt_config,
            redis,
            start_time: std::time::Instant::now(),
        };

        Router::new()
            .route("/health", get(health_check_handler))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_ok() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint_get_method() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint_post_not_allowed() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_body() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse JSON response and verify structure
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["status"].is_string()); // status can be "healthy", "degraded", or "unhealthy"
        assert!(json["timestamp"].is_string());
        assert!(json["checks"].is_object());
        assert!(json["checks"]["database"].is_object());
        assert!(json["checks"]["redis"].is_object());
        assert!(json["checks"]["system"].is_object());
        assert!(json["uptime_seconds"].is_number()); // uptime in seconds
    }

    #[tokio::test]
    async fn test_health_check_database_connectivity() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Database status should exist and be a string
        let db_status = json["checks"]["database"]["status"].as_str().unwrap();
        assert!(matches!(db_status, "healthy" | "unhealthy"));
        assert_eq!(
            json["checks"]["database"]["type"].as_str().unwrap(),
            "postgresql"
        );
    }

    #[tokio::test]
    async fn test_health_check_redis_connectivity() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Redis status should exist and be a string
        let redis_status = json["checks"]["redis"]["status"].as_str().unwrap();
        assert!(matches!(redis_status, "healthy" | "degraded" | "unhealthy"));
        assert_eq!(json["checks"]["redis"]["type"].as_str().unwrap(), "redis");
    }

    #[tokio::test]
    async fn test_health_check_system_metrics() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // System metrics should exist
        assert!(json["checks"]["system"]["status"].is_string());
        assert!(json["checks"]["system"]["process_id"].is_number());
        assert!(json["checks"]["system"]["version"].is_string());
        assert!(json["checks"]["system"]["environment"].is_string());
    }

    #[tokio::test]
    async fn test_health_status_matches_components() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let overall_status = json["status"].as_str().unwrap();
        let db_status = json["checks"]["database"]["status"].as_str().unwrap();
        let redis_status = json["checks"]["redis"]["status"].as_str().unwrap();

        // Overall status should reflect the worst component status
        // "healthy" means all components are healthy
        // "degraded" means some components are degraded (Redis health check returns degraded)
        // "unhealthy" means at least one component is unhealthy
        if db_status == "healthy" && redis_status == "healthy" {
            assert_eq!(overall_status, "healthy");
        }
        else {
            assert!(matches!(overall_status, "degraded" | "unhealthy"));
        }
    }

    #[tokio::test]
    async fn test_nonexistent_route_returns_404() {
        let app = test_health_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/nonexistent")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
