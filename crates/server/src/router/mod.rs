//! # API Router Configuration
//!
//! Configures API routes for the Horizon application.

use axum::{
    extract::{Extension, Path, Query, State as AxumState},
    http::HeaderMap,
    middleware,
    routing::{delete, get, post, put},
    Json,
    Router,
};
use error::Result;

use crate::AppState;

/// Creates the API router with all routes
///
/// # Arguments
///
/// * `state` - Application state containing DB pool and config
///
/// # Returns
///
/// Configured Axum router with all routes
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
        .layer(middleware::from_fn(crate::middleware::auth::auth_middleware));

    // Public routes that don't require authentication
    let public_routes = Router::new()
        .route("/api/v1/auth/setup", post(setup_handler))
        .route("/api/v1/auth/login", post(login_handler))
        // MFA verification during login (uses mfa_token from login response, not session auth)
        .route("/api/v1/auth/mfa/verify", post(mfa_verify_login_handler))
        .route("/api/v1/auth/mfa/verify-backup", post(mfa_verify_backup_code_handler));

    public_routes.merge(protected_routes).with_state(state)
}

// ==================== AUTH HANDLERS ====================

/// Wrapper handler for setup endpoint that uses State extractor
async fn setup_handler(
    AxumState(state): AxumState<AppState>,
    Json(req): Json<crate::dto::auth::SetupRequest>,
) -> Result<Json<crate::dto::auth::AuthSuccessResponse>> {
    crate::auth::handlers::setup_handler_inner(&state, req).await
}

/// Wrapper handler for login endpoint that uses State extractor
async fn login_handler(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::auth::LoginRequest>,
) -> Result<Json<crate::dto::auth::AuthSuccessResponse>> {
    crate::auth::handlers::login_handler_inner(&state, req, headers).await
}

/// Wrapper handler for logout endpoint that uses State extractor
async fn logout_handler(
    AxumState(state): AxumState<AppState>,
    request: axum::extract::Request,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::handlers::logout_handler_inner(&state, request).await
}

/// Wrapper handler for refresh endpoint that uses State extractor
async fn refresh_handler(
    AxumState(state): AxumState<AppState>,
    Json(req): Json<crate::dto::auth::RefreshRequest>,
) -> Result<Json<crate::dto::auth::AuthSuccessResponse>> {
    crate::auth::handlers::refresh_handler_inner(&state, req).await
}

/// Wrapper handler for getting user sessions
async fn sessions_handler(
    AxumState(state): AxumState<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::auth::sessions::SessionsResponse>> {
    crate::auth::sessions::get_sessions_handler(&state, authenticated_user).await
}

/// Wrapper handler for deleting a specific session
async fn delete_session_handler(
    AxumState(state): AxumState<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(session_id): Path<String>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::sessions::delete_session_handler(&state, authenticated_user, Path(session_id)).await
}

/// Wrapper handler for deleting all user sessions (logout everywhere)
async fn delete_all_sessions_handler(
    AxumState(state): AxumState<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::sessions::delete_all_sessions_handler(&state, authenticated_user).await
}

// ==================== MFA HANDLERS ====================

/// Enable MFA for the authenticated user
async fn mfa_enable_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaEnableRequest>,
) -> Result<Json<crate::dto::mfa::MfaSetupResponse>> {
    crate::auth::mfa::mfa_enable_handler(&state, user, req).await
}

/// Verify TOTP code to finalize MFA setup
async fn mfa_verify_setup_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaVerifyRequest>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::mfa::mfa_verify_setup_handler(&state, user, req).await
}

/// Verify MFA during login (public endpoint, uses mfa_token)
async fn mfa_verify_login_handler(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::mfa::MfaVerifyRequest>,
) -> Result<Json<crate::dto::mfa::MfaVerifyResponse>> {
    let mfa_token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| error::AppError::unauthorized("MFA token is required in Authorization header"))?;
    crate::auth::mfa::mfa_verify_login_handler(&state, mfa_token, req).await
}

/// Verify MFA using a backup code during login (public endpoint, uses mfa_token)
async fn mfa_verify_backup_code_handler(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::mfa::MfaBackupCodeRequest>,
) -> Result<Json<crate::dto::mfa::MfaVerifyResponse>> {
    let mfa_token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| error::AppError::unauthorized("MFA token is required in Authorization header"))?;
    crate::auth::mfa::mfa_verify_backup_code_handler(&state, mfa_token, req).await
}

/// Disable MFA for the authenticated user
async fn mfa_disable_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaDisableRequest>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::mfa::mfa_disable_handler(&state, user, req).await
}

/// Regenerate backup codes
async fn mfa_regenerate_backup_codes_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::mfa::MfaVerifyRequest>,
) -> Result<Json<crate::dto::mfa::MfaBackupCodesResponse>> {
    crate::auth::mfa::mfa_regenerate_backup_codes_handler(&state, user, req).await
}

/// Get MFA status
async fn mfa_status_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::mfa::MfaStatusResponse>> {
    crate::auth::mfa::mfa_status_handler(&state, user).await
}

// ==================== USER HANDLERS ====================

/// Get my profile
async fn get_my_profile_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::users::UserProfileResponse>> {
    crate::auth::users::get_my_profile_handler(&state, user).await
}

/// Update my profile
async fn update_my_profile_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::users::UpdateUserProfileRequest>,
) -> Result<Json<crate::dto::users::UserProfileResponse>> {
    crate::auth::users::update_my_profile_handler(&state, user, req).await
}

/// List users (admin only)
async fn list_users_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Query(query): Query<crate::dto::users::UserListQuery>,
) -> Result<Json<crate::dto::users::UserListResponse>> {
    crate::auth::users::list_users_handler(&state, user, query).await
}

// ==================== TEAM HANDLERS ====================

/// Create a new team
async fn create_team_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::teams::CreateTeamRequest>,
) -> Result<Json<crate::dto::teams::TeamResponse>> {
    crate::auth::teams::create_team_handler(&state, user, req).await
}

/// List teams
async fn list_teams_handler(
    AxumState(state): AxumState<AppState>,
    Query(query): Query<crate::dto::teams::TeamListQuery>,
) -> Result<Json<crate::dto::teams::TeamListResponse>> {
    crate::auth::teams::list_teams_handler(&state, query).await
}

/// Get a team by ID
async fn get_team_handler(
    AxumState(state): AxumState<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::teams::TeamResponse>> {
    crate::auth::teams::get_team_handler(&state, &id).await
}

/// Update a team
async fn update_team_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
    Json(req): Json<crate::dto::teams::UpdateTeamRequest>,
) -> Result<Json<crate::dto::teams::TeamResponse>> {
    crate::auth::teams::update_team_handler(&state, user, &id, req).await
}

/// Delete a team
async fn delete_team_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::teams::delete_team_handler(&state, user, &id).await
}

/// List team members
async fn list_team_members_handler(
    AxumState(state): AxumState<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::teams::TeamMembersResponse>> {
    crate::auth::teams::list_team_members_handler(&state, &id).await
}

/// Add a team member
async fn add_team_member_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
    Json(req): Json<crate::dto::teams::AddTeamMemberRequest>,
) -> Result<Json<crate::dto::teams::TeamMemberResponse>> {
    crate::auth::teams::add_team_member_handler(&state, user, &id, req).await
}

/// Update a team member's role
async fn update_team_member_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path((id, member_id)): Path<(String, String)>,
    Json(req): Json<crate::dto::teams::UpdateTeamMemberRequest>,
) -> Result<Json<crate::dto::teams::TeamMemberResponse>> {
    crate::auth::teams::update_team_member_handler(&state, user, &id, &member_id, req).await
}

/// Remove a team member
async fn remove_team_member_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path((id, member_id)): Path<(String, String)>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::teams::remove_team_member_handler(&state, user, &id, &member_id).await
}

// ==================== API KEY HANDLERS ====================

/// Create a new API key
async fn create_api_key_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Json(req): Json<crate::dto::api_keys::CreateApiKeyRequest>,
) -> Result<Json<crate::dto::api_keys::CreateApiKeyResponse>> {
    crate::auth::api_keys::create_api_key_handler(&state, user, req).await
}

/// List API keys
async fn list_api_keys_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Query(query): Query<crate::dto::api_keys::ApiKeyListQuery>,
) -> Result<Json<crate::dto::api_keys::ApiKeyListResponse>> {
    crate::auth::api_keys::list_api_keys_handler(&state, user, query).await
}

/// Get a single API key detail
async fn get_api_key_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::api_keys::ApiKeyDetail>> {
    crate::auth::api_keys::get_api_key_handler(&state, user, &id).await
}

/// Delete (revoke) an API key
async fn delete_api_key_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::api_keys::delete_api_key_handler(&state, user, &id).await
}

/// Rotate an API key
async fn rotate_api_key_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::api_keys::RotateApiKeyResponse>> {
    crate::auth::api_keys::rotate_api_key_handler(&state, user, &id).await
}

/// Update API key permissions
async fn update_api_key_permissions_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
    Json(req): Json<crate::dto::api_keys::UpdateApiKeyPermissionsRequest>,
) -> Result<Json<crate::dto::api_keys::ApiKeyDetail>> {
    crate::auth::api_keys::update_api_key_permissions_handler(&state, user, &id, req).await
}

/// Get API key usage statistics
async fn get_api_key_usage_handler(
    AxumState(state): AxumState<AppState>,
    Extension(user): Extension<crate::middleware::auth::AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<crate::dto::api_keys::ApiKeyUsageResponse>> {
    crate::auth::api_keys::get_api_key_usage_handler(&state, user, &id).await
}

// ==================== INFRASTRUCTURE ====================

/// Creates the health check router
pub fn create_health_router() -> Router { Router::new().route("/health", axum::routing::get(|| async { "OK" })) }

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
    Router::new()
        .merge(create_health_router())
        .merge(create_router(state))
        .layer(middleware::from_fn(
            crate::middleware::security_headers::security_headers_middleware,
        ))
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use tower::ServiceExt;

    use super::*;

    /// Create a minimal health-check router for testing
    fn test_health_router() -> Router { create_health_router() }

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
        assert_eq!(&body[..], b"OK");
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
