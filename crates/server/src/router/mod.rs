//! # API Router Configuration
//!
//! Configures API routes for the Horizon application.

use axum::{
    extract::{Extension, Path, State as AxumState},
    http::HeaderMap,
    middleware,
    routing::{delete, get, post},
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
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/auth/refresh", post(refresh_handler))
        .route("/api/v1/auth/sessions", get(sessions_handler))
        .route("/api/v1/auth/sessions/:id", delete(delete_session_handler))
        .route("/api/v1/auth/sessions", delete(delete_all_sessions_handler))
        .layer(middleware::from_fn(
            crate::middleware::auth::auth_middleware,
        ));

    // Public routes that don't require authentication
    let public_routes = Router::new()
        .route("/api/v1/auth/setup", post(setup_handler))
        .route("/api/v1/auth/login", post(login_handler));

    public_routes.merge(protected_routes).with_state(state)
}

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
/// Wrapper handler for deleting all user sessions (logout everywhere)
async fn delete_all_sessions_handler(
    AxumState(state): AxumState<AppState>,
    Extension(authenticated_user): Extension<crate::middleware::auth::AuthenticatedUser>,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    crate::auth::sessions::delete_all_sessions_handler(&state, authenticated_user).await
}

/// Creates the health check router
pub fn create_health_router() -> Router { Router::new().route("/health", axum::routing::get(|| async { "OK" })) }

/// Creates the main application router
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
}
