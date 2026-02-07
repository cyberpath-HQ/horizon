//! # Authentication Middleware
//!
//! JWT authentication middleware for protecting API endpoints.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::{
    auth::jwt::{extract_bearer_token, validate_token},
    token_blacklist::hash_token_for_blacklist,
    AppState,
};

/// User information extracted from JWT token
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// User ID
    pub id:    String,
    /// User email
    pub email: String,
    /// User roles
    pub roles: Vec<String>,
}

/// Authentication middleware
///
/// This middleware:
/// 1. Extracts the Bearer token from the Authorization header
/// 2. Validates the JWT token
/// 3. Adds authenticated user info to request extensions
/// 4. Rejects requests with invalid/missing tokens
pub async fn auth_middleware(mut request: Request, next: Next) -> Response {
    // Get app state for Redis access
    let app_state = match request.extensions().get::<AppState>() {
        Some(state) => state,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server configuration error",
            )
                .into_response();
        },
    };

    let jwt_config = &app_state.jwt_config;

    // Extract Authorization header
    let auth_header = match request.headers().get(header::AUTHORIZATION) {
        Some(header) => {
            match header.to_str() {
                Ok(h) => h,
                Err(_) => {
                    return create_auth_error_response("Invalid authorization header encoding");
                },
            }
        },
        None => {
            return create_auth_error_response("Missing authorization header");
        },
    };

    // Extract Bearer token
    let token = match extract_bearer_token(auth_header) {
        Some(token) => token,
        None => {
            return create_auth_error_response("Invalid authorization header format");
        },
    };

    // Validate token
    let claims = match validate_token(jwt_config, &token) {
        Ok(claims) => claims,
        Err(e) => {
            // Map specific JWT errors to appropriate responses
            let error_msg = e.to_string().to_lowercase();
            if error_msg.contains("expired") {
                return create_auth_error_response("Token has expired");
            }
            else if error_msg.contains("signature") {
                return create_auth_error_response("Invalid token signature");
            }
            else {
                return create_auth_error_response("Invalid token");
            }
        },
    };

    // Check if token is blacklisted
    let token_hash = hash_token_for_blacklist(&token);
    let blacklist = crate::token_blacklist::TokenBlacklist::new(app_state.redis.clone());
    match blacklist.is_blacklisted(&token_hash).await {
        Ok(true) => {
            return create_auth_error_response("Token has been revoked");
        },
        Ok(false) => {
            // Token is not blacklisted, continue
        },
        Err(e) => {
            // Fail-closed for security: deny request if we can't verify token status
            tracing::error!("Failed to check token blacklist, denying request: {}", e);
            return create_auth_error_response("Authentication service temporarily unavailable");
        },
    }

    // Create authenticated user from claims
    let user = AuthenticatedUser {
        id:    claims.sub,
        email: claims.email,
        roles: claims.roles,
    };

    // Add user to request extensions
    request.extensions_mut().insert(user);

    // Continue with the request
    next.run(request).await
}

/// Create standardized authentication error response
fn create_auth_error_response(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(json!({
            "success": false,
            "code": "AUTHENTICATION_ERROR",
            "message": message
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::jwt::extract_bearer_token;

    #[tokio::test]
    async fn test_extract_bearer_token() {
        assert_eq!(
            extract_bearer_token("Bearer abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_bearer_token("Bearer   abc123   "),
            Some("abc123".to_string())
        );
        assert!(extract_bearer_token("Basic abc123").is_none());
        assert!(extract_bearer_token("Bearer").is_none());
        assert!(extract_bearer_token("").is_none());
    }

    #[tokio::test]
    async fn test_extract_bearer_token_edge_cases() {
        // Verify extract_bearer_token works correctly
        assert!(extract_bearer_token("Bearer test").is_some());
        assert!(extract_bearer_token("Bearer").is_none());
        assert!(extract_bearer_token("").is_none());
        assert!(extract_bearer_token("Basic abc123").is_none());
    }
}
