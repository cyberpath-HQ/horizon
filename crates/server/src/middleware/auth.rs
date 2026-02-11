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
use auth::jwt::{extract_bearer_token, validate_token};
use error::AppError;

use crate::AppState;

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

impl<S> axum::extract::FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .ok_or(axum::http::StatusCode::UNAUTHORIZED)
    }
}

/// Authentication middleware
///
/// This middleware:
/// 1. Extracts the Bearer token from the Authorization header
/// 2. Validates the JWT token
/// 3. Adds authenticated user info to request extensions
/// 4. Rejects requests with invalid/missing tokens
pub async fn auth_middleware(mut request: Request, next: Next) -> Response {
    // Get app state
    let state = match request.extensions().get::<AppState>() {
        Some(s) => s,
        None => {
            tracing::error!("Server misconfiguration: missing app state in request extensions");
            return create_server_error_response("Server configuration error: missing app state");
        },
    };
    // Get JWT config from state
    let jwt_config = &state.jwt_config;

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
        Err(AppError::JwtExpired) => {
            return create_auth_error_response("Token has expired");
        },
        Err(AppError::JwtInvalidSignature) => {
            return create_auth_error_response("Invalid token signature");
        },
        Err(AppError::JwtInvalidToken) => {
            return create_auth_error_response("Invalid token");
        },
        Err(_) => {
            return create_auth_error_response("Authentication failed");
        },
    };

    // Check if token is blacklisted
    let token_hash = crate::token_blacklist::hash_token_for_blacklist(&token);
    let blacklist = crate::token_blacklist::TokenBlacklist::new(state.redis.clone());
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

    // Add user to request extensions (directly, not wrapped in Extension)
    request.extensions_mut().insert(user.clone());

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

/// Create server error response for misconfiguration (missing app state)
fn create_server_error_response(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({
            "success": false,
            "code": "SERVER_ERROR",
            "message": message
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use auth::jwt::extract_bearer_token;

    use super::*;

    #[test]
    fn test_extract_bearer_token() {
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

    #[test]
    fn test_extract_bearer_token_edge_cases() {
        assert!(extract_bearer_token("Bearer test").is_some());
        assert!(extract_bearer_token("Bearer").is_none());
        assert!(extract_bearer_token("").is_none());
        assert!(extract_bearer_token("Basic abc123").is_none());
    }

    #[test]
    fn test_extract_bearer_token_with_spaces() {
        assert_eq!(
            extract_bearer_token("Bearer token123"),
            Some("token123".to_string())
        );
    }

    #[test]
    fn test_extract_bearer_token_case_sensitive() {
        // Bearer prefix should be case-sensitive
        assert!(extract_bearer_token("bearer token").is_none());
        assert!(extract_bearer_token("BEARER token").is_none());
    }

    #[test]
    fn test_authenticated_user_structure() {
        let user = AuthenticatedUser {
            id:    "user-123".to_string(),
            email: "user@example.com".to_string(),
            roles: vec!["admin".to_string(), "viewer".to_string()],
        };

        assert_eq!(user.id, "user-123");
        assert_eq!(user.email, "user@example.com");
        assert_eq!(user.roles.len(), 2);
        assert!(user.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn test_authenticated_user_clone() {
        let user1 = AuthenticatedUser {
            id:    "user-456".to_string(),
            email: "test@example.com".to_string(),
            roles: vec!["user".to_string()],
        };

        let user2 = user1.clone();
        assert_eq!(user1.id, user2.id);
        assert_eq!(user1.email, user2.email);
        assert_eq!(user1.roles, user2.roles);
    }

    #[test]
    fn test_authenticated_user_empty_roles() {
        let user = AuthenticatedUser {
            id:    "user-789".to_string(),
            email: "noprole@example.com".to_string(),
            roles: vec![],
        };

        assert!(user.roles.is_empty());
    }

    #[test]
    fn test_create_auth_error_response_formats() {
        // Test that error responses are created correctly
        let response = create_auth_error_response("Test error");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_create_auth_error_messages() {
        let messages = vec![
            "Missing authorization header",
            "Invalid authorization header format",
            "Token has expired",
            "Invalid token signature",
            "Invalid token",
            "Authentication failed",
            "Token has been revoked",
            "Authentication service temporarily unavailable",
        ];

        for msg in messages {
            let response = create_auth_error_response(msg);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn test_bearer_token_extraction_variations() {
        // Test various Bearer token formats
        let test_cases = vec![
            (
                "Bearer valid_token_123",
                Some("valid_token_123".to_string()),
            ),
            (
                "Bearer token.with.dots",
                Some("token.with.dots".to_string()),
            ),
            (
                "Bearer token-with-dashes",
                Some("token-with-dashes".to_string()),
            ),
            (
                "Bearer token_with_underscores",
                Some("token_with_underscores".to_string()),
            ),
            ("Bearer", None),
            ("Bearer ", None),
            ("bearer lowercase", None),
        ];

        for (input, expected) in test_cases {
            assert_eq!(
                extract_bearer_token(input),
                expected,
                "Failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_authenticated_user_debug_format() {
        let user = AuthenticatedUser {
            id:    "user-debug".to_string(),
            email: "debug@example.com".to_string(),
            roles: vec!["admin".to_string()],
        };

        let debug_str = format!("{:?}", user);
        assert!(debug_str.contains("user-debug"));
        assert!(debug_str.contains("debug@example.com"));
    }

    #[test]
    fn test_authenticated_user_multiple_roles() {
        let roles = vec![
            "admin".to_string(),
            "editor".to_string(),
            "viewer".to_string(),
            "user".to_string(),
        ];

        let user = AuthenticatedUser {
            id:    "multi-role-user".to_string(),
            email: "roles@example.com".to_string(),
            roles: roles.clone(),
        };

        assert_eq!(user.roles.len(), 4);
        for (i, role) in roles.iter().enumerate() {
            assert_eq!(&user.roles[i], role);
        }
    }

    #[test]
    fn test_authenticated_user_equality() {
        let user1 = AuthenticatedUser {
            id:    "same-user".to_string(),
            email: "same@example.com".to_string(),
            roles: vec!["admin".to_string()],
        };

        let user2 = AuthenticatedUser {
            id:    "same-user".to_string(),
            email: "same@example.com".to_string(),
            roles: vec!["admin".to_string()],
        };

        assert_eq!(user1.id, user2.id);
        assert_eq!(user1.email, user2.email);
    }
}
