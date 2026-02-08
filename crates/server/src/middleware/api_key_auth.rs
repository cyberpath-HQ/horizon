//! # API Key Authentication Middleware
//!
//! Authenticates requests using the X-API-Key header.
//! Falls through to JWT auth if no X-API-Key header is present.
//! Also logs API key usage for audit trail.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use tracing::{debug, warn};

use crate::{
    auth::api_keys::{authenticate_api_key, check_api_key_permissions, log_api_key_usage},
    middleware::auth::AuthenticatedUser,
    AppState,
};

/// API key authentication middleware
///
/// This middleware:
/// 1. Checks for the X-API-Key header
/// 2. If present, authenticates the API key (hash lookup + expiration check)
/// 3. Verifies the associated user is active
/// 4. Checks API key permissions for the endpoint
/// 5. Injects an `AuthenticatedUser` into request extensions (same as JWT auth)
/// 6. Logs usage to the audit trail
/// 7. If no X-API-Key header, passes through (caller should also have JWT middleware)
pub async fn api_key_auth_middleware(mut request: Request, next: Next) -> Response {
    // Check for X-API-Key header
    let api_key_header = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let raw_key = match api_key_header {
        Some(key) if !key.is_empty() => key,
        _ => {
            // No API key header, pass through to other auth methods
            return next.run(request).await;
        },
    };

    // Get app state
    let app_state = match request.extensions().get::<AppState>() {
        Some(state) => state.clone(),
        None => {
            return create_api_key_error_response("Server configuration error");
        },
    };

    // Authenticate the API key
    let (api_key_model, user_model) = match authenticate_api_key(&app_state, &raw_key).await {
        Ok(result) => result,
        Err(e) => {
            warn!(error = %e, "API key authentication failed");
            return create_api_key_error_response("Invalid or expired API key");
        },
    };

    // Check permissions for this endpoint and method
    let path = request.uri().path().to_string();
    let method = request.method().to_string();

    if !check_api_key_permissions(&api_key_model.permissions, &path, &method) {
        warn!(
            api_key_id = %api_key_model.id,
            path = %path,
            method = %method,
            "API key lacks required permissions"
        );
        return create_api_key_error_response("API key does not have permission for this endpoint");
    }

    // Load user roles for the authenticated user extension
    let user_roles = match auth::roles::get_user_roles(&app_state.db, &user_model.id).await {
        Ok(roles) => roles,
        Err(_) => return create_api_key_error_response("Failed to load user roles"),
    };

    // Insert authenticated user into request extensions
    let authenticated_user = AuthenticatedUser {
        id:    user_model.id.clone(),
        email: user_model.email.clone(),
        roles: user_roles,
    };
    request.extensions_mut().insert(authenticated_user);

    // Extract info for logging before the request is consumed
    let api_key_id = api_key_model.id.clone();
    let user_id = user_model.id.clone();
    let ip_address = extract_ip_from_request(&request);
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    debug!(
        api_key_id = %api_key_id,
        user_id = %user_id,
        path = %path,
        method = %method,
        "Request authenticated via API key"
    );

    // Run the handler
    let response = next.run(request).await;
    let status_code = response.status().as_u16() as i16;

    // Log usage asynchronously (don't block the response)
    let state_clone = app_state.clone();
    let path_clone = path.clone();
    let method_clone = method.clone();
    let ip_clone = ip_address.clone();
    let ua_clone = user_agent.clone();
    tokio::spawn(async move {
        if let Err(e) = log_api_key_usage(
            &state_clone,
            &api_key_id,
            &path_clone,
            &method_clone,
            ip_clone.as_deref(),
            ua_clone.as_deref(),
            status_code,
        )
        .await
        {
            warn!(error = %e, "Failed to log API key usage");
        }
    });

    response
}

/// Extract client IP from request headers
fn extract_ip_from_request(request: &Request) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

/// Create a standardized API key authentication error response
fn create_api_key_error_response(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "API-Key")],
        axum::Json(json!({
            "success": false,
            "code": "API_KEY_AUTHENTICATION_ERROR",
            "message": message
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;

    #[test]
    fn test_extract_ip_xforwardedfor() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "192.168.1.1, 10.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            extract_ip_from_request(&request),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_xrealip() {
        let request = Request::builder()
            .uri("/test")
            .header("x-real-ip", "10.0.0.5")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            extract_ip_from_request(&request),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn test_extract_ip_missing() {
        let request = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_ip_from_request(&request), None);
    }

    #[test]
    fn test_extract_ip_prefers_forwarded() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-real-ip", "5.6.7.8")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            extract_ip_from_request(&request),
            Some("1.2.3.4".to_string())
        );
    }
}
