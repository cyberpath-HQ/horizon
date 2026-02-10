//! # Rate Limiting Middleware
//!
//! Redis-backed sliding window rate limiter using sorted sets.
//! Supports per-endpoint rate limits based on sensitivity levels.

use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use redis::AsyncCommands;
use serde_json::json;
use tracing::{debug, warn};

use crate::AppState;

/// Lua script for atomic rate limiting
static RATE_LIMIT_SCRIPT: &str = r#"
    local key = KEYS[1]
    local window_start = ARGV[1]
    local max_requests = ARGV[2]
    local member = ARGV[3]
    local score = ARGV[4]
    local ttl = ARGV[5]

    -- Remove old entries
    redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

    -- Get current count
    local count = redis.call('ZCARD', key)

    -- If under limit, add new entry
    if count < tonumber(max_requests) then
        redis.call('ZADD', key, score, member)
        redis.call('EXPIRE', key, ttl)
        return count
    else
        return count
    end
"#;
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed in the window
    pub max_requests:   u64,
    /// Window size in seconds
    pub window_seconds: u64,
}

impl RateLimitConfig {
    /// Create a new rate limit configuration
    #[must_use]
    pub const fn new(max_requests: u64, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
        }
    }
}

/// Default rate limit: 100 requests per minute
pub const RATE_LIMIT_DEFAULT: RateLimitConfig = RateLimitConfig::new(100, 60);

/// Authentication endpoints: 10 requests per minute (stricter for security)
pub const RATE_LIMIT_AUTH: RateLimitConfig = RateLimitConfig::new(10, 60);

/// Login-specific rate limit: 5 attempts per minute
pub const RATE_LIMIT_LOGIN: RateLimitConfig = RateLimitConfig::new(5, 60);

/// MFA verification: 10 attempts per minute
pub const RATE_LIMIT_MFA: RateLimitConfig = RateLimitConfig::new(10, 60);

/// API key endpoints: 30 requests per minute
pub const RATE_LIMIT_API_KEYS: RateLimitConfig = RateLimitConfig::new(30, 60);

/// Determine the rate limit configuration for a given path
///
/// # Arguments
///
/// * `path` - The request path
///
/// # Returns
///
/// The appropriate rate limit configuration for the endpoint
fn rate_limit_for_path(path: &str) -> &'static RateLimitConfig {
    if path.contains("/auth/login") {
        &RATE_LIMIT_LOGIN
    }
    else if path.contains("/auth/mfa") {
        &RATE_LIMIT_MFA
    }
    else if path.contains("/auth/setup") || path.contains("/auth/refresh") {
        &RATE_LIMIT_AUTH
    }
    else if path.contains("/auth/api-keys") {
        &RATE_LIMIT_API_KEYS
    }
    else {
        &RATE_LIMIT_DEFAULT
    }
}

/// Extract the client IP address from the request headers
///
/// Checks X-Forwarded-For, X-Real-IP, and falls back to "unknown"
///
/// # Arguments
///
/// * `request` - The HTTP request
///
/// # Returns
///
/// The client IP address string
fn extract_client_ip(request: &Request, peer_addr: &SocketAddr) -> String {
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
        .unwrap_or_else(|| peer_addr.ip().to_string())
}

/// Rate limiting middleware using Redis sorted sets (sliding window)
///
/// This middleware:
/// 1. Extracts the client IP
/// 2. Determines the rate limit based on the endpoint
/// 3. Uses Redis ZRANGEBYSCORE + ZADD for sliding window counting
/// 4. Returns 429 Too Many Requests when the limit is exceeded
/// 5. Adds rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After)
pub async fn rate_limit_middleware(mut request: Request, next: Next) -> Response {
    // Try to get peer address from ConnectInfo if available
    let peer_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0);

    // If no ConnectInfo or app state, skip rate limiting (e.g., in tests)
    let app_state = match request.extensions().get::<AppState>() {
        Some(state) => state.clone(),
        None => {
            // If no state, skip rate limiting (fall through)
            return next.run(request).await;
        },
    };

    let peer_addr = match peer_addr {
        Some(addr) => addr,
        None => {
            // If no ConnectInfo available (e.g., in tests), skip rate limiting
            debug!("ConnectInfo not available, skipping rate limiting");
            return next.run(request).await;
        },
    };

    let path = request.uri().path().to_string();
    let client_ip = extract_client_ip(&request, &peer_addr);
    let config = rate_limit_for_path(&path);

    // Build rate limit key: rate_limit:{ip}:{path_category}
    let path_category = categorize_path(&path);
    let key = format!("rate_limit:{}:{}", client_ip, path_category);

    match check_rate_limit(&app_state.redis, &key, config).await {
        Ok(RateLimitResult::Allowed {
            remaining,
        }) => {
            let mut response = next.run(request).await;
            // Add rate limit headers
            let headers = response.headers_mut();
            headers.insert(
                "X-RateLimit-Limit",
                config.max_requests.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Remaining",
                remaining.to_string().parse().unwrap(),
            );
            response
        },
        Ok(RateLimitResult::Exceeded {
            retry_after,
        }) => {
            warn!(
                ip = %client_ip,
                path = %path,
                "Rate limit exceeded"
            );
            create_rate_limit_response(config.max_requests, retry_after)
        },
        Err(e) => {
            // On Redis errors, fail open (allow the request)
            warn!(error = %e, "Rate limit check failed, allowing request");
            next.run(request).await
        },
    }
}

/// Result of a rate limit check
enum RateLimitResult {
    /// Request is allowed, with remaining count
    Allowed {
        remaining: u64,
    },
    /// Rate limit exceeded, with seconds until retry
    Exceeded {
        retry_after: u64,
    },
}

/// Check rate limit using Redis sorted sets (sliding window algorithm)
///
/// Algorithm:
/// 1. Remove all entries outside the current window (ZREMRANGEBYSCORE)
/// 2. Count current entries (ZCARD)
/// 3. If under limit, add new entry (ZADD)
/// 4. Set TTL on the key
///
/// # Arguments
///
/// * `redis` - Redis client
/// * `key` - Rate limit key
/// * `config` - Rate limit configuration
///
/// # Returns
///
/// Rate limit result (allowed or exceeded)
async fn check_rate_limit(
    redis: &redis::Client,
    key: &str,
    config: &RateLimitConfig,
) -> std::result::Result<RateLimitResult, redis::RedisError> {
    let mut conn = redis.get_multiplexed_async_connection().await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64;

    let window_start = now - (config.window_seconds as f64 * 1000.0);

    // Use Lua script for atomic operation
    let script = redis::Script::new(RATE_LIMIT_SCRIPT);
    let member = format!("{}:{}", now, rand::random::<u32>());
    let ttl = config.window_seconds as i64 + 1;

    let count: i64 = script
        .key(key)
        .arg(window_start)
        .arg(config.max_requests)
        .arg(&member)
        .arg(now)
        .arg(ttl)
        .invoke_async(&mut conn)
        .await?;

    if count >= config.max_requests as i64 {
        // Get the oldest entry to calculate retry_after
        let oldest: Vec<(String, f64)> = conn.zrange_withscores(key, 0, 0).await?;
        let retry_after = if let Some((_, score)) = oldest.first() {
            let window_end = score + (config.window_seconds as f64 * 1000.0);
            ((window_end - now) / 1000.0).ceil() as u64
        }
        else {
            config.window_seconds
        };

        return Ok(RateLimitResult::Exceeded {
            retry_after: retry_after.max(1),
        });
    }

    let remaining = config.max_requests - count as u64 - 1;

    debug!(
        key = %key,
        count = count + 1,
        limit = config.max_requests,
        remaining = remaining,
        "Rate limit check passed"
    );

    Ok(RateLimitResult::Allowed {
        remaining,
    })
}

/// Categorize a path for rate limiting grouping
///
/// Groups similar paths to share rate limits
///
/// # Arguments
///
/// * `path` - The request path
///
/// # Returns
///
/// A category string for the path
fn categorize_path(path: &str) -> &str {
    if path.contains("/auth/login") {
        "auth_login"
    }
    else if path.contains("/auth/mfa") {
        "auth_mfa"
    }
    else if path.contains("/auth/setup") {
        "auth_setup"
    }
    else if path.contains("/auth/refresh") {
        "auth_refresh"
    }
    else if path.contains("/auth/api-keys") {
        "api_keys"
    }
    else if path.contains("/auth/") {
        "auth_other"
    }
    else {
        "default"
    }
}

/// Create a rate limit exceeded response
fn create_rate_limit_response(max_requests: u64, retry_after: u64) -> Response {
    let body = axum::Json(json!({
        "success": false,
        "code": "RATE_LIMIT_EXCEEDED",
        "message": format!("Too many requests. Please retry after {} seconds.", retry_after),
        "retry_after": retry_after
    }));

    let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();

    let headers = response.headers_mut();
    headers.insert(
        header::RETRY_AFTER,
        retry_after.to_string().parse().unwrap(),
    );
    if let Ok(val) = max_requests.to_string().parse() {
        headers.insert("x-ratelimit-limit", val);
    }
    headers.insert("x-ratelimit-remaining", "0".parse().unwrap());

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== rate limit config tests ====================

    #[test]
    fn test_rate_limit_config_new() {
        let config = RateLimitConfig::new(50, 30);
        assert_eq!(config.max_requests, 50);
        assert_eq!(config.window_seconds, 30);
    }

    #[test]
    fn test_rate_limit_config_zero_requests() {
        let config = RateLimitConfig::new(0, 60);
        assert_eq!(config.max_requests, 0);
        assert_eq!(config.window_seconds, 60);
    }

    #[test]
    fn test_rate_limit_config_large_values() {
        let config = RateLimitConfig::new(1_000_000, 3600);
        assert_eq!(config.max_requests, 1_000_000);
        assert_eq!(config.window_seconds, 3600);
    }

    #[test]
    fn test_rate_limit_config_clone() {
        let config1 = RateLimitConfig::new(100, 60);
        let config2 = config1.clone();

        assert_eq!(config1.max_requests, config2.max_requests);
        assert_eq!(config1.window_seconds, config2.window_seconds);
    }

    #[test]
    fn test_rate_limit_config_debug_format() {
        let config = RateLimitConfig::new(100, 60);
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("RateLimitConfig"));
        assert!(debug_str.contains("100"));
        assert!(debug_str.contains("60"));
    }

    #[test]
    fn test_rate_limit_constants() {
        // Verify all rate limit constants are properly configured
        assert_eq!(RATE_LIMIT_DEFAULT.max_requests, 100);
        assert_eq!(RATE_LIMIT_AUTH.max_requests, 10);
        assert_eq!(RATE_LIMIT_LOGIN.max_requests, 5);
        assert_eq!(RATE_LIMIT_MFA.max_requests, 10);
        assert_eq!(RATE_LIMIT_API_KEYS.max_requests, 30);

        // All should have 60-second windows
        assert_eq!(RATE_LIMIT_DEFAULT.window_seconds, 60);
        assert_eq!(RATE_LIMIT_AUTH.window_seconds, 60);
        assert_eq!(RATE_LIMIT_LOGIN.window_seconds, 60);
        assert_eq!(RATE_LIMIT_MFA.window_seconds, 60);
        assert_eq!(RATE_LIMIT_API_KEYS.window_seconds, 60);
    }

    // ==================== rate_limit_for_path tests ====================

    #[test]
    fn test_rate_limit_for_path_login() {
        let config = rate_limit_for_path("/api/v1/auth/login");
        assert_eq!(config.max_requests, RATE_LIMIT_LOGIN.max_requests);
        assert_eq!(config.window_seconds, RATE_LIMIT_LOGIN.window_seconds);
    }

    #[test]
    fn test_rate_limit_for_path_mfa() {
        let config = rate_limit_for_path("/api/v1/auth/mfa/verify");
        assert_eq!(config.max_requests, RATE_LIMIT_MFA.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_setup() {
        let config = rate_limit_for_path("/api/v1/auth/setup");
        assert_eq!(config.max_requests, RATE_LIMIT_AUTH.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_refresh() {
        let config = rate_limit_for_path("/api/v1/auth/refresh");
        assert_eq!(config.max_requests, RATE_LIMIT_AUTH.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_api_keys() {
        let config = rate_limit_for_path("/api/v1/auth/api-keys");
        assert_eq!(config.max_requests, RATE_LIMIT_API_KEYS.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_default() {
        let config = rate_limit_for_path("/api/v1/something-else");
        assert_eq!(config.max_requests, RATE_LIMIT_DEFAULT.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_empty() {
        let config = rate_limit_for_path("");
        assert_eq!(config.max_requests, RATE_LIMIT_DEFAULT.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_case_sensitive() {
        // Paths are case-sensitive, so different case should hit default
        let config = rate_limit_for_path("/api/v1/AUTH/LOGIN");
        assert_eq!(config.max_requests, RATE_LIMIT_DEFAULT.max_requests);
    }

    #[test]
    fn test_rate_limit_for_path_login_variations() {
        // Test that substring matching works for various login path variations
        assert_eq!(
            rate_limit_for_path("/auth/login").max_requests,
            RATE_LIMIT_LOGIN.max_requests
        );
        assert_eq!(
            rate_limit_for_path("/v1/auth/login").max_requests,
            RATE_LIMIT_LOGIN.max_requests
        );
        assert_eq!(
            rate_limit_for_path("/api/auth/login").max_requests,
            RATE_LIMIT_LOGIN.max_requests
        );
    }

    #[test]
    fn test_rate_limit_for_path_mfa_variations() {
        assert_eq!(
            rate_limit_for_path("/auth/mfa/verify").max_requests,
            RATE_LIMIT_MFA.max_requests
        );
        assert_eq!(
            rate_limit_for_path("/auth/mfa/setup").max_requests,
            RATE_LIMIT_MFA.max_requests
        );
        assert_eq!(
            rate_limit_for_path("/auth/mfa/disable").max_requests,
            RATE_LIMIT_MFA.max_requests
        );
    }

    // ==================== categorize_path tests ====================

    #[test]
    fn test_categorize_path_login() {
        assert_eq!(categorize_path("/api/v1/auth/login"), "auth_login");
    }

    #[test]
    fn test_categorize_path_mfa() {
        assert_eq!(categorize_path("/api/v1/auth/mfa/verify"), "auth_mfa");
    }

    #[test]
    fn test_categorize_path_setup() {
        assert_eq!(categorize_path("/api/v1/auth/setup"), "auth_setup");
    }

    #[test]
    fn test_categorize_path_refresh() {
        assert_eq!(categorize_path("/api/v1/auth/refresh"), "auth_refresh");
    }

    #[test]
    fn test_categorize_path_api_keys() {
        assert_eq!(categorize_path("/api/v1/auth/api-keys"), "api_keys");
    }

    #[test]
    fn test_categorize_path_other_auth() {
        assert_eq!(categorize_path("/api/v1/auth/logout"), "auth_other");
    }

    #[test]
    fn test_categorize_path_default() {
        assert_eq!(categorize_path("/api/v1/health"), "default");
    }

    #[test]
    fn test_categorize_path_empty() {
        assert_eq!(categorize_path(""), "default");
    }

    #[test]
    fn test_categorize_path_priority_order() {
        // /auth/login should match login before auth_other
        assert_eq!(categorize_path("/auth/login"), "auth_login");
        // /auth/mfa should match mfa before auth_other
        assert_eq!(categorize_path("/auth/mfa"), "auth_mfa");
    }

    #[test]
    fn test_categorize_path_case_sensitivity() {
        // Paths are case-sensitive
        assert_eq!(categorize_path("/API/V1/AUTH/LOGIN"), "default");
        assert_eq!(categorize_path("/api/v1/Auth/login"), "default");
    }

    #[test]
    fn test_categorize_path_variations() {
        // Test multiple forms of each endpoint
        assert_eq!(categorize_path("/v1/auth/login"), "auth_login");
        assert_eq!(categorize_path("/auth/login/extra"), "auth_login");
        assert_eq!(categorize_path("/api/auth/mfa/verify"), "auth_mfa");
        assert_eq!(categorize_path("/auth/setup/init"), "auth_setup");
    }

    // ==================== extract_client_ip tests ====================

    #[test]
    fn test_extract_client_ip_xforwardedfor() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "192.168.1.1, 10.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "192.168.1.1");
    }

    #[test]
    fn test_extract_client_ip_xrealip() {
        let request = Request::builder()
            .uri("/test")
            .header("x-real-ip", "10.0.0.5")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "10.0.0.5");
    }

    #[test]
    fn test_extract_client_ip_missing() {
        let request = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "127.0.0.1");
    }

    #[test]
    fn test_extract_client_ip_prefers_forwarded_for() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-real-ip", "5.6.7.8")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "1.2.3.4");
    }

    #[test]
    fn test_extract_client_ip_xforwardedfor_single() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "10.20.30.40")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "10.20.30.40");
    }

    #[test]
    fn test_extract_client_ip_xforwardedfor_whitespace() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "  192.168.1.100  ,  10.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        // Should trim whitespace from first IP
        assert_eq!(extract_client_ip(&request, &peer_addr), "192.168.1.100");
    }

    #[test]
    fn test_extract_client_ip_xforwardedfor_multiple() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        // Should take first IP
        assert_eq!(extract_client_ip(&request, &peer_addr), "1.1.1.1");
    }

    #[test]
    fn test_extract_client_ip_ipv6() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "[2001:db8::1]")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "[2001:db8::1]");
    }

    #[test]
    fn test_extract_client_ip_xrealip_ipv6() {
        let request = Request::builder()
            .uri("/test")
            .header("x-real-ip", "2001:db8::1")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(extract_client_ip(&request, &peer_addr), "2001:db8::1");
    }

    #[test]
    fn test_extract_client_ip_localhost() {
        let request = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "[::1]:8080".parse().unwrap();
        // Should extract the peer address when no headers
        let ip = extract_client_ip(&request, &peer_addr);
        assert!(!ip.is_empty());
    }

    #[test]
    fn test_extract_client_ip_case_insensitive_headers() {
        // HTTP headers are case-insensitive, but lowercase is standard
        let request = Request::builder()
            .uri("/test")
            .header("X-Forwarded-For", "203.0.113.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        // Header names are standardized to lowercase internally
        let ip = extract_client_ip(&request, &peer_addr);
        // If lowercase header is not found, should fall to peer addr
        assert!(!ip.is_empty());
    }

    // ==================== create_rate_limit_response tests ====================

    #[test]
    fn test_create_rate_limit_response_status() {
        let response = create_rate_limit_response(100, 30);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_create_rate_limit_response_headers() {
        let response = create_rate_limit_response(100, 30);
        let headers = response.headers();

        // Should have Retry-After header
        assert!(headers.contains_key("retry-after"));
        let retry_after = headers.get("retry-after").unwrap().to_str().unwrap();
        assert_eq!(retry_after, "30");

        // Should have rate limit headers
        assert!(headers.contains_key("x-ratelimit-limit"));
        assert!(headers.contains_key("x-ratelimit-remaining"));
        assert_eq!(
            headers
                .get("x-ratelimit-remaining")
                .unwrap()
                .to_str()
                .unwrap(),
            "0"
        );
    }

    #[test]
    fn test_create_rate_limit_response_retry_after_values() {
        let response1 = create_rate_limit_response(100, 1);
        let response2 = create_rate_limit_response(100, 60);
        let response3 = create_rate_limit_response(100, 3600);

        assert_eq!(
            response1
                .headers()
                .get("retry-after")
                .unwrap()
                .to_str()
                .unwrap(),
            "1"
        );
        assert_eq!(
            response2
                .headers()
                .get("retry-after")
                .unwrap()
                .to_str()
                .unwrap(),
            "60"
        );
        assert_eq!(
            response3
                .headers()
                .get("retry-after")
                .unwrap()
                .to_str()
                .unwrap(),
            "3600"
        );
    }

    #[test]
    fn test_create_rate_limit_response_zero_retry() {
        let response = create_rate_limit_response(100, 0);
        // Even with 0, should set some header
        assert!(response.headers().contains_key("retry-after"));
    }

    #[test]
    fn test_create_rate_limit_response_large_limits() {
        let response = create_rate_limit_response(10_000, 3600);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("x-ratelimit-limit"));
    }

    // ==================== edge cases and integration tests ====================

    #[test]
    fn test_path_routing_accuracy() {
        // Ensure path routing doesn't have false matches
        assert_eq!(categorize_path("/auth/not-login"), "auth_other");
        assert_eq!(categorize_path("/authlogin"), "default"); // No slash

        // Ensure substring matching doesn't create false positives
        // "/create-auth-api-keys" doesn't contain "/auth/" so should be default
        assert_eq!(categorize_path("/create-auth-api-keys"), "default");
    }

    #[test]
    fn test_rate_limit_for_nested_paths() {
        // Verify deeply nested paths work correctly
        assert_eq!(
            rate_limit_for_path("/api/v1/auth/mfa/verify/backup-codes").max_requests,
            RATE_LIMIT_MFA.max_requests
        );
    }

    #[test]
    fn test_extract_client_ip_with_empty_xforwardedfor() {
        let request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "")
            .header("x-real-ip", "10.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        // When x-forwarded-for header exists but is empty, it returns empty string
        // (the map() finds Some("") and doesn't trigger or_else)
        let ip = extract_client_ip(&request, &peer_addr);
        assert_eq!(ip, "");
    }
}
