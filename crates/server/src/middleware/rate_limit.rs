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
pub async fn rate_limit_middleware(
    axum::extract::ConnectInfo(peer_addr): axum::extract::ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let app_state = match request.extensions().get::<AppState>() {
        Some(state) => state.clone(),
        None => {
            // If no state, skip rate limiting (fall through)
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
    fn test_categorize_path() {
        assert_eq!(categorize_path("/api/v1/auth/login"), "auth_login");
        assert_eq!(categorize_path("/api/v1/auth/mfa/verify"), "auth_mfa");
        assert_eq!(categorize_path("/api/v1/auth/setup"), "auth_setup");
        assert_eq!(categorize_path("/api/v1/auth/refresh"), "auth_refresh");
        assert_eq!(categorize_path("/api/v1/auth/api-keys"), "api_keys");
        assert_eq!(categorize_path("/api/v1/auth/logout"), "auth_other");
        assert_eq!(categorize_path("/api/v1/health"), "default");
    }

    #[test]
    fn test_rate_limit_config_new() {
        let config = RateLimitConfig::new(50, 30);
        assert_eq!(config.max_requests, 50);
        assert_eq!(config.window_seconds, 30);
    }

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
}
