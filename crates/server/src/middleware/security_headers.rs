//! # Security Headers Middleware
//!
//! Adds standard security headers to all HTTP responses following
//! OWASP recommended practices.

use axum::{
    body::Body,
    extract::Request,
    http::{self, header::HeaderName, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// CORS configuration for the API
#[derive(Clone, Debug)]
pub struct CorsConfig {
    /// Allowed origin patterns (domains)
    pub allowed_origins:   Vec<String>,
    /// Allowed HTTP methods
    pub allowed_methods:   Vec<http::Method>,
    /// Allowed HTTP headers (request headers the server will accept)
    pub allowed_headers:   Vec<String>,
    /// Exposed headers (headers the client can read from response)
    pub exposed_headers:   Vec<String>,
    /// Whether to allow credentials
    pub allow_credentials: bool,
    /// Maximum age for preflight cache (seconds)
    pub max_age:           u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            // Allow all origins by default for development
            // In production, this should be restricted to specific frontend domains
            allowed_origins:   vec!["*".to_string()],
            allowed_methods:   vec![
                http::Method::GET,
                http::Method::POST,
                http::Method::PUT,
                http::Method::PATCH,
                http::Method::DELETE,
                http::Method::OPTIONS,
            ],
            allowed_headers:   vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
                "Accept".to_string(),
                "Origin".to_string(),
            ],
            // Expose rate-limit headers for client-side usage
            exposed_headers:   vec![
                "X-RateLimit-Limit".to_string(),
                "X-RateLimit-Remaining".to_string(),
                "X-RateLimit-Reset".to_string(),
                "Retry-After".to_string(),
                "X-Request-ID".to_string(),
            ],
            allow_credentials: false,
            max_age:           3600,
        }
    }
}

impl CorsConfig {
    pub fn from_env() -> Self {
        Self {
            allowed_origins:   std::env::var("HORIZON_CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            allowed_methods:   std::env::var("HORIZON_CORS_ALLOWED_METHODS")
                .unwrap_or_else(|_| "GET,POST,PUT,PATCH,DELETE,OPTIONS".to_string())
                .split(',')
                .map(|s| s.trim().parse().unwrap_or(http::Method::GET))
                .collect(),
            allowed_headers:   std::env::var("HORIZON_CORS_ALLOWED_HEADERS")
                .unwrap_or_else(|_| "Content-Type,Authorization,X-Requested-With,Accept,Origin".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            exposed_headers:   std::env::var("HORIZON_CORS_EXPOSED_HEADERS")
                .unwrap_or_else(|_| {
                    "X-RateLimit-Limit,X-RateLimit-Remaining,X-RateLimit-Reset,Retry-After,X-Request-ID".to_string()
                })
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            allow_credentials: std::env::var("HORIZON_CORS_ALLOW_CREDENTIALS")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            max_age:           std::env::var("HORIZON_CORS_MAX_AGE")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
        }
    }
}

/// Extract the origin header from a request
fn get_request_origin(request: &Request) -> Option<String> {
    request
        .headers()
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Check if an origin is allowed
fn is_origin_allowed(origin: &str, allowed_origins: &[String]) -> bool {
    allowed_origins.iter().any(|allowed| {
        if allowed == "*" {
            true
        }
        else if let Some(suffix) = allowed.strip_prefix('*') {
            // Handle wildcard subdomains (e.g., "*.example.com")
            origin.ends_with(suffix)
        }
        else {
            origin == allowed
        }
    })
}

/// Safely insert a header value, returning true on success
fn insert_header(headers: &mut http::HeaderMap, name: &str, value: &str) -> bool {
    if let (Ok(name), Ok(value)) = (
        name.parse::<HeaderName>(),
        value.parse::<http::HeaderValue>(),
    ) {
        headers.insert(name, value);
        true
    }
    else {
        tracing::warn!("Failed to insert header: {} = {}", name, value);
        false
    }
}

/// Security headers middleware
///
/// Adds the following security headers to all responses:
/// - Content-Security-Policy: Restricts resource loading origins
/// - X-Frame-Options: Prevents clickjacking
/// - X-Content-Type-Options: Prevents MIME sniffing
/// - X-XSS-Protection: Legacy XSS protection header
/// - Referrer-Policy: Controls referrer information
/// - Permissions-Policy: Restricts browser features
/// - Strict-Transport-Security: Forces HTTPS (only if TLS is enabled)
/// - Cache-Control: Prevents sensitive data caching for API responses
pub async fn security_headers_middleware(request: Request, next: Next, enable_tls: bool) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Content-Security-Policy: Restrictive default for API server
    insert_header(
        headers,
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'",
    );

    // X-Frame-Options: Prevent embedding in frames (clickjacking protection)
    insert_header(headers, "X-Frame-Options", "DENY");

    // X-Content-Type-Options: Prevent MIME type sniffing
    insert_header(headers, "X-Content-Type-Options", "nosniff");

    // X-XSS-Protection: Legacy but still useful for older browsers
    insert_header(headers, "X-XSS-Protection", "1; mode=block");

    // Referrer-Policy: Don't send referrer for cross-origin requests
    insert_header(
        headers,
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    );

    // Permissions-Policy: Disable unnecessary browser features
    insert_header(
        headers,
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    );

    // Strict-Transport-Security: Only enable if TLS is configured
    // This prevents browsers from connecting over HTTP after seeing HTTPS
    if enable_tls {
        insert_header(
            headers,
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        );
    }

    // Cache-Control: Prevent caching of API responses containing sensitive data
    insert_header(
        headers,
        "Cache-Control",
        "no-store, no-cache, must-revalidate, proxy-revalidate, private",
    );

    // Pragma: Legacy no-cache for HTTP/1.0 compatibility
    insert_header(headers, "Pragma", "no-cache");

    response
}

/// CORS middleware for handling cross-origin requests
///
/// Adds CORS headers to responses based on configuration.
/// Handles preflight (OPTIONS) requests automatically.
pub async fn cors_middleware(request: Request, next: Next, config: CorsConfig) -> Response {
    let origin = get_request_origin(&request);
    tracing::debug!(
        "Request origin: {}",
        origin.clone().unwrap_or_else(|| "None".into())
    );
    tracing::debug!("CORS config: {:?}", config);

    // Handle preflight (OPTIONS) requests
    if request.method() == http::Method::OPTIONS &&
        let Some(ref req_origin) = origin &&
        is_origin_allowed(req_origin, &config.allowed_origins)
    {
        let mut response = (StatusCode::NO_CONTENT, Body::empty()).into_response();
        let headers = response.headers_mut();

        // Allow the origin
        insert_header(headers, "Access-Control-Allow-Origin", req_origin);

        // Allow specific methods
        // Join all methods into a single comma-separated value
        let allowed_methods_value = config
            .allowed_methods
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        insert_header(
            headers,
            "Access-Control-Allow-Methods",
            &allowed_methods_value,
        );

        // Allow specific request headers
        // Join all headers into a single comma-separated value
        let allowed_headers_value = config.allowed_headers.join(", ");
        insert_header(
            headers,
            "Access-Control-Allow-Headers",
            &allowed_headers_value,
        );

        // Expose headers that client-side JavaScript might need to read
        // Join all exposed headers into a single comma-separated value
        let exposed_headers_value = config.exposed_headers.join(", ");
        insert_header(
            headers,
            "Access-Control-Expose-Headers",
            &exposed_headers_value,
        );

        // Credentials
        if config.allow_credentials {
            insert_header(headers, "Access-Control-Allow-Credentials", "true");
        }

        // Max age for preflight cache
        insert_header(
            headers,
            "Access-Control-Max-Age",
            &config.max_age.to_string(),
        );

        return response;
    }

    // Origin not allowed - return 403 for preflight
    if request.method() == http::Method::OPTIONS {
        return (StatusCode::FORBIDDEN, Body::empty()).into_response();
    }

    // Handle regular requests
    let mut response = next.run(request).await;

    if let Some(ref req_origin) = origin &&
        is_origin_allowed(req_origin, &config.allowed_origins)
    {
        let headers = response.headers_mut();
        insert_header(headers, "Access-Control-Allow-Origin", req_origin);

        // Expose headers for client-side access
        // Join all exposed headers into a single comma-separated value
        let exposed_headers_value = config.exposed_headers.join(", ");
        insert_header(
            headers,
            "Access-Control-Expose-Headers",
            &exposed_headers_value,
        );

        if config.allow_credentials {
            insert_header(headers, "Access-Control-Allow-Credentials", "true");
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware::from_fn,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    use super::*;

    async fn dummy_handler() -> &'static str { "OK" }

    #[tokio::test]
    async fn test_security_headers_present() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(|req, next| {
                security_headers_middleware(req, next, true)
            }));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key("content-security-policy"));
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-xss-protection").unwrap(), "1; mode=block");
        assert!(headers.contains_key("referrer-policy"));
        assert!(headers.contains_key("permissions-policy"));
        assert!(headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("cache-control"));
        assert_eq!(headers.get("pragma").unwrap(), "no-cache");
    }

    #[tokio::test]
    async fn test_security_headers_hsts_enabled() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(|req, next| {
                security_headers_middleware(req, next, true)
            }));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        let hsts = response
            .headers()
            .get("strict-transport-security")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(hsts.contains("max-age=31536000"));
        assert!(hsts.contains("includeSubDomains"));
    }

    #[tokio::test]
    async fn test_security_headers_hsts_disabled() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(|req, next| {
                security_headers_middleware(req, next, false)
            }));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        // HSTS should NOT be present when TLS is disabled
        assert!(!response.headers().contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn test_security_headers_csp_value() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(|req, next| {
                security_headers_middleware(req, next, true)
            }));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn test_security_headers_cache_control() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(|req, next| {
                security_headers_middleware(req, next, true)
            }));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        let cc = response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(cc.contains("no-store"));
        assert!(cc.contains("no-cache"));
        assert!(cc.contains("must-revalidate"));
    }

    // CORS Tests

    #[tokio::test]
    async fn test_cors_allows_origin() {
        let config = CorsConfig::default();
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(move |req, next| {
                cors_middleware(req, next, config.clone())
            }));

        let request = Request::builder()
            .uri("/test")
            .header("Origin", "http://localhost:3000")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .contains_key("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn test_cors_exposes_rate_limit_headers() {
        let config = CorsConfig::default();
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(move |req, next| {
                cors_middleware(req, next, config.clone())
            }));

        let request = Request::builder()
            .uri("/test")
            .header("Origin", "http://localhost:3000")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Rate-limit headers should be exposed
        assert!(response
            .headers()
            .contains_key("access-control-expose-headers"));

        let expose_headers = response
            .headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(expose_headers.contains("X-RateLimit-Limit"));
        assert!(expose_headers.contains("X-RateLimit-Remaining"));
        assert!(expose_headers.contains("Retry-After"));
    }

    #[tokio::test]
    async fn test_cors_preflight_exposes_headers() {
        let config = CorsConfig::default();
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(move |req, next| {
                cors_middleware(req, next, config.clone())
            }));

        let request = Request::builder()
            .uri("/test")
            .method("OPTIONS")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "POST")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response
            .headers()
            .contains_key("access-control-allow-methods"));
        assert!(response
            .headers()
            .contains_key("access-control-allow-headers"));
        assert!(response
            .headers()
            .contains_key("access-control-expose-headers"));
    }

    #[tokio::test]
    async fn test_cors_wildcard_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        };
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(move |req, next| {
                cors_middleware(req, next, config.clone())
            }));

        let request = Request::builder()
            .uri("/test")
            .header("Origin", "http://example.com")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .contains_key("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn test_cors_disallows_unauthorized_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["https://trusted-domain.com".to_string()],
            ..Default::default()
        };
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(move |req, next| {
                cors_middleware(req, next, config.clone())
            }));

        let request = Request::builder()
            .uri("/test")
            .header("Origin", "http://untrusted-domain.com")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should still allow the request but not add CORS headers
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
}
