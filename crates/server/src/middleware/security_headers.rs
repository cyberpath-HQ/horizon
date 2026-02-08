//! # Security Headers Middleware
//!
//! Adds standard security headers to all HTTP responses following
//! OWASP recommended practices.

use axum::{extract::Request, middleware::Next, response::Response};

/// Security headers middleware
///
/// Adds the following security headers to all responses:
/// - Content-Security-Policy: Restricts resource loading origins
/// - X-Frame-Options: Prevents clickjacking
/// - X-Content-Type-Options: Prevents MIME sniffing
/// - X-XSS-Protection: Legacy XSS protection header
/// - Referrer-Policy: Controls referrer information
/// - Permissions-Policy: Restricts browser features
/// - Strict-Transport-Security: Forces HTTPS
/// - Cache-Control: Prevents sensitive data caching for API responses
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Content-Security-Policy: Restrictive default for API server
    headers.insert(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );

    // X-Frame-Options: Prevent embedding in frames (clickjacking protection)
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());

    // X-Content-Type-Options: Prevent MIME type sniffing
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());

    // X-XSS-Protection: Legacy but still useful for older browsers
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());

    // Referrer-Policy: Don't send referrer for cross-origin requests
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Permissions-Policy: Disable unnecessary browser features
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()"
            .parse()
            .unwrap(),
    );

    // Strict-Transport-Security: Force HTTPS (1 year, include subdomains)
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );

    // Cache-Control: Prevent caching of API responses containing sensitive data
    headers.insert(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, proxy-revalidate"
            .parse()
            .unwrap(),
    );

    // Pragma: Legacy no-cache for HTTP/1.0 compatibility
    headers.insert("Pragma", "no-cache".parse().unwrap());

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
            .layer(from_fn(security_headers_middleware));

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
    async fn test_security_headers_csp_value() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(security_headers_middleware));

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
    async fn test_security_headers_hsts_value() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(security_headers_middleware));

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
    async fn test_security_headers_cache_control() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn(security_headers_middleware));

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
}
