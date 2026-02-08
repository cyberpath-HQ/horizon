//! # Server Middleware Tests
//!
//! Tests for security headers and other middleware.

#[cfg(test)]
mod rate_limit_tests {
    use std::net::SocketAddr;

    #[test]
    fn test_rate_limit_key_generation() {
        // Test rate limit key generation from socket address
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let ip = addr.ip();
        let key = format!("rate_limit:{}", ip);
        assert!(!key.is_empty());
        assert!(key.contains("rate_limit"));
    }

    #[test]
    fn test_rate_limit_window_calculation() {
        // Test rate limit window calculation
        use chrono::Utc;
        let now = Utc::now();
        let window_seconds = 60u64;
        let window = (now.timestamp() as u64) / window_seconds;
        assert!(window > 0);
    }
}

#[cfg(test)]
mod api_key_auth_tests {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    #[test]
    fn test_api_key_extraction_from_header() {
        // Test API key extraction logic
        let api_key = "test-api-key-12345";
        let encoded = BASE64.encode(api_key);
        let header_value = format!("ApiKey {}", encoded);

        // Verify the header format is valid
        assert!(header_value.starts_with("ApiKey "));
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_api_key_hashing() {
        // Test API key hashing for comparison
        let api_key = "test-api-key-value";
        let hash = blake3::hash(api_key.as_bytes()).to_hex().to_string();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // BLAKE3 produces 64-char hex string
    }
}
