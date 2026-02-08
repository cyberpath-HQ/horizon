//! # Server Utility Tests
//!
//! Tests for server utility functions and data transformation.

#[cfg(test)]
mod server_utils_tests {
    #[test]
    fn test_cuid_generation() {
        // Test that CUID values are generated correctly
        let id1 = cuid2::cuid();
        let id2 = cuid2::cuid();

        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
        assert_ne!(id1, id2, "CUIDs should be unique");
    }

    #[test]
    fn test_blake3_hashing() {
        let data = b"test data";
        let hash1 = blake3::hash(data).to_hex().to_string();
        let hash2 = blake3::hash(data).to_hex().to_string();

        assert_eq!(hash1, hash2, "Same data should produce same hash");
        assert_eq!(hash1.len(), 64, "BLAKE3 hex should be 64 characters");
    }

    #[test]
    fn test_blake3_different_inputs() {
        let hash1 = blake3::hash(b"data1").to_hex().to_string();
        let hash2 = blake3::hash(b"data2").to_hex().to_string();

        assert_ne!(
            hash1, hash2,
            "Different data should produce different hashes"
        );
    }

    #[test]
    fn test_timestamp_generation() {
        let now1 = chrono::Utc::now();
        let now2 = chrono::Utc::now();

        assert!(now2 >= now1, "Later timestamp should be >= earlier");
    }

    #[test]
    fn test_http_status_codes() {
        // Verify common HTTP status codes
        assert_eq!(200, axum::http::StatusCode::OK.as_u16());
        assert_eq!(201, axum::http::StatusCode::CREATED.as_u16());
        assert_eq!(204, axum::http::StatusCode::NO_CONTENT.as_u16());
        assert_eq!(400, axum::http::StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(401, axum::http::StatusCode::UNAUTHORIZED.as_u16());
        assert_eq!(403, axum::http::StatusCode::FORBIDDEN.as_u16());
        assert_eq!(404, axum::http::StatusCode::NOT_FOUND.as_u16());
        assert_eq!(500, axum::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16());
    }
}

#[cfg(test)]
mod dto_tests {
    use serde_json::json;

    #[test]
    fn test_json_serialization() {
        let json_data = json!({
            "id": "test-id",
            "name": "Test Name",
            "email": "test@example.com"
        });

        assert_eq!(json_data["id"], "test-id");
        assert_eq!(json_data["name"], "Test Name");
    }

    #[test]
    fn test_json_deserialization() {
        let json_str = r#"{"id":"123","name":"Test"}"#;
        let data: serde_json::Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(data["id"], "123");
        assert_eq!(data["name"], "Test");
    }

    #[test]
    fn test_json_null_values() {
        let json_data = json!({
            "id": "test-id",
            "description": null
        });

        assert_eq!(json_data["id"], "test-id");
        assert!(json_data["description"].is_null());
    }

    #[test]
    fn test_json_array_handling() {
        let json_data = json!({
            "roles": ["admin", "user", "viewer"]
        });

        let roles = json_data["roles"].as_array().unwrap();
        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0], "admin");
    }
}

#[cfg(test)]
mod validation_tests {
    use validator::Validate;

    #[derive(Validate)]
    struct TestUser {
        #[validate(email)]
        email: String,

        #[validate(length(min = 3, max = 50))]
        username: String,
    }

    #[test]
    fn test_email_validation() {
        let valid_user = TestUser {
            email:    "test@example.com".to_string(),
            username: "testuser".to_string(),
        };

        assert!(valid_user.validate().is_ok());
    }

    #[test]
    fn test_invalid_email() {
        let invalid_user = TestUser {
            email:    "not-an-email".to_string(),
            username: "testuser".to_string(),
        };

        assert!(invalid_user.validate().is_err());
    }

    #[test]
    fn test_username_length_validation() {
        let invalid_user = TestUser {
            email:    "test@example.com".to_string(),
            username: "ab".to_string(), // Too short
        };

        assert!(invalid_user.validate().is_err());
    }
}

#[cfg(test)]
mod error_mapping_tests {
    #[test]
    fn test_error_to_status_code() {
        // Test basic error mapping
        let not_found_code = axum::http::StatusCode::NOT_FOUND;
        let unauthorized_code = axum::http::StatusCode::UNAUTHORIZED;
        let internal_error_code = axum::http::StatusCode::INTERNAL_SERVER_ERROR;

        assert_eq!(not_found_code.as_u16(), 404);
        assert_eq!(unauthorized_code.as_u16(), 401);
        assert_eq!(internal_error_code.as_u16(), 500);
    }

    #[test]
    fn test_error_message_formatting() {
        let message = "Test error message";
        let formatted = format!("Error: {}", message);

        assert!(formatted.contains("Error"));
        assert!(formatted.contains(message));
    }
}
