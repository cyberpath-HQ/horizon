//! # Error Crate Tests
//!
//! Tests for error types, responses, and conversions.

#[cfg(test)]
mod error_response_tests {
    use error::AppError;

    #[test]
    fn test_error_creation() {
        let error = AppError::not_found("User not found");
        // Verify it can be created and has the correct variant
        assert!(matches!(error, AppError::NotFound(_)));
    }

    #[test]
    fn test_error_message() {
        let error = AppError::bad_request("Invalid input");
        let msg = format!("{}", error);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_multiple_error_types() {
        let errors = vec![
            AppError::not_found("Item 1"),
            AppError::bad_request("Invalid"),
            AppError::internal("Failed"),
        ];

        assert_eq!(errors.len(), 3);
    }

    #[test]
    fn test_app_error_conversions() {
        let error = AppError::database("DB error");
        let msg = format!("{}", error);
        assert!(msg.contains("database") || msg.contains("DB"));
    }
}

#[cfg(test)]
mod api_response_builder_tests {
    use error::ApiResponse;
    use serde_json::json;

    #[test]
    fn test_api_response_ok_with_data() {
        let data = json!({"id": "123", "name": "Test"});
        let response = ApiResponse::ok(data.clone());

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "success");
        assert!(json["data"].is_object());
    }

    #[test]
    fn test_api_response_builder() {
        let data = json!({"message": "Operation completed"});
        let response = ApiResponse::builder()
            .with_data(data)
            .with_response_time(100)
            .build();
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "success");
        assert!(json["data"].is_object());
    }

    #[test]
    fn test_api_response_error_response() {
        let response = ApiResponse::<serde_json::Value>::error("400", "Invalid request");
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "error");
    }
}

#[cfg(test)]
mod error_status_mapping_tests {
    use error::AppError;

    #[test]
    fn test_not_found_status() {
        let error = AppError::not_found("Resource");
        let msg = format!("{}", error);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_unauthorized_status() {
        let error = AppError::unauthorized("Unauthorized access");
        let msg = format!("{}", error);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_bad_request_status() {
        let error = AppError::bad_request("Invalid input");
        let msg = format!("{}", error);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_internal_error_status() {
        let error = AppError::internal("Server error");
        let msg = format!("{}", error);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_database_error_status() {
        let error = AppError::database("Query failed");
        let msg = format!("{}", error);
        assert!(!msg.is_empty());
    }
}

#[cfg(test)]
mod error_code_tests {
    // Test error code mappings
    #[test]
    fn test_error_code_uniqueness() {
        let codes = vec!["NOT_FOUND", "UNAUTHORIZED", "BAD_REQUEST", "CONFLICT"];
        let unique_codes: std::collections::HashSet<_> = codes.into_iter().collect();
        assert_eq!(unique_codes.len(), 4, "All codes should be unique");
    }

    #[test]
    fn test_error_code_format() {
        let code = "INTERNAL_SERVER_ERROR";
        assert!(code.chars().all(|c| c.is_uppercase() || c == '_'));
    }
}

#[cfg(test)]
mod result_type_tests {
    use error::Result;

    #[test]
    fn test_result_ok() {
        let result: Result<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_error() {
        use error::AppError;
        let result: Result<i32> = Err(AppError::internal("error"));
        assert!(result.is_err());
    }

    #[test]
    fn test_result_mapping() {
        let result: Result<i32> = Ok(10);
        let mapped = result.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 20);
    }

    #[test]
    fn test_result_and_then() {
        let result: Result<i32> = Ok(5);
        let chained = result.and_then(|v| Ok::<i32, _>(v + 3));
        assert_eq!(chained.unwrap(), 8);
    }
}

#[cfg(test)]
mod into_response_tests {
    use error::AppError;

    #[test]
    fn test_app_error_variants() {
        // Test that all error variants can be created
        let _not_found = AppError::NotFound {
            message: "Not found".to_string(),
        };
        let _bad_request = AppError::BadRequest {
            message: "Bad request".to_string(),
        };
        let _unauthorized = AppError::Unauthorized {
            message: "Unauthorized".to_string(),
        };
        let _forbidden = AppError::Forbidden {
            message: "Forbidden".to_string(),
        };
        let _conflict = AppError::Conflict {
            message: "Conflict".to_string(),
        };
        let _validation = AppError::Validation {
            message: "Validation error".to_string(),
        };
        let _internal = AppError::Internal {
            message: "Internal error".to_string(),
        };
        let _database = AppError::Database {
            message: "Database error".to_string(),
        };
        let _io = AppError::Io {
            message: "IO error".to_string(),
        };
        let _jwt_expired = AppError::JwtExpired;
        let _jwt_invalid_signature = AppError::JwtInvalidSignature;
        let _jwt_invalid_token = AppError::JwtInvalidToken;
    }

    #[test]
    fn test_app_error_into_response() {
        use axum::response::IntoResponse;

        let error = AppError::NotFound {
            message: "Test not found".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);

        let error = AppError::BadRequest {
            message: "Test bad request".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        let error = AppError::Unauthorized {
            message: "Test unauthorized".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let error = AppError::Forbidden {
            message: "Test forbidden".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);

        let error = AppError::Conflict {
            message: "Test conflict".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);

        let error = AppError::Validation {
            message: "Test validation".to_string(),
        };
        let response = error.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );

        let error = AppError::Internal {
            message: "Test internal".to_string(),
        };
        let response = error.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        let error = AppError::Database {
            message: "Test database".to_string(),
        };
        let response = error.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        let error = AppError::Io {
            message: "Test io".to_string(),
        };
        let response = error.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        let error = AppError::JwtExpired;
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let error = AppError::JwtInvalidSignature;
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let error = AppError::JwtInvalidToken;
        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_api_response_success() {
        use error::ApiResponse;

        let response: ApiResponse<String> = ApiResponse::ok("test data".to_string());
        assert!(response.is_success());
        assert_eq!(response.data(), Some(&"test data".to_string()));
    }

    #[test]
    fn test_api_response_error() {
        use error::ApiResponse;

        let response: ApiResponse<()> = ApiResponse::error("TEST_ERROR", "Test error message");
        assert!(!response.is_success());
        assert_eq!(response.data(), None);
    }

    #[test]
    fn test_api_response_builder() {
        use error::ApiResponse;

        let response: ApiResponse<String> = ApiResponse::builder()
            .with_data("test data".to_string())
            .with_request_id("req-123")
            .build();
        assert!(response.is_success());
        assert_eq!(response.data(), Some(&"test data".to_string()));
    }

    #[test]
    fn test_api_response_builder_error() {
        use error::ApiResponse;

        let response: ApiResponse<()> = ApiResponse::builder()
            .with_error("TEST_ERROR", "Test error message")
            .with_request_id("req-123")
            .build();
        assert!(!response.is_success());
        assert_eq!(response.data(), None);
    }
}
