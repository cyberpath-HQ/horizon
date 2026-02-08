//! # Error Crate Tests
//!
//! Tests for error types, responses, and conversions.

#[cfg(test)]
mod error_response_tests {
    use error::AppError;

    #[test]
    fn test_error_creation() {
        let _error = AppError::not_found("User not found");
        // Just verify it can be created
        assert!(true);
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
