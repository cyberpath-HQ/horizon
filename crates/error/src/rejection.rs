//! # Rejection Handlers
//!
//! Custom rejection handlers for converting Axum rejections into API errors.

use axum::{
    extract::rejection::{JsonRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Handle JSON deserialization errors and convert them to proper API responses.
///
/// This handler catches errors like "missing field `username`" and returns them
/// in the standard API error format.
pub fn handle_json_rejection(rejection: JsonRejection) -> Response {
    // Get the error message from the rejection
    let error_message = rejection.to_string();

    // Try to extract a more user-friendly message
    let message = if error_message.contains("missing field") {
        // Extract field name from error message like "missing field `username` at line 1 column 2"
        if let Some(start) = error_message.find("missing field `") {
            if let Some(end) = error_message[start ..].find('`') {
                let field_name = &error_message[start + 15 .. start + end];
                format!("Missing required field: {}", field_name)
            }
            else {
                error_message
            }
        }
        else {
            error_message
        }
    }
    else {
        error_message
    };

    let error_response = json!({
        "success": false,
        "code": "BAD_REQUEST",
        "message": message
    });

    (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
}

/// Handle query string deserialization errors and convert them to proper API responses.
pub fn handle_query_rejection(rejection: QueryRejection) -> Response {
    let error_message = format!("Query string deserialization error: {}", rejection);

    let error_response = json!({
        "success": false,
        "code": "BAD_REQUEST",
        "message": error_message
    });

    (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_rejection_response_format() {
        // This would require creating a JsonRejection which is complex in tests
        // The function is tested indirectly through integration tests
        let _ = handle_json_rejection;
        let _ = handle_query_rejection;
    }
}
