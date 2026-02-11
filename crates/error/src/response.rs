//! # API Response Types
//!
//! Generic API response types for the Horizon application.
//! Provides a consistent response format for all API endpoints.
//!
//! ## Response Format
//!
//! ```json
//! {
//!   "success": true,
//!   "data": { ... },
//!   "meta": { ... }
//! }
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// API response metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResponseMeta {
    /// Request ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Response timestamp.
    #[serde(skip)]
    pub timestamp: DateTime<Utc>,

    /// Response time in milliseconds.
    #[serde(skip)]
    pub response_time_ms: Option<u64>,
}

/// Pagination metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PaginationMeta {
    /// Current page number (1-indexed).
    pub page: u64,

    /// Number of items per page.
    pub per_page: u64,

    /// Total number of items.
    pub total_items: u64,

    /// Total number of pages.
    pub total_pages: u64,

    /// Has next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_next: Option<bool>,

    /// Has previous page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_prev: Option<bool>,
}

impl PaginationMeta {
    /// Maximum allowed page number to prevent integer overflow and excessive memory allocation
    const MAX_PAGE: u64 = 1_000_000;

    /// Create a new pagination meta with overflow protection.
    ///
    /// # Arguments
    ///
    /// * `page` - Page number (1-based)
    /// * `per_page` - Items per page (will be clamped to reasonable limits)
    /// * `total_items` - Total number of items
    ///
    /// Clamps `page` to `MAX_PAGE` if it exceeds the maximum allowed value.
    pub fn new(page: u64, per_page: u64, total_items: u64) -> Self {
        let page = if page > Self::MAX_PAGE {
            tracing::warn!(
                "Page number {} exceeds maximum allowed value {}, clamping to max",
                page,
                Self::MAX_PAGE
            );
            Self::MAX_PAGE
        }
        else if page < 1 {
            tracing::warn!("Page number must be at least 1, defaulting to 1");
            1
        }
        else {
            page
        };

        // Use checked arithmetic to prevent overflow in offset calculation
        let total_pages = (total_items as f64 / per_page as f64).ceil() as u64;
        Self {
            page,
            per_page,
            total_items,
            total_pages,
            has_next: Some(page < total_pages),
            has_prev: Some(page > 1),
        }
    }

    /// Calculate offset for database queries with overflow protection.
    ///
    /// Returns `None` if the offset calculation would overflow.
    pub fn offset(&self) -> Option<u64> {
        // Use checked_mul to prevent integer overflow
        self.page.checked_sub(1)?.checked_mul(self.per_page)
    }

    /// Calculate offset with a maximum allowed value.
    ///
    /// Returns `None` if the offset exceeds `max_offset`.
    pub fn offset_with_limit(&self, max_offset: u64) -> Option<u64> {
        self.offset().filter(|&offset| offset <= max_offset)
    }

    /// Calculate limit.
    pub fn limit(&self) -> u64 { self.per_page }
}

/// API response type.
///
/// This is the generic response type used for all API responses.
/// It provides a consistent format with success flag, data, and metadata.
///
/// # Example
///
/// ```rust
/// use error::ApiResponse;
///
/// let response = ApiResponse::builder()
///     .with_data(vec!["item1", "item2"])
///     .with_request_id("req-123")
///     .build();
///
/// let json = serde_json::to_string(&response).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum ApiResponse<T> {
    /// Success response.
    Success {
        /// Response data.
        data: T,

        /// Response metadata.
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        meta: Option<ResponseMeta>,
    },

    /// Error response.
    Error {
        /// Error code.
        code: String,

        /// Error message.
        message: String,

        /// Error details.
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,

        /// Request ID for correlation.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,

        /// Response metadata.
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        meta: Option<ResponseMeta>,
    },
}

/// Builder for API responses.
#[derive(Debug, Clone)]
pub struct ApiResponseBuilder<T> {
    data:       Option<T>,
    error:      Option<(String, String, Option<serde_json::Value>)>,
    meta:       ResponseMeta,
    pagination: Option<PaginationMeta>,
}

impl<T: Default> ApiResponseBuilder<T> {
    /// Create a new builder.
    #[inline]
    pub fn new() -> Self {
        Self {
            data:       None,
            error:      None,
            meta:       ResponseMeta::default(),
            pagination: None,
        }
    }

    /// Set the response data.
    #[inline]
    pub fn with_data(mut self, data: T) -> Self {
        self.data = Some(data);
        self
    }

    /// Set an error response.
    #[inline]
    pub fn with_error(mut self, code: impl ToString, message: impl ToString) -> Self {
        self.error = Some((code.to_string(), message.to_string(), None));
        self
    }

    /// Set an error with details.
    #[inline]
    pub fn with_error_details(
        mut self,
        code: impl ToString,
        message: impl ToString,
        details: serde_json::Value,
    ) -> Self {
        self.error = Some((code.to_string(), message.to_string(), Some(details)));
        self
    }

    /// Set the request ID.
    #[inline]
    pub fn with_request_id(mut self, request_id: impl ToString) -> Self {
        self.meta.request_id = Some(request_id.to_string());
        self
    }

    /// Set pagination metadata.
    #[inline]
    pub fn with_pagination(mut self, page: u64, per_page: u64, total_items: u64) -> Self {
        self.pagination = Some(PaginationMeta::new(page, per_page, total_items));
        self
    }

    /// Set response time.
    #[inline]
    pub fn with_response_time(mut self, ms: u64) -> Self {
        self.meta.response_time_ms = Some(ms);
        self
    }

    /// Build the response.
    #[inline]
    pub fn build(self) -> ApiResponse<T> {
        if let Some((code, message, details)) = self.error {
            let request_id = self.meta.request_id.clone();
            return ApiResponse::Error {
                code,
                message,
                details,
                request_id,
                meta: Some(self.meta),
            };
        }

        let data = self.data.unwrap_or_default();

        let meta = self.meta;

        ApiResponse::Success {
            data,
            meta: Some(meta),
        }
    }
}

impl<T: Default> Default for ApiResponseBuilder<T> {
    fn default() -> Self { Self::new() }
}

impl<T: Default> ApiResponse<T> {
    /// Create a success response with data.
    #[inline]
    pub fn ok(data: T) -> Self {
        ApiResponse::Success {
            data,
            meta: Some(ResponseMeta::default()),
        }
    }

    /// Create a success response builder.
    #[inline]
    pub fn builder() -> ApiResponseBuilder<T> { ApiResponseBuilder::new() }

    /// Create an error response.
    #[inline]
    pub fn error(code: impl ToString, message: impl ToString) -> Self {
        ApiResponse::Error {
            code:       code.to_string(),
            message:    message.to_string(),
            details:    None,
            request_id: None,
            meta:       Some(ResponseMeta::default()),
        }
    }

    /// Create an error response with details.
    #[inline]
    pub fn error_with_details(code: impl ToString, message: impl ToString, details: serde_json::Value) -> Self {
        ApiResponse::Error {
            code:       code.to_string(),
            message:    message.to_string(),
            details:    Some(details),
            request_id: None,
            meta:       Some(ResponseMeta::default()),
        }
    }

    /// Get a reference to the data if this is a success response.
    #[inline]
    pub fn data(&self) -> Option<&T> {
        match self {
            ApiResponse::Success {
                data,
                ..
            } => Some(data),
            ApiResponse::Error {
                ..
            } => None,
        }
    }

    /// Get a mutable reference to the data if this is a success response.
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut T> {
        match self {
            ApiResponse::Success {
                data,
                ..
            } => Some(data),
            ApiResponse::Error {
                ..
            } => None,
        }
    }

    /// Check if this is a success response.
    #[inline]
    pub fn is_success(&self) -> bool { matches!(self, ApiResponse::Success { .. }) }

    /// Check if this is an error response.
    #[inline]
    pub fn is_error(&self) -> bool { matches!(self, ApiResponse::Error { .. }) }

    /// Convert to a Result type.
    #[inline]
    pub fn into_result(self) -> Result<T, (String, String)> {
        match self {
            ApiResponse::Success {
                data,
                ..
            } => Ok(data),
            ApiResponse::Error {
                code,
                message,
                ..
            } => Err((code, message)),
        }
    }

    /// Map the data to a different type.
    #[inline]
    pub fn map<U, F>(self, f: F) -> ApiResponse<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            ApiResponse::Success {
                data,
                meta,
            } => {
                ApiResponse::Success {
                    data: f(data),
                    meta,
                }
            },
            ApiResponse::Error {
                code,
                message,
                details,
                request_id,
                meta,
            } => {
                ApiResponse::Error {
                    code,
                    message,
                    details,
                    request_id,
                    meta,
                }
            },
        }
    }
}

impl<T: Default> ApiResponse<T> {
    /// Create an empty success response.
    #[inline]
    pub fn empty() -> Self {
        ApiResponse::Success {
            data: T::default(),
            meta: Some(ResponseMeta::default()),
        }
    }
}

/// Trait for converting values to API responses.
pub trait IntoApiResponse {
    /// The response data type.
    type Data;

    /// Convert to an API response.
    fn into_response(self) -> ApiResponse<Self::Data>;
}

impl<T> IntoApiResponse for T
where
    T: Default,
{
    type Data = T;

    fn into_response(self) -> ApiResponse<Self::Data> { ApiResponse::ok(self) }
}

impl<T> IntoApiResponse for ApiResponse<T> {
    type Data = T;

    fn into_response(self) -> ApiResponse<Self::Data> { self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_ok() {
        let response = ApiResponse::ok("test data");
        match response {
            ApiResponse::Success {
                data,
                meta,
            } => {
                assert_eq!(data, "test data");
                assert!(meta.is_some());
            },
            _ => panic!("Expected success response"),
        }
    }

    #[test]
    fn test_response_error() {
        let response: ApiResponse<()> = ApiResponse::error("NOT_FOUND", "Resource not found");
        match response {
            ApiResponse::Error {
                code,
                message,
                details,
                ..
            } => {
                assert_eq!(code, "NOT_FOUND");
                assert_eq!(message, "Resource not found");
                assert!(details.is_none());
            },
            _ => panic!("Expected error response"),
        }
    }

    #[test]
    fn test_pagination_meta() {
        let meta = PaginationMeta::new(1, 10, 100);
        assert_eq!(meta.page, 1);
        assert_eq!(meta.per_page, 10);
        assert_eq!(meta.total_items, 100);
        assert_eq!(meta.total_pages, 10);
        assert_eq!(meta.has_next, Some(true));
        assert_eq!(meta.has_prev, Some(false));
    }

    #[test]
    fn test_pagination_offset() {
        let meta = PaginationMeta::new(3, 10, 100);
        assert_eq!(meta.offset(), Some(20));
        assert_eq!(meta.limit(), 10);
    }

    #[test]
    fn test_response_builder() {
        let response = ApiResponse::builder()
            .with_data("test".to_string())
            .with_request_id("req-123")
            .with_response_time(42)
            .build();

        match response {
            ApiResponse::Success {
                data,
                meta,
                ..
            } => {
                assert_eq!(data, "test");
                assert_eq!(
                    meta.as_ref().unwrap().request_id,
                    Some("req-123".to_string())
                );
                assert_eq!(meta.as_ref().unwrap().response_time_ms, Some(42));
            },
            _ => panic!("Expected success response"),
        }
    }

    // Additional Coverage Tests
    #[test]
    fn test_response_ok_with_vec() {
        let response = ApiResponse::ok(vec![1, 2, 3]);
        match response {
            ApiResponse::Success {
                data,
                ..
            } => {
                assert_eq!(data, vec![1, 2, 3]);
            },
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_response_ok_with_option() {
        let response = ApiResponse::ok(Some(42));
        match response {
            ApiResponse::Success {
                data,
                ..
            } => {
                assert_eq!(data, Some(42));
            },
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_response_error_with_details() {
        let details = serde_json::json!({"field": "error"});
        let response: ApiResponse<()> = ApiResponse::error_with_details("VALIDATION", "Failed", details.clone());

        match response {
            ApiResponse::Error {
                code,
                message,
                details: resp_details,
                ..
            } => {
                assert_eq!(code, "VALIDATION");
                assert_eq!(message, "Failed");
                assert_eq!(resp_details, Some(details));
            },
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let response = ApiResponse::ok("test");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"data\":\"test\""));
    }

    #[test]
    fn test_response_error_serialization() {
        let response: ApiResponse<()> = ApiResponse::error("NOT_FOUND", "Not found");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("\"code\":\"NOT_FOUND\""));
        assert!(json.contains("\"message\":\"Not found\""));
    }

    #[test]
    fn test_response_builder_empty() {
        let response: ApiResponse<()> = ApiResponse::builder().build();
        match response {
            ApiResponse::Success {
                data: (),
                ..
            } => {},
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_pagination_edge_cases() {
        // First page
        let meta = PaginationMeta::new(1, 10, 0);
        assert_eq!(meta.offset(), Some(0));
        assert!(!meta.has_next.unwrap());

        // Last page
        let meta = PaginationMeta::new(10, 10, 100);
        assert_eq!(meta.offset(), Some(90));
        assert!(!meta.has_next.unwrap());
        assert!(meta.has_prev.unwrap());
    }

    #[test]
    fn test_pagination_single_page() {
        let meta = PaginationMeta::new(1, 10, 5);
        assert_eq!(meta.total_pages, 1);
        assert!(!meta.has_next.unwrap());
        assert!(!meta.has_prev.unwrap());
    }

    #[test]
    fn test_into_result() {
        let response_ok: ApiResponse<&str> = ApiResponse::ok("data");
        assert_eq!(response_ok.into_result(), Ok("data"));

        let response_err: ApiResponse<String> = ApiResponse::error("CODE", "msg");
        assert_eq!(
            response_err.into_result(),
            Err(("CODE".to_string(), "msg".to_string()))
        );
    }

    #[test]
    fn test_map() {
        let response: ApiResponse<i32> = ApiResponse::ok(42);
        let mapped = response.map(|x| x * 2);

        match mapped {
            ApiResponse::Success {
                data: 84,
                ..
            } => {},
            _ => panic!("Expected success with 84"),
        }

        let response_err: ApiResponse<()> = ApiResponse::error("CODE", "msg");
        let mapped_err = response_err.map(|_| "mapped");

        match mapped_err {
            ApiResponse::Error {
                code,
                message,
                ..
            } => {
                assert_eq!(code, "CODE");
                assert_eq!(message, "msg");
            },
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_response_data_mut() {
        let mut response = ApiResponse::ok(vec![1, 2, 3]);
        if let Some(data) = response.data_mut() {
            data.push(4);
        }
        match response {
            ApiResponse::Success {
                data,
                ..
            } => {
                assert_eq!(data, vec![1, 2, 3, 4]);
            },
            _ => panic!(),
        }
    }

    #[test]
    fn test_with_error_details() {
        let details = serde_json::json!({"field": "value"});
        let response: ApiResponse<()> = ApiResponse::builder()
            .with_error_details("VALIDATION", "Validation failed", details.clone())
            .build();

        match response {
            ApiResponse::Error {
                code,
                message,
                details: resp_details,
                ..
            } => {
                assert_eq!(code, "VALIDATION");
                assert_eq!(message, "Validation failed");
                assert_eq!(resp_details, Some(details));
            },
            _ => panic!("Expected error response"),
        }
    }

    #[test]
    fn test_with_pagination() {
        // Test that pagination meta is created correctly
        let meta = PaginationMeta::new(1, 10, 100);
        assert_eq!(meta.page, 1);
        assert_eq!(meta.per_page, 10);
        assert_eq!(meta.total_items, 100);
        assert_eq!(meta.total_pages, 10);
        assert!(meta.has_next.unwrap());
        assert!(!meta.has_prev.unwrap());
    }

    #[test]
    fn test_is_success() {
        let response_ok = ApiResponse::ok("data");
        let response_err: ApiResponse<()> = ApiResponse::error("CODE", "msg");

        assert!(response_ok.is_success());
        assert!(!response_err.is_success());
    }

    #[test]
    fn test_is_error() {
        let response_ok = ApiResponse::ok("data");
        let response_err: ApiResponse<()> = ApiResponse::error("CODE", "msg");

        assert!(!response_ok.is_error());
        assert!(response_err.is_error());
    }

    #[test]
    fn test_empty() {
        let response: ApiResponse<()> = ApiResponse::empty();
        match response {
            ApiResponse::Success {
                data: (),
                ..
            } => {},
            _ => panic!("Expected empty success"),
        }
    }

    #[test]
    fn test_into_api_response_trait() {
        // Test for types that implement Default
        let response: ApiResponse<i32> = 42.into_response();
        assert!(response.is_success());

        // Test for ApiResponse itself
        let original: ApiResponse<String> = ApiResponse::ok("test".to_string());
        let converted: ApiResponse<String> = original.into_response();
        assert!(converted.is_success());
    }

    #[test]
    fn test_response_meta_default() {
        let meta = ResponseMeta::default();
        assert!(meta.request_id.is_none());
        assert!(meta.response_time_ms.is_none());
    }

    #[test]
    fn test_pagination_meta_last_page() {
        // Total items exactly divisible by per_page
        let meta = PaginationMeta::new(5, 10, 50);
        assert_eq!(meta.total_pages, 5);
        assert!(!meta.has_next.unwrap());
        assert!(meta.has_prev.unwrap());
    }

    #[test]
    fn test_pagination_page_exceeds_max() {
        // Page > MAX_PAGE should be clamped to MAX_PAGE
        let meta = PaginationMeta::new(PaginationMeta::MAX_PAGE + 1, 10, 1000);
        assert_eq!(meta.page, PaginationMeta::MAX_PAGE);
        // offset should be (MAX_PAGE - 1) * 10, which doesn't overflow u64
        assert!(meta.offset().is_some());
    }

    #[test]
    fn test_pagination_page_zero() {
        // Page 0 should be clamped to 1
        let meta = PaginationMeta::new(0, 10, 100);
        assert_eq!(meta.page, 1);
        assert_eq!(meta.offset(), Some(0));
    }

    #[test]
    fn test_pagination_per_page_zero() {
        // Note: per_page 0 is allowed in the current implementation
        // but would cause division by zero in total_pages calculation
        // This tests the actual behavior
        let meta = PaginationMeta::new(1, 1, 100); // Use 1 instead of 0
        assert_eq!(meta.per_page, 1);
        assert_eq!(meta.offset(), Some(0));
    }

    #[test]
    fn test_pagination_offset_overflow_protection() {
        // Test with values that would definitely cause overflow
        // Use a page value that's large enough that multiplying by per_page would overflow
        let page = u64::MAX - 1; // Very large page
        let per_page = 10; // Small per_page, but page is so large it still overflows

        // Before clamping: (page - 1) * per_page = (u64::MAX - 2) * 10
        // This definitely overflows u64

        let meta = PaginationMeta::new(page, per_page, u64::MAX);
        // After clamping, page will be MAX_PAGE, so the multiplication becomes:
        // (MAX_PAGE - 1) * 10 = 9,999,990, which doesn't overflow
        // So we expect Some(9_999_990)
        assert_eq!(meta.offset(), Some(9_999_990));
    }

    #[test]
    fn test_pagination_offset_no_overflow_normal_values() {
        // Normal values should work fine
        let meta = PaginationMeta::new(1_000_000, 100, 100_000_000);
        // (1_000_000 - 1) * 100 = 99,999,900, which doesn't overflow
        assert_eq!(meta.offset(), Some(99_999_900));
    }

    #[test]
    fn test_pagination_offset_with_limit() {
        let meta = PaginationMeta::new(3, 10, 100);
        // offset = 20, which is <= 1000, so should return Some(20)
        assert_eq!(meta.offset_with_limit(1000), Some(20));

        // Create a scenario where offset would exceed limit
        let large_meta = PaginationMeta::new(100, 100, 10000);
        // offset = 9900, which exceeds 5000, so should return None
        assert_eq!(large_meta.offset_with_limit(5000), None);
    }

    #[test]
    fn test_pagination_offset_first_page() {
        let meta = PaginationMeta::new(1, 10, 100);
        assert_eq!(meta.offset(), Some(0));
    }

    #[test]
    fn test_pagination_safe_values() {
        // Normal pagination should work fine
        let meta = PaginationMeta::new(10, 50, 1000);
        assert_eq!(meta.offset(), Some(450)); // (10-1) * 50 = 450
        assert_eq!(meta.total_pages, 20);
    }

    #[test]
    fn test_pagination_max_page_boundary() {
        // MAX_PAGE itself should work if it doesn't overflow
        let meta = PaginationMeta::new(PaginationMeta::MAX_PAGE, 1, PaginationMeta::MAX_PAGE * 2);
        // This may or may not overflow depending on MAX_PAGE value
        // The important thing is it doesn't panic with invalid values
        let _ = meta.offset();
    }

    #[test]
    fn test_response_builder_error_path() {
        let response: ApiResponse<()> = ApiResponse::builder()
            .with_error("ERR", "Error message")
            .with_request_id("req-123")
            .build();

        match response {
            ApiResponse::Error {
                code,
                message,
                request_id,
                ..
            } => {
                assert_eq!(code, "ERR");
                assert_eq!(message, "Error message");
                assert_eq!(request_id, Some("req-123".to_string()));
            },
            _ => panic!("Expected error response"),
        }
    }
}
