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
    /// Create a new pagination meta.
    pub fn new(page: u64, per_page: u64, total_items: u64) -> Self {
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

    /// Calculate offset for database queries.
    pub fn offset(&self) -> u64 { (self.page - 1) * self.per_page }

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
/// let response = ApiResponse::ok()
///     .with_data(vec!["item1", "item2"])
///     .with_pagination(1, 10, 100);
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

impl<T> ApiResponseBuilder<T> {
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

        let data = self.data.unwrap_or_else(|| {
            // This panics if T doesn't implement Default, which is intentional
            panic!("ApiResponseBuilder: data not set")
        });

        let meta = self.meta;

        ApiResponse::Success {
            data,
            meta: Some(meta),
        }
    }
}

impl<T> Default for ApiResponseBuilder<T> {
    fn default() -> Self { Self::new() }
}

impl<T> ApiResponse<T> {
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
        let response = ApiResponse::error("NOT_FOUND", "Resource not found");
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
        assert_eq!(meta.offset(), 20);
        assert_eq!(meta.limit(), 10);
    }

    #[test]
    fn test_response_builder() {
        let response = ApiResponse::builder::<String>()
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
}
