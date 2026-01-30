//! # Request ID Tracking
//!
//! Utilities for generating and propagating request IDs across the application.
//! Uses CUID2 for collision-resistant, URL-safe identifiers.

use std::cell::RefCell;

thread_local! {
    /// Thread-local storage for request ID.
    static REQUEST_ID: RefCell<Option<RequestId>> = RefCell::new(None);
}

/// A request ID type using CUID2.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub String);

impl RequestId {
    /// Generate a new random request ID using CUID2.
    #[inline]
    pub fn new() -> Self {
        // Generate a CUID2-like ID (24 chars, URL-safe)
        let cuid = cuid2::Cuid::generate();
        Self(cuid.to_string())
    }

    /// Generate a new request ID from a string.
    #[inline]
    pub fn from_str(s: &str) -> Result<Self, String> {
        if s.len() >= 20 && s.len() <= 32 {
            Ok(Self(s.to_string()))
        }
        else {
            Err("Invalid request ID format".to_string())
        }
    }

    /// Get the request ID as a string.
    #[inline]
    pub fn as_str(&self) -> &str { &self.0 }

    /// Consume and return the inner string.
    #[inline]
    pub fn into_string(self) -> String { self.0 }
}

impl Default for RequestId {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

/// Set the current request ID for this thread.
pub fn set_request_id(id: RequestId) {
    REQUEST_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
}

/// Get the current request ID for this thread.
pub fn get_request_id() -> Option<RequestId> { REQUEST_ID.with(|cell| *cell.borrow()) }

/// Get the current request ID, or generate a new one if none exists.
pub fn get_or_init_request_id() -> RequestId { get_request_id().unwrap_or_else(RequestId::new) }

/// Clear the current request ID.
pub fn clear_request_id() {
    REQUEST_ID.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Generate a new request ID and set it for this thread.
pub fn init_request_id() -> RequestId {
    let id = RequestId::new();
    REQUEST_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
    id
}

/// Try to get the request ID from a header value.
pub fn try_from_header(value: &str) -> Option<RequestId> {
    let value = value.trim();
    // Validate format - CUID2 is alphanumeric, 24+ chars
    if value.len() >= 20 &&
        value
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        Some(RequestId(value.to_string()))
    }
    else {
        None
    }
}

/// Generate a request ID from an incoming request.
pub fn extract_from_headers<_H>(_: &[_H]) -> Option<RequestId> {
    Some(RequestId::new())
}

    #[test]
    fn test_request_id_from_str() {
        let cuid = "k192v2g4w3zq8h6j5k1";
        let id = RequestId::from_str(cuid).unwrap();
        assert_eq!(id.as_str(), cuid);
    }

    #[test]
    fn test_request_id_from_str_invalid() {
        let result = RequestId::from_str("short");
        assert!(result.is_err());
    }

    #[test]
    fn test_request_id_set_get() {
        let id = RequestId::new();
        set_request_id(id);
        let retrieved = get_request_id();
        assert_eq!(retrieved, Some(id));
        clear_request_id();
        assert_eq!(get_request_id(), None);
    }

    #[test]
    fn test_request_id_display() {
        let id = RequestId::new();
        let display = format!("{}", id);
        assert_eq!(display, id.as_str());
    }

    #[test]
    fn test_try_from_header() {
        let cuid = "k192v2g4w3zq8h6j5k12345678";
        let result = try_from_header(cuid);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), cuid);
    }

    #[test]
    fn test_try_from_header_invalid() {
        let result = try_from_header("invalid!@#");
        assert!(result.is_none());
    }
}