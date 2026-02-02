//! # Error Codes
//!
//! Structured error codes for the Horizon application.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Error categories for grouping errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Client,
    Server,
    Authentication,
    Authorization,
    Validation,
    Database,
    External,
}

/// Error code trait.
pub trait ErrorCode: fmt::Display {
    fn code(&self) -> &'static str;
    fn status(&self) -> http::StatusCode;
    fn category(&self) -> ErrorCategory;
    fn should_log(&self) -> bool;
    fn expose_details(&self) -> bool;
}

// ============================================================================
// Not Found Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct NotFound {
    resource:   String,
    identifier: Option<String>,
}

impl NotFound {
    pub fn new(resource: impl ToString) -> Self {
        Self {
            resource:   resource.to_string(),
            identifier: None,
        }
    }

    pub fn with_identifier(mut self, identifier: impl ToString) -> Self {
        self.identifier = Some(identifier.to_string());
        self
    }
}

impl ErrorCode for NotFound {
    fn code(&self) -> &'static str { "NOT_FOUND" }

    fn status(&self) -> http::StatusCode { http::StatusCode::NOT_FOUND }

    fn category(&self) -> ErrorCategory { ErrorCategory::Client }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { true }
}

impl fmt::Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(id) = &self.identifier {
            write!(f, "{} '{}' not found", self.resource, id)
        }
        else {
            write!(f, "{} not found", self.resource)
        }
    }
}

impl std::error::Error for NotFound {}

// ============================================================================
// Bad Request Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct BadRequest {
    message: String,
    field:   Option<String>,
}

impl BadRequest {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            field:   None,
        }
    }

    pub fn with_field(mut self, field: impl ToString) -> Self {
        self.field = Some(field.to_string());
        self
    }
}

impl ErrorCode for BadRequest {
    fn code(&self) -> &'static str { "BAD_REQUEST" }

    fn status(&self) -> http::StatusCode { http::StatusCode::BAD_REQUEST }

    fn category(&self) -> ErrorCategory { ErrorCategory::Client }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { true }
}

impl fmt::Display for BadRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.message) }
}

impl std::error::Error for BadRequest {}

// ============================================================================
// Validation Errors
// ============================================================================

/// A single validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field:   String,
    pub message: String,
    pub code:    Option<String>,
}

impl ValidationError {
    pub fn new(field: impl ToString, message: impl ToString) -> Self {
        Self {
            field:   field.to_string(),
            message: message.to_string(),
            code:    None,
        }
    }

    pub fn with_code(mut self, code: impl ToString) -> Self {
        self.code = Some(code.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct Validation {
    errors: Vec<ValidationError>,
}

impl Validation {
    pub fn new(errors: Vec<ValidationError>) -> Self {
        Self {
            errors,
        }
    }

    pub fn add_error(&mut self, error: ValidationError) { self.errors.push(error); }

    pub fn into_errors(self) -> Vec<ValidationError> { self.errors }
}

impl ErrorCode for Validation {
    fn code(&self) -> &'static str { "VALIDATION_ERROR" }

    fn status(&self) -> http::StatusCode { http::StatusCode::UNPROCESSABLE_ENTITY }

    fn category(&self) -> ErrorCategory { ErrorCategory::Validation }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { true }
}

impl fmt::Display for Validation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validation failed: {} errors", self.errors.len())
    }
}

impl std::error::Error for Validation {}

// ============================================================================
// Unauthorized Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnauthorizedReason {
    InvalidToken,
    ExpiredToken,
    MissingToken,
    InvalidCredentials,
    MfaRequired,
    MfaInvalid,
}

impl fmt::Display for UnauthorizedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnauthorizedReason::InvalidToken => write!(f, "invalid_token"),
            UnauthorizedReason::ExpiredToken => write!(f, "expired_token"),
            UnauthorizedReason::MissingToken => write!(f, "missing_token"),
            UnauthorizedReason::InvalidCredentials => write!(f, "invalid_credentials"),
            UnauthorizedReason::MfaRequired => write!(f, "mfa_required"),
            UnauthorizedReason::MfaInvalid => write!(f, "mfa_invalid"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Unauthorized {
    message: String,
    reason:  Option<UnauthorizedReason>,
}

impl Unauthorized {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            reason:  None,
        }
    }

    pub fn with_reason(mut self, reason: UnauthorizedReason) -> Self {
        self.reason = Some(reason);
        self
    }
}

impl ErrorCode for Unauthorized {
    fn code(&self) -> &'static str { "UNAUTHORIZED" }

    fn status(&self) -> http::StatusCode { http::StatusCode::UNAUTHORIZED }

    fn category(&self) -> ErrorCategory { ErrorCategory::Authentication }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { false }
}

impl fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(reason) = &self.reason {
            write!(f, "{} (reason: {})", self.message, reason)
        }
        else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Unauthorized {}

// ============================================================================
// Forbidden Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct Forbidden {
    message: String,
    action:  Option<String>,
}

impl Forbidden {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            action:  None,
        }
    }

    pub fn with_action(mut self, action: impl ToString) -> Self {
        self.action = Some(action.to_string());
        self
    }
}

impl ErrorCode for Forbidden {
    fn code(&self) -> &'static str { "FORBIDDEN" }

    fn status(&self) -> http::StatusCode { http::StatusCode::FORBIDDEN }

    fn category(&self) -> ErrorCategory { ErrorCategory::Authorization }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { false }
}

impl fmt::Display for Forbidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(action) = &self.action {
            write!(f, "{} (action: {})", self.message, action)
        }
        else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Forbidden {}

// ============================================================================
// Conflict Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct Conflict {
    message:       String,
    resource_type: Option<String>,
    existing_id:   Option<String>,
}

impl Conflict {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message:       message.to_string(),
            resource_type: None,
            existing_id:   None,
        }
    }

    pub fn with_resource_type(mut self, resource_type: impl ToString) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self
    }

    pub fn with_existing_id(mut self, id: impl ToString) -> Self {
        self.existing_id = Some(id.to_string());
        self
    }
}

impl ErrorCode for Conflict {
    fn code(&self) -> &'static str { "CONFLICT" }

    fn status(&self) -> http::StatusCode { http::StatusCode::CONFLICT }

    fn category(&self) -> ErrorCategory { ErrorCategory::Client }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { true }
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(id) = &self.existing_id {
            write!(f, "{} (existing_id: {})", self.message, id)
        }
        else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Conflict {}

// ============================================================================
// Rate Limit Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct RateLimit {
    retry_after: u64,
    limit:       Option<u64>,
}

impl RateLimit {
    pub fn new(retry_after: u64) -> Self {
        Self {
            retry_after,
            limit: None,
        }
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn retry_after(&self) -> u64 { self.retry_after }
}

impl ErrorCode for RateLimit {
    fn code(&self) -> &'static str { "RATE_LIMIT_EXCEEDED" }

    fn status(&self) -> http::StatusCode { http::StatusCode::TOO_MANY_REQUESTS }

    fn category(&self) -> ErrorCategory { ErrorCategory::Client }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { true }
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rate limit exceeded. Retry after {} seconds",
            self.retry_after
        )
    }
}

impl std::error::Error for RateLimit {}

// ============================================================================
// Internal Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct Internal {
    message:  String,
    error_id: Option<String>,
}

impl Internal {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message:  message.to_string(),
            error_id: None,
        }
    }

    pub fn with_error_id(mut self, error_id: impl ToString) -> Self {
        self.error_id = Some(error_id.to_string());
        self
    }
}

impl ErrorCode for Internal {
    fn code(&self) -> &'static str { "INTERNAL_ERROR" }

    fn status(&self) -> http::StatusCode { http::StatusCode::INTERNAL_SERVER_ERROR }

    fn category(&self) -> ErrorCategory { ErrorCategory::Server }

    fn should_log(&self) -> bool { true }

    fn expose_details(&self) -> bool { false }
}

impl fmt::Display for Internal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(id) = &self.error_id {
            write!(f, "{} (error_id: {})", self.message, id)
        }
        else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Internal {}

// ============================================================================
// Database Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct Database {
    message: String,
    query:   Option<String>,
}

impl Database {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            query:   None,
        }
    }

    pub fn with_query(mut self, query: impl ToString) -> Self {
        self.query = Some(query.to_string());
        self
    }
}

impl ErrorCode for Database {
    fn code(&self) -> &'static str { "DATABASE_ERROR" }

    fn status(&self) -> http::StatusCode { http::StatusCode::INTERNAL_SERVER_ERROR }

    fn category(&self) -> ErrorCategory { ErrorCategory::Database }

    fn should_log(&self) -> bool { true }

    fn expose_details(&self) -> bool { false }
}

impl fmt::Display for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Database error: {}", self.message) }
}

impl std::error::Error for Database {}

// ============================================================================
// IO Errors
// ============================================================================

#[derive(Debug, Clone)]
pub struct Io {
    message: String,
    path:    Option<String>,
}

impl Io {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            path:    None,
        }
    }

    pub fn with_path(mut self, path: impl ToString) -> Self {
        self.path = Some(path.to_string());
        self
    }
}

impl ErrorCode for Io {
    fn code(&self) -> &'static str { "IO_ERROR" }

    fn status(&self) -> http::StatusCode { http::StatusCode::INTERNAL_SERVER_ERROR }

    fn category(&self) -> ErrorCategory { ErrorCategory::Server }

    fn should_log(&self) -> bool { false }

    fn expose_details(&self) -> bool { false }
}

impl fmt::Display for Io {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{} (path: {})", self.message, path)
        }
        else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Io {}

#[cfg(test)]
mod tests {
    use super::*;

    // NotFound Tests
    #[test]
    fn test_not_found_new() {
        let err = NotFound::new("User");
        assert_eq!(err.code(), "NOT_FOUND");
        assert_eq!(err.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(err.category(), ErrorCategory::Client);
        assert!(!err.should_log());
        assert!(err.expose_details());
        assert_eq!(format!("{}", err), "User not found");
    }

    #[test]
    fn test_not_found_with_identifier() {
        let err = NotFound::new("User").with_identifier("123");
        assert_eq!(format!("{}", err), "User '123' not found");
    }

    // BadRequest Tests
    #[test]
    fn test_bad_request_new() {
        let err = BadRequest::new("Invalid input");
        assert_eq!(err.code(), "BAD_REQUEST");
        assert_eq!(err.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(err.category(), ErrorCategory::Client);
        assert!(!err.should_log());
        assert!(err.expose_details());
        assert_eq!(format!("{}", err), "Bad request: Invalid input");
    }

    #[test]
    fn test_bad_request_with_field() {
        let err = BadRequest::new("Required").with_field("email");
        assert_eq!(format!("{}", err), "Bad request: Required (field: email)");
    }

    // Unauthorized Tests
    #[test]
    fn test_unauthorized_new() {
        let err = Unauthorized::new("Token expired");
        assert_eq!(err.code(), "UNAUTHORIZED");
        assert_eq!(err.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.category(), ErrorCategory::Authentication);
        assert!(!err.should_log());
        assert!(err.expose_details());
    }

    #[test]
    fn test_unauthorized_with_reason() {
        let err = Unauthorized::new("Invalid").with_reason(UnauthorizedReason::ExpiredToken);
        assert_eq!(
            format!("{}", err),
            "Unauthorized: Invalid (reason: expired_token)"
        );
    }

    // Forbidden Tests
    #[test]
    fn test_forbidden_new() {
        let err = Forbidden::new("Access denied");
        assert_eq!(err.code(), "FORBIDDEN");
        assert_eq!(err.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(err.category(), ErrorCategory::Authorization);
        assert!(!err.should_log());
        assert!(err.expose_details());
    }

    #[test]
    fn test_forbidden_with_action() {
        let err = Forbidden::new("No permission").with_action("delete");
        assert_eq!(
            format!("{}", err),
            "Forbidden: No permission (action: delete)"
        );
    }

    // Conflict Tests
    #[test]
    fn test_conflict_new() {
        let err = Conflict::new("Duplicate entry");
        assert_eq!(err.code(), "CONFLICT");
        assert_eq!(err.status(), http::StatusCode::CONFLICT);
        assert_eq!(err.category(), ErrorCategory::Client);
        assert!(!err.should_log());
        assert!(err.expose_details());
    }

    #[test]
    fn test_conflict_with_existing_id() {
        let err = Conflict::new("User exists").with_existing_id("user-123");
        assert_eq!(
            format!("{}", err),
            "Conflict: User exists (existing_id: user-123)"
        );
    }

    // Validation Tests
    #[test]
    fn test_validation_new() {
        let err = Validation::new(vec![ValidationError::new("email", "Invalid format")]);
        assert_eq!(err.code(), "VALIDATION_ERROR");
        assert_eq!(err.status(), http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(err.category(), ErrorCategory::Validation);
        assert!(!err.should_log());
        assert!(err.expose_details());
    }

    #[test]
    fn test_validation_add_error() {
        let mut err = Validation::new(vec![]);
        err.add_error(ValidationError::new("name", "Required"));
        let errors = err.into_errors();
        assert_eq!(errors.len(), 1);
    }

    // RateLimit Tests
    #[test]
    fn test_rate_limit_new() {
        let err = RateLimit::new(60);
        assert_eq!(err.code(), "RATE_LIMIT");
        assert_eq!(err.status(), http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.category(), ErrorCategory::Client);
        assert!(err.should_log());
        assert!(!err.expose_details());
        assert_eq!(err.retry_after(), 60);
    }

    // Internal Tests
    #[test]
    fn test_internal_new() {
        let err = Internal::new("Something went wrong");
        assert_eq!(err.code(), "INTERNAL_ERROR");
        assert_eq!(err.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.category(), ErrorCategory::Server);
        assert!(err.should_log());
        assert!(!err.expose_details());
    }

    #[test]
    fn test_internal_with_error_id() {
        let err = Internal::new("Failed").with_error_id("ERR-001");
        assert_eq!(
            format!("{}", err),
            "Internal error: Failed (error_id: ERR-001)"
        );
    }

    // Database Tests
    #[test]
    fn test_database_new() {
        let err = Database::new("Connection failed");
        assert_eq!(err.code(), "DATABASE_ERROR");
        assert_eq!(err.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.category(), ErrorCategory::Database);
        assert!(err.should_log());
        assert!(!err.expose_details());
    }

    #[test]
    fn test_database_with_query() {
        let err = Database::new("Query failed").with_query("SELECT * FROM users");
        assert_eq!(
            format!("{}", err),
            "Database error: Connection failed (query: SELECT * FROM users)"
        );
    }

    // Io Tests
    #[test]
    fn test_io_new() {
        let err = Io::new("File not found");
        assert_eq!(err.code(), "IO_ERROR");
        assert_eq!(err.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.category(), ErrorCategory::Server);
        assert!(err.should_log());
        assert!(!err.expose_details());
    }

    #[test]
    fn test_io_with_path() {
        let err = Io::new("Cannot read").with_path("/data/file.txt");
        assert_eq!(
            format!("{}", err),
            "IO error: Cannot read (path: /data/file.txt)"
        );
    }

    // ErrorCategory Tests
    #[test]
    fn test_error_category_values() {
        assert_eq!(ErrorCategory::Client, ErrorCategory::Client);
        assert_eq!(ErrorCategory::Server, ErrorCategory::Server);
        assert_eq!(ErrorCategory::Authentication, ErrorCategory::Authentication);
        assert_eq!(ErrorCategory::Authorization, ErrorCategory::Authorization);
        assert_eq!(ErrorCategory::Validation, ErrorCategory::Validation);
        assert_eq!(ErrorCategory::Database, ErrorCategory::Database);
        assert_eq!(ErrorCategory::External, ErrorCategory::External);
    }
}
