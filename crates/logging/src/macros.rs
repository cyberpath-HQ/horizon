//! # Logging Macros
//!
//! Convenience macros for structured logging.
//! These macros provide additional metadata and structured fields.

/// Log with request ID and target.
///
/// # Example
///
/// ```rust
/// use logging::{info_with_request, RequestId};
///
/// let request_id = RequestId::new();
/// info_with_request!(target: "api", request_id, "Request processed", { duration_ms = 42 });
/// ```
#[macro_export]
macro_rules! info_with_request {
    (target: $target:expr, $request_id:expr, $($arg:tt)*) => {
        tracing::info!(target: $target, request_id = %$request_id, $($arg)*)
    };
    (target: $target:expr, $request_id:expr, $($arg:tt)*) => {
        tracing::info!(target: $target, request_id = %$request_id, $($arg)*)
    };
}

/// Log an error with request ID and error details.
#[macro_export]
macro_rules! error_with_request {
    (target: $target:expr, $request_id:expr, $err:expr, $($arg:tt)*) => {
        tracing::error!(target: $target, request_id = %$request_id, error = %$err, $($arg)*)
    };
}

/// Log a warning with request ID.
#[macro_export]
macro_rules! warn_with_request {
    (target: $target:expr, $request_id:expr, $($arg:tt)*) => {
        tracing::warn!(target: $target, request_id = %$request_id, $($arg)*)
    };
}

/// Log debug information with request ID.
#[macro_export]
macro_rules! debug_with_request {
    (target: $target:expr, $request_id:expr, $($arg:tt)*) => {
        tracing::debug!(target: $target, request_id = %$request_id, $($arg)*)
    };
}

/// Log an API request with method, path, and status.
#[macro_export]
macro_rules! log_api_request {
    ($method:expr, $path:expr, $status:expr, $duration:expr) => {
        tracing::info!(
            target: "api",
            method = %$method,
            path = %$path,
            status = %$status,
            duration_ms = %$duration,
            "API request"
        )
    };
}

/// Log a database query with duration and table name.
#[macro_export]
macro_rules! log_db_query {
    ($query:expr, $table:expr, $duration:expr) => {
        tracing::debug!(
            target: "database",
            query = %$query,
            table = %$table,
            duration_ms = %$duration,
            "Database query"
        )
    };
}

/// Log a cache operation with key and result.
#[macro_export]
macro_rules! log_cache_operation {
    ($operation:expr, $key:expr, $hit:expr, $duration:expr) => {
        tracing::debug!(
            target: "cache",
            operation = %$operation,
            key = %$key,
            hit = $hit,
            duration_ms = %$duration,
            "Cache operation"
        )
    };
}

/// Log an authentication event.
#[macro_export]
macro_rules! log_auth_event {
    ($event:expr, $user_id:expr, $success:expr) => {
        tracing::info!(
            target: "auth",
            event = %$event,
            user_id = %$user_id,
            success = $success,
            "Authentication event"
        )
    };
}

/// Log a security event.
#[macro_export]
macro_rules! log_security_event {
    ($event:expr, $user_id:expr, $details:expr) => {
        tracing::warn!(
            target: "security",
            event = %$event,
            user_id = %$user_id,
            details = %$details,
            "Security event"
        )
    };
}

/// Measure and log the duration of a block of code.
///
/// # Example
///
/// ```rust
/// use logging::measure_duration;
///
/// let result = measure_duration!("database_query", "users", || {
///     // Some database operation
///     Ok(vec![])
/// });
/// ```
#[macro_export]
macro_rules! measure_duration {
    ($target:expr, $context:expr, $block:block) => {{
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        tracing::debug!(
            target: $target,
            context = %$context,
            duration_ms = duration.as_secs_f64() * 1000.0,
            "Operation completed"
        );
        result
    }};
    ($target:expr, $context:expr, $name:expr, $block:block) => {{
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        tracing::debug!(
            target: $target,
            name = $name,
            context = %$context,
            duration_ms = duration.as_secs_f64() * 1000.0,
            "Operation completed"
        );
        result
    }};
}

/// Create a scoped span for measuring operation duration.
#[macro_export]
macro_rules! span_duration {
    ($name:expr, $context:expr) => {
        tracing::info_span!(
            $name,
            context = %$context,
            start_time = tracing::field::debug(std::time::Instant::now())
        )
    };
    ($name:expr, $context:expr, $($k:ident = $v:expr),+) => {
        tracing::info_span!(
            $name,
            context = %$context,
            $($k = $v),+,
            start_time = tracing::field::debug(std::time::Instant::now())
        )
    };
}
