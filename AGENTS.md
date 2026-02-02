# Horizon Development Guide for AI Agents

This file provides guidelines for AI coding agents working on the Horizon CMDB project.

## Project Overview

Horizon is a self-hostable Configuration Management Database (CMDB) system written in Rust. It uses:

- **Web Framework**: Axum with Tokio async runtime
- **Database**: PostgreSQL with Sea-ORM, Redis for caching
- **Error Handling**: thiserror + anyhow pattern
- **Workspace**: Multiple crates under `crates/` directory

## Build Commands

```bash
# Build entire workspace
cargo build

# Build specific crate
cargo build -p cli

# Build with all features
cargo build --all-features

# Release build
cargo build --release

# Single test file
cargo test -p error -- lib.rs
cargo test -p error --lib   # Run lib tests only
cargo test -p error::lib::tests --lib  # Specific test module

# Run tests with output
cargo test -p cli -- --nocapture

# Run doc tests
cargo test --doc

# Format all code
cargo fmt --all

# Lint with all features
cargo clippy --all-features

# Check for missing documentation
cargo doc --all-features --no-deps

# Audit dependencies for vulnerabilities
cargo audit
```

## Code Style Guidelines

### Formatting (rustfmt.toml)

- **Indentation**: 4 spaces, no tabs
- **Max line width**: 120 characters
- **Line endings**: Unix (LF)
- **Brace style**: SameLineWhere
- **Trailing semicolon**: Always required
- **Comment width**: 100 characters
- **Wrap comments**: Enabled

### Imports

- **Group imports**: `StdExternalCrate` (std, external, crate)
- **Granularity**: Crate-level (`imports_granularity = "Crate`)
- **Single-line imports**: Allowed for single items
- **Sort order**: Standard → External → Local (parent module first)

```rust
use std::collections::HashMap;
use async_openai::types::CreateEmbeddingRequest;
use tracing::{info, debug};
use crate::models::User;
use super::parent_module;
```

### Naming Conventions

| Item           | Convention           | Example                            |
| -------------- | -------------------- | ---------------------------------- |
| Structs        | PascalCase           | `UserProfile`, `AssetInventory`    |
| Enums          | PascalCase           | `UserStatus`, `AssetType`          |
| Traits         | PascalCase           | `Serializable`, `Validator`        |
| Functions      | snake_case           | `validate_input`, `get_user_by_id` |
| Variables      | snake_case           | `user_id`, `config_path`           |
| Constants      | SCREAMING_SNAKE_CASE | `MAX_CONNECTIONS`                  |
| Types          | PascalCase           | `Vec<T>`, `Result<T, E>`           |
| Generic params | PascalCase           | `T`, `E`, `R`                      |

### Error Handling

Use the `AppError` enum from `error` crate with thiserror:

```rust
use error::{AppError, Result};

// Function returning Result
async fn get_user(id: &str) -> Result<User> {
    // Use ? for propagation
    let user = db.find_user(id).await?;
    // Use context for debugging
    user.ok_or_else(|| AppError::not_found("User"))
}

// Builder pattern for API responses
use error::{ApiResponse, ApiResponseBuilder};
let response = ApiResponse::ok(user).with_pagination(meta);
```

Error variants: `NotFound`, `BadRequest`, `Unauthorized`, `Forbidden`, `Conflict`, `Validation`, `RateLimit`,
`Internal`, `Database`, `Io`.

### Async/Await Patterns

- All async functions must be awaitable with Tokio
- Avoid blocking calls; use async equivalents
- Use `#[tokio::main]` or `#[tokio::test]` for entry points
- Use `?` for error propagation in async contexts

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config().await?;
    let server = axum::Router::new()
        .route("/", get(index))
        .layer(middleware);
    axum::serve(listener, server).await?;
    Ok(())
}
```

### Documentation Requirements

- **Public APIs**: Comprehensive doc comments with examples
- **Complex logic**: Inline comments explaining reasoning
- **All public items**: `///` doc comments required

````rust
/// Retrieves a user by their unique identifier.
///
/// # Arguments
/// * `id` - The unique user ID (UUID or CUID format)
///
/// # Returns
/// Returns `Ok(Some(User))` if found, `Ok(None)` if not found,
/// or `Err(AppError)` for database errors.
///
/// # Example
/// ```ignore
/// let user = get_user("user-123").await?;
/// ```
pub async fn get_user(id: &str) -> Result<Option<User>> {
    // Complex logic explained here
}
````

### Testing Standards

- Every function requires unit tests
- Test edge cases: empty inputs, invalid data, boundary conditions
- Use standard `#[cfg(test)]` modules
- Tests should be in the same file as the code they test

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_validation_success() {
        let user = User::new("valid@example.com");
        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_user_validation_invalid_email() {
        let user = User::new("invalid-email");
        assert!(user.validate().is_err());
    }
}
```

### Security Considerations

- **No hardcoded secrets**: Use environment variables
- **Validate all inputs**: Use `validator` crate
- **Use cryptographic best practices**: Argon2id for passwords, XChaCha20-Poly1305 for encryption
- **Audit trails**: Log important operations with tracing

## Project Structure

```
crates/
├── cli/          # Command-line interface
├── error/        # Error types and API responses
├── logging/      # Structured logging infrastructure
├── ui/           # Tauri desktop application
└── .../          # Other crates
```

## Important Files

- `Cargo.toml`: Workspace configuration and Clippy lints
- `rustfmt.toml`: Code formatting rules
- `IMPLEMENTATION_PLAN.md`: Architecture and phase details
- `.github/copilot-instructions.md`: AI coding guidelines

## Key Patterns

- **Result<T, E>**: Use `error::Result<T>` alias
- **ApiResponse**: Standard API response wrapper with pagination
- **Context**: Add context to errors with `.context("operation")`
- **Builder**: Use builder patterns for complex construction
- **Modules**: Organize code into logical modules per crate, with clear public/private boundaries. Use `mod.rs` files for module roots.
- **Crates**: Each crate should have a clear responsibility and expose a well-defined public API. Prefer creating new crates for distinct functionalities and always avoid monolithic crates.
- **Dependencies**: Use minimal dependencies. Prefer lightweight crates and avoid large frameworks unless necessary. Regularly audit dependencies for vulnerabilities.

## Quality Gate

Before marking any task complete:

1. Code compiles: `cargo build --all-features`
2. Tests pass: `cargo test --all-features`
3. Linting clean: `cargo clippy --all-features`
4. Formatting correct: `cargo fmt --all`
5. Documentation builds: `cargo doc --all-features --no-deps`
6. Coverage: At least 90% test coverage, verified with `./scripts/run_coverage.sh` and output file checked in `target/coverage/html/index.html` file
