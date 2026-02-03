//! Authentication utilities for Horizon CMDB.
//!
//! This crate provides authentication-related functionality including:
//! - Password hashing and verification using Argon2id
//! - JWT token management
//! - Session management
//! - API key authentication

pub mod password;
pub use password::{
    hash_password,
    validate_password_strength,
    verify_password,
    PasswordConfig,
    PasswordError,
    PasswordValidationError,
};
/// Re-exports
pub use secrecy;
pub use subtle;
