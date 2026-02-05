//! Password hashing and verification utilities using Argon2id.
//!
//! This module provides secure password hashing using the Argon2id algorithm,
//! which is the winner of the Password Hashing Competition and provides
//! protection against GPU and ASIC attacks.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use base64::prelude::*;

/// Errors that can occur during password operations.
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Hashing failed: {0}")]
    HashingFailed(String),

    #[error("Verification failed: password does not match")]
    VerificationFailed,

    #[error("Invalid hash format")]
    InvalidHashFormat,

    #[error("Base64 decoding failed: {0}")]
    DecodingFailed(#[from] base64::DecodeError),
}

/// Configuration for Argon2id password hashing.
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Memory cost in KiB (default: 15 MiB = 15360 KiB)
    pub memory_cost: u32,
    /// Number of iterations (default: 3)
    pub time_cost:   u32,
    /// Number of lanes (default: 2)
    pub parallelism: u32,
    /// Length of the generated hash (default: 32 bytes)
    pub hash_length: u32,
    /// Length of the salt (default: 16 bytes)
    pub salt_length: u32,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            memory_cost: 15360, // 15 MiB
            time_cost:   3,
            parallelism: 2,
            hash_length: 32,
            salt_length: 16,
        }
    }
}

/// Hashes a password using Argon2id.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `config` - Optional configuration for Argon2id parameters
///
/// # Returns
///
/// A `Result` containing the hashed password as a `SecretString` or an error.
///
/// # Example
///
/// ```
/// use auth::password::{hash_password, PasswordConfig};
/// use secrecy::SecretString;
///
/// let password = SecretString::from("my_secure_password".to_string());
/// let hash = hash_password(&password, None).unwrap();
/// ```
pub fn hash_password(password: &SecretString, config: Option<PasswordConfig>) -> Result<SecretString, PasswordError> {
    let config = config.unwrap_or_default();

    // Generate a random salt
    let mut salt = vec![0u8; config.salt_length as usize];
    rng().fill_bytes(&mut salt);

    // Configure Argon2id
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(config.hash_length as usize),
        )
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))?,
    );

    // Hash the password
    let mut output = vec![0u8; config.hash_length as usize];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut output)
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))?;

    // Format: $argon2id$v=19$m=15360,t=3,p=2$<salt_base64>$<hash_base64>
    let salt_b64 = BASE64_STANDARD.encode(&salt);
    let hash_b64 = BASE64_STANDARD.encode(&output);

    let hash_format = format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        config.memory_cost, config.time_cost, config.parallelism, salt_b64, hash_b64
    );

    Ok(SecretString::from(hash_format))
}

/// Verifies a password against a stored hash.
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `expected_hash` - The stored hash to verify against
///
/// # Returns
///
/// A `Result` indicating success or failure.
///
/// # Example
///
/// ```
/// use auth::password::{hash_password, verify_password};
/// use secrecy::{ExposeSecret, SecretString};
///
/// let password = SecretString::from("my_secure_password".to_string());
/// let hash = hash_password(&password, None).unwrap();
///
/// assert!(verify_password(&password, hash.expose_secret()).is_ok());
/// ```
pub fn verify_password(password: &SecretString, expected_hash: &str) -> Result<(), PasswordError> {
    // Parse the hash format: $argon2id$v=19$m=15360,t=3,p=2$<salt_b64>$<hash_b64>
    // Splitting by '$' gives: ["", "argon2id", "v=19", "m=15360,t=3,p=2", "<salt>", "<hash>"]
    let parts: Vec<&str> = expected_hash.split('$').collect();
    if parts.len() != 6 {
        return Err(PasswordError::InvalidHashFormat);
    }

    let algo_identifier = parts[1];
    let version_str = parts[2];
    let params_str = parts[3];
    let salt_b64 = parts[4];
    let hash_b64 = parts[5];

    // Verify algorithm identifier
    if algo_identifier != "argon2id" {
        return Err(PasswordError::InvalidHashFormat);
    }

    // Parse version: "v=19"
    if !version_str.starts_with("v=") {
        return Err(PasswordError::InvalidHashFormat);
    }
    let version = &version_str[2 ..];
    if version != "19" {
        return Err(PasswordError::InvalidHashFormat);
    }
    let memory_cost: u32 = params_str
        .split(',')
        .find(|p| p.starts_with('m'))
        .and_then(|p| p.strip_prefix('m'))
        .and_then(|p| p.split(',').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(15360);

    let time_cost: u32 = params_str
        .split(',')
        .find(|p| p.starts_with('t'))
        .and_then(|p| p.strip_prefix('t'))
        .and_then(|p| p.split(',').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(3);

    let parallelism: u32 = params_str
        .split(',')
        .find(|p| p.starts_with('p'))
        .and_then(|p| p.strip_prefix('p'))
        .and_then(|p| p.parse().ok())
        .unwrap_or(2);

    // Decode salt and stored hash
    let salt = BASE64_STANDARD.decode(salt_b64)?;
    let stored_hash = BASE64_STANDARD.decode(hash_b64)?;

    // Configure Argon2id with the same parameters
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(memory_cost, time_cost, parallelism, Some(stored_hash.len()))
            .map_err(|e| PasswordError::HashingFailed(e.to_string()))?,
    );

    // Hash the provided password with the same salt
    let mut computed_hash = vec![0u8; stored_hash.len()];
    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            &salt,
            &mut computed_hash,
        )
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))?;

    // Compare using constant-time comparison
    if computed_hash.len() != stored_hash.len() {
        return Err(PasswordError::VerificationFailed);
    }

    use subtle::ConstantTimeEq;
    if computed_hash.as_slice().ct_eq(&stored_hash).into() {
        Ok(())
    }
    else {
        Err(PasswordError::VerificationFailed)
    }
}

/// Checks if a password is strong enough.
///
/// # Arguments
///
/// * `password` - The password to check
///
/// # Returns
///
/// A `Result` indicating success or a vector of validation errors.
pub fn validate_password_strength(password: &str) -> Result<(), Vec<PasswordValidationError>> {
    let mut errors = Vec::new();

    if password.len() < 12 {
        errors.push(PasswordValidationError::TooShort);
    }

    if password.len() > 256 {
        errors.push(PasswordValidationError::TooLong);
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

    if !has_uppercase {
        errors.push(PasswordValidationError::MissingUppercase);
    }

    if !has_lowercase {
        errors.push(PasswordValidationError::MissingLowercase);
    }

    if !has_digit {
        errors.push(PasswordValidationError::MissingDigit);
    }

    if !has_special {
        errors.push(PasswordValidationError::MissingSpecial);
    }

    if errors.is_empty() {
        Ok(())
    }
    else {
        Err(errors)
    }
}

/// Errors for password validation.
#[derive(Debug, Error)]
pub enum PasswordValidationError {
    #[error("Password must be at least 12 characters long")]
    TooShort,

    #[error("Password must be at most 256 characters long")]
    TooLong,

    #[error("Password must contain at least one uppercase letter")]
    MissingUppercase,

    #[error("Password must contain at least one lowercase letter")]
    MissingLowercase,

    #[error("Password must contain at least one digit")]
    MissingDigit,

    #[error("Password must contain at least one special character")]
    MissingSpecial,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = SecretString::from("TestPassword123!".to_string());
        let hash = hash_password(&password, None).unwrap();
        let result = verify_password(&password, hash.expose_secret());
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = SecretString::from("CorrectPassword".to_string());
        let wrong_password = SecretString::from("WrongPassword".to_string());
        let hash = hash_password(&password, None).unwrap();
        assert!(verify_password(&wrong_password, hash.expose_secret()).is_err());
    }

    #[test]
    fn test_password_validation() {
        let weak = "abc";
        assert!(validate_password_strength(weak).is_err());

        let strong = "StrongP@ssw0rd!";
        assert!(validate_password_strength(strong).is_ok());
    }
}
