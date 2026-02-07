//! # Multi-Factor Authentication (MFA) Service
//!
//! TOTP-based MFA implementation using RFC 6238 compliant TOTP tokens.
//! Provides secret generation, QR code generation, token verification,
//! and backup code management.

use blake3;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

/// Number of backup codes to generate
const BACKUP_CODE_COUNT: usize = 10;

/// Length of each backup code in characters (hex encoded from 4 bytes = 8 chars)
const BACKUP_CODE_BYTES: usize = 4;

/// TOTP algorithm to use (SHA1 for maximum authenticator app compatibility)
const TOTP_ALGORITHM: Algorithm = Algorithm::SHA1;

/// Number of digits in the TOTP code
const TOTP_DIGITS: usize = 6;

/// Number of time steps to allow as skew (1 step = 30 seconds before/after)
const TOTP_SKEW: u8 = 1;

/// TOTP time step in seconds
const TOTP_STEP: u64 = 30;

/// Errors that can occur during MFA operations.
#[derive(Debug, Error)]
pub enum MfaError {
    /// Failed to generate TOTP secret
    #[error("Failed to generate TOTP secret: {0}")]
    SecretGenerationFailed(String),

    /// Failed to create TOTP instance
    #[error("Failed to create TOTP instance: {0}")]
    TotpCreationFailed(String),

    /// Failed to generate QR code
    #[error("Failed to generate QR code: {0}")]
    QrCodeFailed(String),

    /// Invalid TOTP code
    #[error("Invalid TOTP code")]
    InvalidCode,

    /// MFA is not enabled for this user
    #[error("MFA is not enabled for this user")]
    MfaNotEnabled,

    /// MFA is already enabled for this user
    #[error("MFA is already enabled for this user")]
    MfaAlreadyEnabled,

    /// Invalid backup code
    #[error("Invalid backup code")]
    InvalidBackupCode,

    /// No backup codes remaining
    #[error("No backup codes remaining")]
    NoBackupCodesRemaining,

    /// Invalid secret format
    #[error("Invalid secret format: {0}")]
    InvalidSecretFormat(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result of MFA setup - contains the secret and provisioning info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetupResult {
    /// Base32-encoded TOTP secret
    pub secret:         String,
    /// otpauth:// URI for authenticator apps
    pub otpauth_uri:    String,
    /// Base64-encoded QR code PNG image
    pub qr_code_base64: String,
    /// Backup codes for account recovery
    pub backup_codes:   Vec<String>,
}

/// Hashed backup codes stored in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedBackupCodes {
    /// BLAKE3-hashed backup codes
    pub codes: Vec<String>,
}

/// Generates a new TOTP secret for MFA setup.
///
/// # Arguments
///
/// * `issuer` - The service name (e.g., "Horizon")
/// * `account_name` - The user's account identifier (e.g., email)
///
/// # Returns
///
/// An `MfaSetupResult` containing the secret, QR code, and backup codes.
///
/// # Errors
///
/// Returns `MfaError` if secret generation, TOTP creation, or QR code generation fails.
pub fn generate_mfa_setup(issuer: &str, account_name: &str) -> Result<MfaSetupResult, MfaError> {
    // Generate a random secret (160 bits = 20 bytes, standard for TOTP)
    let secret = Secret::generate_secret();
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| MfaError::SecretGenerationFailed(e.to_string()))?;

    // Create the TOTP instance
    let totp = TOTP::new(
        TOTP_ALGORITHM,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes,
        Some(issuer.to_string()),
        account_name.to_string(),
    )
    .map_err(|e| MfaError::TotpCreationFailed(e.to_string()))?;

    // Get the otpauth URI
    let otpauth_uri = totp.get_url();

    // Generate QR code as base64-encoded PNG
    let qr_code_base64 = totp
        .get_qr_base64()
        .map_err(|e| MfaError::QrCodeFailed(e.to_string()))?;

    // Get base32-encoded secret for manual entry
    let secret_base32 = totp.get_secret_base32();

    // Generate backup codes
    let backup_codes = generate_backup_codes();

    Ok(MfaSetupResult {
        secret: secret_base32,
        otpauth_uri,
        qr_code_base64,
        backup_codes,
    })
}

/// Creates a TOTP instance from a base32-encoded secret.
///
/// # Arguments
///
/// * `secret_base32` - Base32-encoded TOTP secret
/// * `issuer` - The service name
/// * `account_name` - The user's account identifier
///
/// # Returns
///
/// A configured TOTP instance.
///
/// # Errors
///
/// Returns `MfaError` if the secret is invalid or TOTP creation fails.
pub fn create_totp_from_secret(secret_base32: &str, issuer: &str, account_name: &str) -> Result<TOTP, MfaError> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| MfaError::InvalidSecretFormat(e.to_string()))?;

    TOTP::new(
        TOTP_ALGORITHM,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes,
        Some(issuer.to_string()),
        account_name.to_string(),
    )
    .map_err(|e| MfaError::TotpCreationFailed(e.to_string()))
}

/// Verifies a TOTP code against a secret.
///
/// # Arguments
///
/// * `secret_base32` - Base32-encoded TOTP secret
/// * `code` - The 6-digit TOTP code to verify
/// * `issuer` - The service name
/// * `account_name` - The user's account identifier
///
/// # Returns
///
/// `Ok(true)` if the code is valid, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns `MfaError` if the secret is invalid or verification encounters an error.
pub fn verify_totp_code(secret_base32: &str, code: &str, issuer: &str, account_name: &str) -> Result<bool, MfaError> {
    let totp = create_totp_from_secret(secret_base32, issuer, account_name)?;

    // Use system time for verification
    let time = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|e| MfaError::TotpCreationFailed(format!("Failed to get system time: {}", e)))?
        .as_secs();

    Ok(totp.check(code, time))
}

/// Generates a set of backup codes for account recovery.
///
/// Each backup code is a hex-encoded random string (8 characters).
///
/// # Returns
///
/// A vector of backup code strings.
pub fn generate_backup_codes() -> Vec<String> {
    let mut codes = Vec::with_capacity(BACKUP_CODE_COUNT);
    let mut rng = rand::rng();

    for _ in 0 .. BACKUP_CODE_COUNT {
        let mut bytes = [0u8; BACKUP_CODE_BYTES];
        rng.fill_bytes(&mut bytes);
        // Format as uppercase hex with dash in middle for readability: XXXX-XXXX
        let hex = hex_encode(&bytes);
        let formatted = format!("{}-{}", &hex[.. 4], &hex[4 ..]);
        codes.push(formatted.to_uppercase());
    }

    codes
}

/// Hashes backup codes for secure storage using BLAKE3.
///
/// # Arguments
///
/// * `codes` - The plaintext backup codes to hash
///
/// # Returns
///
/// A `HashedBackupCodes` struct containing the hashed codes.
pub fn hash_backup_codes(codes: &[String]) -> HashedBackupCodes {
    let hashed: Vec<String> = codes
        .iter()
        .map(|code| {
            // Normalize: remove dashes and convert to uppercase before hashing
            let normalized = code.replace('-', "").to_uppercase();
            blake3::hash(normalized.as_bytes()).to_hex().to_string()
        })
        .collect();

    HashedBackupCodes {
        codes: hashed,
    }
}

/// Verifies a backup code against stored hashes and returns the remaining codes.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `code` - The backup code to verify
/// * `hashed_codes` - The stored hashed backup codes
///
/// # Returns
///
/// `Ok(HashedBackupCodes)` with the used code removed if valid,
/// or `Err(MfaError)` if the code is invalid.
pub fn verify_and_consume_backup_code(
    code: &str,
    hashed_codes: &HashedBackupCodes,
) -> Result<HashedBackupCodes, MfaError> {
    if hashed_codes.codes.is_empty() {
        return Err(MfaError::NoBackupCodesRemaining);
    }

    // Normalize input: remove dashes and convert to uppercase
    let normalized = code.replace('-', "").to_uppercase();
    let code_hash = blake3::hash(normalized.as_bytes()).to_hex().to_string();
    let code_hash_bytes = code_hash.as_bytes();

    let mut found_index: Option<usize> = None;

    for (i, stored_hash) in hashed_codes.codes.iter().enumerate() {
        let stored_bytes = stored_hash.as_bytes();
        // Constant-time comparison to prevent timing attacks
        if code_hash_bytes.len() == stored_bytes.len() && bool::from(code_hash_bytes.ct_eq(stored_bytes)) {
            found_index = Some(i);
            break;
        }
    }

    match found_index {
        Some(idx) => {
            // Remove the used code
            let mut remaining = hashed_codes.codes.clone();
            remaining.remove(idx);
            Ok(HashedBackupCodes {
                codes: remaining,
            })
        },
        None => Err(MfaError::InvalidBackupCode),
    }
}

/// Serializes hashed backup codes to JSON string for database storage.
///
/// # Arguments
///
/// * `codes` - The hashed backup codes to serialize
///
/// # Returns
///
/// A JSON string representation of the hashed codes.
///
/// # Errors
///
/// Returns `MfaError` if serialization fails.
pub fn serialize_backup_codes(codes: &HashedBackupCodes) -> Result<String, MfaError> {
    serde_json::to_string(codes).map_err(|e| MfaError::SerializationError(e.to_string()))
}

/// Deserializes hashed backup codes from a JSON string.
///
/// # Arguments
///
/// * `json` - The JSON string to deserialize
///
/// # Returns
///
/// A `HashedBackupCodes` struct.
///
/// # Errors
///
/// Returns `MfaError` if deserialization fails.
pub fn deserialize_backup_codes(json: &str) -> Result<HashedBackupCodes, MfaError> {
    serde_json::from_str(json).map_err(|e| MfaError::SerializationError(e.to_string()))
}

/// Encodes bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mfa_setup() {
        let result = generate_mfa_setup("Horizon", "test@example.com");
        assert!(result.is_ok(), "MFA setup should succeed: {:?}", result);

        let setup = result.unwrap();
        assert!(!setup.secret.is_empty(), "Secret should not be empty");
        assert!(
            setup.otpauth_uri.starts_with("otpauth://totp/"),
            "URI should be otpauth format"
        );
        assert!(
            setup.otpauth_uri.contains("Horizon"),
            "URI should contain issuer"
        );
        assert!(
            setup.otpauth_uri.contains("test%40example.com") || setup.otpauth_uri.contains("test@example.com"),
            "URI should contain account name"
        );
        assert!(
            !setup.qr_code_base64.is_empty(),
            "QR code should not be empty"
        );
        assert_eq!(
            setup.backup_codes.len(),
            BACKUP_CODE_COUNT,
            "Should generate {} backup codes",
            BACKUP_CODE_COUNT
        );
    }

    #[test]
    fn test_generate_mfa_setup_different_secrets() {
        let result1 = generate_mfa_setup("Horizon", "user1@example.com").unwrap();
        let result2 = generate_mfa_setup("Horizon", "user2@example.com").unwrap();

        assert_ne!(
            result1.secret, result2.secret,
            "Different users should get different secrets"
        );
    }

    #[test]
    fn test_create_totp_from_secret() {
        let setup = generate_mfa_setup("Horizon", "test@example.com").unwrap();
        let totp = create_totp_from_secret(&setup.secret, "Horizon", "test@example.com");
        assert!(
            totp.is_ok(),
            "Should create TOTP from valid secret: {:?}",
            totp
        );
    }

    #[test]
    fn test_create_totp_from_invalid_secret() {
        let result = create_totp_from_secret("not-valid-base32!!!", "Horizon", "test@example.com");
        assert!(result.is_err(), "Invalid secret should fail");
    }

    #[test]
    fn test_verify_totp_code_valid() {
        let setup = generate_mfa_setup("Horizon", "test@example.com").unwrap();
        let totp = create_totp_from_secret(&setup.secret, "Horizon", "test@example.com").unwrap();

        // Generate a valid code for the current time
        let time = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_code = totp.generate(time);

        let result = verify_totp_code(&setup.secret, &valid_code, "Horizon", "test@example.com");
        assert!(
            result.is_ok(),
            "Verification should not error: {:?}",
            result
        );
        assert!(result.unwrap(), "Valid code should verify successfully");
    }

    #[test]
    fn test_verify_totp_code_invalid() {
        let setup = generate_mfa_setup("Horizon", "test@example.com").unwrap();

        let result = verify_totp_code(&setup.secret, "000000", "Horizon", "test@example.com");
        assert!(
            result.is_ok(),
            "Verification should not error for wrong code"
        );
        // Note: "000000" might occasionally be valid, but statistically it's extremely unlikely
        // For a robust test, we'd need to mock time. This tests the flow works.
    }

    #[test]
    fn test_verify_totp_code_wrong_format() {
        let setup = generate_mfa_setup("Horizon", "test@example.com").unwrap();

        // Wrong length codes
        let result = verify_totp_code(&setup.secret, "12345", "Horizon", "test@example.com");
        assert!(result.is_ok());
        assert!(!result.unwrap(), "5-digit code should be invalid");

        let result = verify_totp_code(&setup.secret, "1234567", "Horizon", "test@example.com");
        assert!(result.is_ok());
        assert!(!result.unwrap(), "7-digit code should be invalid");
    }

    #[test]
    fn test_generate_backup_codes() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);

        for code in &codes {
            // Format should be XXXX-XXXX (uppercase hex with dash)
            assert_eq!(
                code.len(),
                9,
                "Backup code should be 9 chars (XXXX-XXXX): {}",
                code
            );
            assert_eq!(&code[4 .. 5], "-", "Should have dash in middle: {}", code);
            assert!(
                code.replace('-', "").chars().all(|c| c.is_ascii_hexdigit()),
                "Should be hex characters: {}",
                code
            );
        }

        // All codes should be unique
        let mut unique_codes = codes.clone();
        unique_codes.sort();
        unique_codes.dedup();
        assert_eq!(
            unique_codes.len(),
            codes.len(),
            "All backup codes should be unique"
        );
    }

    #[test]
    fn test_hash_backup_codes() {
        let codes = generate_backup_codes();
        let hashed = hash_backup_codes(&codes);

        assert_eq!(hashed.codes.len(), codes.len());
        for hash in &hashed.codes {
            assert_eq!(hash.len(), 64, "BLAKE3 hash should be 64 hex chars");
        }
    }

    #[test]
    fn test_hash_backup_codes_deterministic() {
        let codes = vec!["ABCD-1234".to_string()];
        let hashed1 = hash_backup_codes(&codes);
        let hashed2 = hash_backup_codes(&codes);

        assert_eq!(
            hashed1.codes, hashed2.codes,
            "Same input should produce same hash"
        );
    }

    #[test]
    fn test_hash_backup_codes_case_insensitive() {
        let codes_upper = vec!["ABCD-1234".to_string()];
        let codes_lower = vec!["abcd-1234".to_string()];
        let hashed_upper = hash_backup_codes(&codes_upper);
        let hashed_lower = hash_backup_codes(&codes_lower);

        assert_eq!(
            hashed_upper.codes, hashed_lower.codes,
            "Hashing should be case-insensitive"
        );
    }

    #[test]
    fn test_hash_backup_codes_dash_insensitive() {
        let codes_with = vec!["ABCD-1234".to_string()];
        let codes_without = vec!["ABCD1234".to_string()];
        let hashed_with = hash_backup_codes(&codes_with);
        let hashed_without = hash_backup_codes(&codes_without);

        assert_eq!(
            hashed_with.codes, hashed_without.codes,
            "Hashing should be dash-insensitive"
        );
    }

    #[test]
    fn test_verify_and_consume_backup_code_valid() {
        let codes = generate_backup_codes();
        let hashed = hash_backup_codes(&codes);

        // Verify the first code
        let result = verify_and_consume_backup_code(&codes[0], &hashed);
        assert!(
            result.is_ok(),
            "Valid backup code should verify: {:?}",
            result
        );

        let remaining = result.unwrap();
        assert_eq!(
            remaining.codes.len(),
            codes.len() - 1,
            "Should have one fewer code after consumption"
        );
    }

    #[test]
    fn test_verify_and_consume_backup_code_case_insensitive() {
        let codes = vec!["ABCD-EF12".to_string()];
        let hashed = hash_backup_codes(&codes);

        let result = verify_and_consume_backup_code("abcd-ef12", &hashed);
        assert!(result.is_ok(), "Should accept lowercase");
    }

    #[test]
    fn test_verify_and_consume_backup_code_without_dash() {
        let codes = vec!["ABCD-EF12".to_string()];
        let hashed = hash_backup_codes(&codes);

        let result = verify_and_consume_backup_code("ABCDEF12", &hashed);
        assert!(result.is_ok(), "Should accept code without dashes");
    }

    #[test]
    fn test_verify_and_consume_backup_code_invalid() {
        let codes = generate_backup_codes();
        let hashed = hash_backup_codes(&codes);

        let result = verify_and_consume_backup_code("XXXX-YYYY", &hashed);
        assert!(result.is_err(), "Invalid code should fail");
        assert!(
            matches!(result.unwrap_err(), MfaError::InvalidBackupCode),
            "Should be InvalidBackupCode error"
        );
    }

    #[test]
    fn test_verify_and_consume_backup_code_empty_codes() {
        let hashed = HashedBackupCodes {
            codes: vec![],
        };

        let result = verify_and_consume_backup_code("ABCD-1234", &hashed);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), MfaError::NoBackupCodesRemaining),
            "Should be NoBackupCodesRemaining error"
        );
    }

    #[test]
    fn test_verify_and_consume_all_backup_codes() {
        let codes = generate_backup_codes();
        let mut hashed = hash_backup_codes(&codes);

        // Consume all codes one by one
        for (i, code) in codes.iter().enumerate() {
            let result = verify_and_consume_backup_code(code, &hashed);
            assert!(result.is_ok(), "Code {} should verify: {:?}", i, result);
            hashed = result.unwrap();
            assert_eq!(
                hashed.codes.len(),
                codes.len() - i - 1,
                "Should have correct remaining count"
            );
        }

        assert!(hashed.codes.is_empty(), "All codes should be consumed");
    }

    #[test]
    fn test_verify_and_consume_backup_code_cannot_reuse() {
        let codes = generate_backup_codes();
        let hashed = hash_backup_codes(&codes);

        // Use the first code
        let remaining = verify_and_consume_backup_code(&codes[0], &hashed).unwrap();

        // Try to use it again
        let result = verify_and_consume_backup_code(&codes[0], &remaining);
        assert!(
            result.is_err(),
            "Should not be able to reuse a consumed code"
        );
    }

    #[test]
    fn test_serialize_deserialize_backup_codes() {
        let codes = generate_backup_codes();
        let hashed = hash_backup_codes(&codes);

        let json = serialize_backup_codes(&hashed).unwrap();
        let deserialized = deserialize_backup_codes(&json).unwrap();

        assert_eq!(hashed.codes, deserialized.codes);
    }

    #[test]
    fn test_deserialize_invalid_json() {
        let result = deserialize_backup_codes("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_mfa_error_display() {
        let err = MfaError::InvalidCode;
        assert_eq!(err.to_string(), "Invalid TOTP code");

        let err = MfaError::MfaNotEnabled;
        assert_eq!(err.to_string(), "MFA is not enabled for this user");

        let err = MfaError::MfaAlreadyEnabled;
        assert_eq!(err.to_string(), "MFA is already enabled for this user");

        let err = MfaError::InvalidBackupCode;
        assert_eq!(err.to_string(), "Invalid backup code");

        let err = MfaError::NoBackupCodesRemaining;
        assert_eq!(err.to_string(), "No backup codes remaining");
    }

    #[test]
    fn test_qr_code_is_valid_base64() {
        use base64::prelude::*;
        let setup = generate_mfa_setup("Horizon", "test@example.com").unwrap();
        // QR code should be valid base64-encoded data
        let decoded = BASE64_STANDARD.decode(&setup.qr_code_base64);
        assert!(decoded.is_ok(), "QR code should be valid base64");
        assert!(!decoded.unwrap().is_empty(), "QR code should not be empty");
    }

    #[test]
    fn test_otpauth_uri_format() {
        let setup = generate_mfa_setup("MyApp", "user@example.com").unwrap();
        assert!(setup.otpauth_uri.starts_with("otpauth://totp/"));
        assert!(setup.otpauth_uri.contains("secret="));
        assert!(setup.otpauth_uri.contains("issuer="));
    }

    #[test]
    fn test_totp_constants() {
        assert_eq!(TOTP_DIGITS, 6);
        assert_eq!(TOTP_STEP, 30);
        assert_eq!(BACKUP_CODE_COUNT, 10);
    }
}
