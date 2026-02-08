//! # MFA Utilities
//!
//! Multi-Factor Authentication utility functions using TOTP.

use error::Result;
use totp_rs::{Algorithm, Secret, TOTP};

/// MFA setup data
#[derive(Debug, Clone)]
pub struct MfaSetup {
    pub secret: String,
    pub backup_codes: Vec<String>,
    pub otpauth_uri: String,
    pub qr_code_base64: String,
}

/// Generate MFA setup data for a user
pub fn generate_mfa_setup(issuer: &str, email: &str) -> Result<MfaSetup> {
    // Generate a random secret
    let secret = Secret::generate_secret().to_string();

    // Create TOTP instance
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.clone()).to_bytes().unwrap(),
        Some(issuer.to_string()),
        email.to_string(),
    ).map_err(|e| error::AppError::internal(format!("Failed to create TOTP: {}", e)))?;

    // Generate backup codes
    let backup_codes = generate_backup_codes();

    // Generate QR code
    let qr_code_base64 = totp.get_qr_base64().map_err(|e| error::AppError::internal(format!("Failed to generate QR code: {}", e)))?;

    Ok(MfaSetup {
        secret,
        backup_codes,
        otpauth_uri: totp.get_url(),
        qr_code_base64,
    })
}

/// Generate backup codes for MFA
pub fn generate_backup_codes() -> Vec<String> {
    (0..10)
        .map(|_| {
            use rand::Rng;
            let mut rng = rand::rng();
            format!("{:04x}-{:04x}-{:04x}-{:04x}", rng.random::<u16>(), rng.random::<u16>(), rng.random::<u16>(), rng.random::<u16>())
        })
        .collect()
}

/// Hash backup codes for storage
pub fn hash_backup_codes(codes: &[String], salt: &str) -> Vec<String> {
    codes.iter().map(|code| {
        let salted = format!("{}{}", salt, code);
        blake3::hash(salted.as_bytes()).to_hex().to_string()
    }).collect()
}

/// Serialize backup codes to JSON
pub fn serialize_backup_codes(hashed_codes: &[String]) -> Result<serde_json::Value> {
    serde_json::to_value(hashed_codes).map_err(|e| error::AppError::internal(format!("Failed to serialize backup codes: {}", e)))
}

/// Deserialize backup codes from JSON
pub fn deserialize_backup_codes(json: &str) -> Result<Vec<String>> {
    serde_json::from_str(json).map_err(|e| error::AppError::internal(format!("Failed to deserialize backup codes: {}", e)))
}

/// Verify TOTP code
pub fn verify_totp_code(secret: &str, code: &str, issuer: &str, account_name: &str) -> Result<bool> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
        Some(issuer.to_string()),
        account_name.to_string(),
    ).map_err(|e| error::AppError::internal(format!("Failed to create TOTP: {}", e)))?;

    totp.check_current(code).map_err(|e| error::AppError::internal(format!("TOTP verification failed: {}", e)))
}

/// Verify and consume a backup code
pub fn verify_and_consume_backup_code(code: &str, stored_codes: Vec<String>, salt: &str) -> Result<Vec<String>> {
    let salted = format!("{}{}", salt, code);
    let hashed_input = blake3::hash(salted.as_bytes()).to_hex().to_string();
    if let Some(pos) = stored_codes.iter().position(|h| h == &hashed_input) {
        let mut codes = stored_codes;
        codes.remove(pos);
        Ok(codes)
    } else {
        Err(error::AppError::unauthorized("Invalid backup code"))
    }
}

/// Check if a backup code is valid without consuming it
pub fn check_backup_code_valid(code: &str, stored_codes: &[String], salt: &str) -> bool {
    let salted = format!("{}{}", salt, code);
    let hashed_input = blake3::hash(salted.as_bytes()).to_hex().to_string();
    stored_codes.contains(&hashed_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_backup_codes() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), 10);
        for code in &codes {
            assert_eq!(code.len(), 19); // XXXX-XXXX-XXXX-XXXX
            assert!(code.chars().nth(4).unwrap() == '-');
            assert!(code.chars().nth(9).unwrap() == '-');
            assert!(code.chars().nth(14).unwrap() == '-');
        }
    }

    #[test]
    fn test_hash_backup_codes() {
        let codes = vec!["test-code".to_string()];
        let salt = "user123";
        let hashed = hash_backup_codes(&codes, salt);
        assert_eq!(hashed.len(), 1);
        // Check it's different from unsalted
        let unsalted = blake3::hash(b"test-code").to_hex().to_string();
        assert_ne!(hashed[0], unsalted);
    }

    #[test]
    fn test_verify_backup_code() {
        let codes = vec!["test-code".to_string()];
        let salt = "user123";
        let hashed = hash_backup_codes(&codes, salt);
        let result = verify_and_consume_backup_code("test-code", hashed.clone(), salt);
        assert!(result.is_ok());
        let remaining = result.unwrap();
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_check_backup_code_valid() {
        let codes = vec!["test-code".to_string()];
        let salt = "user123";
        let hashed = hash_backup_codes(&codes, salt);
        assert!(check_backup_code_valid("test-code", &hashed, salt));
        assert!(!check_backup_code_valid("wrong-code", &hashed, salt));
    }
}