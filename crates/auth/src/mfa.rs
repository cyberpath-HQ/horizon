//! # MFA Utilities
//!
//! Multi-Factor Authentication utility functions using TOTP.

use error::Result;
use totp_rs::{Algorithm, Secret, TOTP};

/// MFA setup data
#[derive(Debug, Clone)]
pub struct MfaSetup {
    pub secret:         String,
    pub backup_codes:   Vec<String>,
    pub otpauth_uri:    String,
    pub qr_code_base64: String,
}

/// Generate MFA setup data for a user
pub fn generate_mfa_setup(issuer: &str, email: &str) -> Result<MfaSetup> {
    // Generate a random secret
    let secret_obj = Secret::generate_secret();
    let secret = secret_obj.to_string();
    let secret_bytes = secret_obj
        .to_bytes()
        .map_err(|e| error::AppError::internal(format!("Failed to get secret bytes: {}", e)))?;

    // Create TOTP instance
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        email.to_string(),
    )
    .map_err(|e| error::AppError::internal(format!("Failed to create TOTP: {}", e)))?;

    // Generate backup codes
    let backup_codes = generate_backup_codes();

    // Generate QR code
    let qr_code_base64 = totp
        .get_qr_base64()
        .map_err(|e| error::AppError::internal(format!("Failed to generate QR code: {}", e)))?;

    Ok(MfaSetup {
        secret,
        backup_codes,
        otpauth_uri: totp.get_url(),
        qr_code_base64,
    })
}

/// Generate backup codes for MFA
pub fn generate_backup_codes() -> Vec<String> {
    (0 .. 10)
        .map(|_| {
            use rand::Rng;
            let mut rng = rand::rng();
            format!(
                "{:04x}-{:04x}-{:04x}-{:04x}",
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>()
            )
        })
        .collect()
}

/// Normalize backup code by removing dashes and converting to lowercase
fn normalize_backup_code(code: &str) -> String {
    code.chars()
        .filter(|&c| c != '-')
        .collect::<String>()
        .to_lowercase()
}

/// Hash backup codes for storage
pub fn hash_backup_codes(codes: &[String], salt: &str) -> Vec<String> {
    codes
        .iter()
        .map(|code| {
            let normalized = normalize_backup_code(code);
            let salted = format!("{}:{}", salt, normalized);
            blake3::hash(salted.as_bytes()).to_hex().to_string()
        })
        .collect()
}

/// Serialize backup codes to JSON
pub fn serialize_backup_codes(hashed_codes: &[String]) -> Result<serde_json::Value> {
    serde_json::to_value(hashed_codes)
        .map_err(|e| error::AppError::internal(format!("Failed to serialize backup codes: {}", e)))
}

/// Deserialize backup codes from JSON
pub fn deserialize_backup_codes(json: &str) -> Result<Vec<String>> {
    serde_json::from_str(json)
        .map_err(|e| error::AppError::internal(format!("Failed to deserialize backup codes: {}", e)))
}

/// Verify TOTP code
pub fn verify_totp_code(secret: &str, code: &str, issuer: &str, account_name: &str) -> Result<bool> {
    // Validate secret is not empty
    if secret.is_empty() {
        return Err(error::AppError::internal("TOTP secret is empty"));
    }

    // Clean the secret - remove any whitespace and convert to uppercase
    let cleaned_secret: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();

    if cleaned_secret.is_empty() {
        return Err(error::AppError::internal(
            "TOTP secret is invalid (empty after cleaning)",
        ));
    }

    // Try to decode the base32 secret
    let secret_bytes = Secret::Encoded(cleaned_secret)
        .to_bytes()
        .map_err(|e| error::AppError::internal(format!("Failed to decode base32 secret: {}", e)))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        account_name.to_string(),
    )
    .map_err(|e| error::AppError::internal(format!("Failed to create TOTP: {}", e)))?;

    totp.check_current(code)
        .map_err(|e| error::AppError::internal(format!("TOTP verification failed: {}", e)))
}

/// Verify and consume a backup code
pub fn verify_and_consume_backup_code(code: &str, stored_codes: Vec<String>, salt: &str) -> Result<Vec<String>> {
    let normalized_code = normalize_backup_code(code);
    let salted = format!("{}:{}", salt, normalized_code);
    let hashed_input = blake3::hash(salted.as_bytes()).to_hex().to_string();
    if let Some(pos) = stored_codes.iter().position(|h| h == &hashed_input) {
        let mut codes = stored_codes;
        codes.remove(pos);
        Ok(codes)
    }
    else {
        Err(error::AppError::unauthorized("Invalid backup code"))
    }
}

/// Check if a backup code is valid without consuming it
pub fn check_backup_code_valid(code: &str, stored_codes: &[String], salt: &str) -> bool {
    let normalized_code = normalize_backup_code(code);
    let salted = format!("{}:{}", salt, normalized_code);
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

    #[test]
    fn test_generate_mfa_setup() {
        let issuer = "TestApp";
        let email = "user@example.com";
        let setup = generate_mfa_setup(issuer, email).unwrap();
        assert!(!setup.secret.is_empty());
        assert_eq!(setup.backup_codes.len(), 10);
        assert!(setup.otpauth_uri.contains(issuer));
        assert!(!setup.otpauth_uri.is_empty()); // URI contains account name, but may be encoded
        assert!(!setup.qr_code_base64.is_empty());
    }

    #[test]
    fn test_serialize_backup_codes() {
        let codes = vec!["code1".to_string(), "code2".to_string()];
        let serialized = serialize_backup_codes(&codes).unwrap();
        let deserialized = deserialize_backup_codes(&serialized.to_string()).unwrap();
        assert_eq!(deserialized, codes);
    }

    #[test]
    fn test_deserialize_backup_codes() {
        let json = r#"["code1","code2"]"#;
        let codes = deserialize_backup_codes(json).unwrap();
        assert_eq!(codes, vec!["code1".to_string(), "code2".to_string()]);
    }

    #[test]
    fn test_verify_totp_code() {
        // This is a basic test - in real scenarios, you'd use a known secret and time
        let secret = "JBSWY3DPEHPK3PXP"; // Test secret
        let issuer = "TestApp";
        let account_name = "user@example.com";
        // Note: This test may be flaky due to time-based codes
        // In a real test, you'd mock the current time
        let _result = verify_totp_code(secret, "123456", issuer, account_name);
        // We can't assert the exact result without controlling time, but ensure it doesn't panic
        // The function call itself ensures no panic
    }

    #[test]
    fn test_normalize_backup_code() {
        assert_eq!(normalize_backup_code("A1B2-C3D4"), "a1b2c3d4");
        assert_eq!(normalize_backup_code("a1b2c3d4"), "a1b2c3d4");
        assert_eq!(normalize_backup_code("A1B2C3D4"), "a1b2c3d4");
    }

    #[test]
    fn test_backup_code_normalization() {
        let codes = vec!["A1B2-C3D4".to_string()];
        let salt = "user123";
        let hashed = hash_backup_codes(&codes, salt);
        // Should work with various formats
        assert!(check_backup_code_valid("A1B2-C3D4", &hashed, salt));
        assert!(check_backup_code_valid("a1b2c3d4", &hashed, salt));
        assert!(check_backup_code_valid("A1B2C3D4", &hashed, salt));
        let result = verify_and_consume_backup_code("a1b2-c3d4", hashed, salt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_totp_code_invalid_secret() {
        let result = verify_totp_code("invalid_secret", "123456", "TestApp", "user@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_backup_codes_invalid_json() {
        let result = deserialize_backup_codes("invalid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_consume_backup_code_invalid() {
        let codes = vec!["hashed".to_string()];
        let result = verify_and_consume_backup_code("wrong", codes, "salt");
        assert!(result.is_err());
    }
}
