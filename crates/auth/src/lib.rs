//! # Authentication Service
//!
//! Comprehensive authentication and authorization system including:
//! - JWT token management
//! - Password hashing and validation
//! - Role-based permissions
//! - API key management
//! - User and team management

pub mod jwt;
pub mod mfa;
pub mod password;
pub mod permissions;
pub mod roles;

// Re-export commonly used types
pub use permissions::{ApiKeyAction, Permission, PermissionService, TeamAction, UserAction};
pub use jwt::{create_access_token, extract_bearer_token, validate_token, Claims, JwtConfig};
pub use password::{hash_password, validate_password_strength, verify_password};
pub use roles::{assign_role_to_user, get_user_roles};
pub use mfa::{
    check_backup_code_valid,
    deserialize_backup_codes,
    generate_backup_codes,
    generate_mfa_setup,
    hash_backup_codes,
    serialize_backup_codes,
    verify_and_consume_backup_code,
    verify_totp_code,
};
pub use secrecy;
pub use subtle;

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};

    use super::password::{hash_password, validate_password_strength, verify_password};

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
