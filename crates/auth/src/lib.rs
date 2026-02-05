// Minimal auth service implementation for Phase B-03
// This provides the core password hashing functionality

pub mod password;

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
