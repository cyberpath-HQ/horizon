//! # MFA Data Transfer Objects
//!
//! Request and response types for Multi-Factor Authentication endpoints.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request to enable MFA - triggers TOTP secret generation
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct MfaEnableRequest {
    /// Current password for verification before enabling MFA
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Response after initiating MFA setup (before verification)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaSetupResponse {
    /// Whether the operation was successful
    pub success:        bool,
    /// Base32-encoded TOTP secret for manual entry
    pub secret:         String,
    /// otpauth:// URI for authenticator apps
    pub otpauth_uri:    String,
    /// Base64-encoded QR code PNG image
    pub qr_code_base64: String,
    /// Backup codes for account recovery (only shown once)
    pub backup_codes:   Vec<String>,
}

/// Request to verify and finalize MFA setup, or verify MFA on login
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct MfaVerifyRequest {
    /// The 6-digit TOTP code from authenticator app
    #[validate(length(equal = 6, message = "TOTP code must be exactly 6 digits"))]
    pub code: String,
}

/// Request to verify MFA using a backup code
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct MfaBackupCodeRequest {
    /// The backup code (format: XXXX-XXXX-XXXX-XXXX or without hyphens)
    #[validate(length(
        min = 16,
        max = 19,
        message = "Backup code must be 16-19 characters (XXXX-XXXX-XXXX-XXXX format or without hyphens)"
    ))]
    pub backup_code: String,
}

/// Request to disable MFA
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct MfaDisableRequest {
    /// Current password for verification
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    /// TOTP code or backup code for MFA verification
    #[validate(length(min = 1, message = "Verification code is required"))]
    pub code:     String,
}

/// Response for MFA verification success (on login)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaVerifyResponse {
    /// Whether the verification was successful
    pub success: bool,
    /// Authentication tokens (issued after successful MFA verification)
    pub tokens:  Option<super::auth::AuthTokens>,
    /// Authenticated user information
    pub user:    Option<super::auth::AuthenticatedUser>,
}

/// Response for regenerated backup codes
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaBackupCodesResponse {
    /// Whether the operation was successful
    pub success:      bool,
    /// New backup codes (only shown once)
    pub backup_codes: Vec<String>,
    /// Count of backup codes generated
    pub count:        usize,
}

/// Response for MFA status check
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaStatusResponse {
    /// Whether MFA is enabled
    pub mfa_enabled:            bool,
    /// Number of remaining backup codes
    pub backup_codes_remaining: usize,
}

/// Login response that may require MFA
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoginMfaResponse {
    /// Whether login was successful (false if MFA is required)
    pub success:      bool,
    /// Whether MFA verification is required to complete login
    pub mfa_required: bool,
    /// Temporary token for MFA verification (short-lived, only valid for MFA verify endpoint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token:    Option<String>,
    /// User info (partial, only id and email before MFA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user:         Option<super::auth::AuthenticatedUser>,
    /// Tokens (only present when MFA is not required or after MFA verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens:       Option<super::auth::AuthTokens>,
}
