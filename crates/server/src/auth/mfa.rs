//! # MFA Handlers
//!
//! HTTP request handlers for Multi-Factor Authentication endpoints.

const REFRESH_TOKEN_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

use auth::{
    jwt::create_access_token,
    mfa::{
        deserialize_backup_codes,
        generate_backup_codes,
        generate_mfa_setup,
        hash_backup_codes,
        serialize_backup_codes,
        verify_and_consume_backup_code,
        verify_totp_code,
    },
    password::verify_password,
};
use axum::Json;
use chrono::Utc;
use entity::users::Entity as UsersEntity;
use error::{AppError, Result};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tracing::debug;
use validator::Validate;

use crate::{
    dto::{
        auth::{AuthTokens, AuthenticatedUser, SuccessResponse},
        mfa::{
            MfaBackupCodeRequest,
            MfaBackupCodesResponse,
            MfaDisableRequest,
            MfaEnableRequest,
            MfaSetupResponse,
            MfaStatusResponse,
            MfaVerifyRequest,
            MfaVerifyResponse,
        },
    },
    middleware::auth::AuthenticatedUser as MiddlewareUser,
    refresh_tokens::generate_refresh_token,
    AppState,
};

/// MFA issuer name used in TOTP URIs
const MFA_ISSUER: &str = "Horizon";

/// Enable MFA for the authenticated user - generates TOTP secret and backup codes
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - MFA enable request containing current password
///
/// # Returns
///
/// MFA setup response with secret, QR code, and backup codes
pub async fn mfa_enable_handler(
    state: &AppState,
    user: MiddlewareUser,
    req: MfaEnableRequest,
) -> Result<Json<MfaSetupResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Find the user
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    // Check if MFA is already enabled
    if db_user.mfa_enabled {
        return Err(AppError::conflict(
            "MFA is already enabled for this account",
        ));
    }

    // Verify current password
    let password_secret = auth::secrecy::SecretString::from(req.password);
    verify_password(&password_secret, &db_user.password_hash)
        .map_err(|_| AppError::unauthorized("Invalid password"))?;

    // Generate MFA setup (secret, QR code, backup codes)
    let setup = generate_mfa_setup(MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("Failed to generate MFA setup: {}", e)))?;

    // Hash backup codes for storage
    let hashed_codes = hash_backup_codes(&setup.backup_codes, &db_user.id);
    let codes_json = serialize_backup_codes(&hashed_codes)
        .map_err(|e| AppError::internal(format!("Failed to serialize backup codes: {}", e)))?;

    // Store the TOTP secret and backup codes (but don't enable MFA yet - user must verify first)
    let mut active_model: entity::users::ActiveModel = db_user.into();
    active_model.totp_secret = Set(Some(setup.secret.clone()));
    active_model.backup_codes = Set(Some(codes_json));
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update user MFA settings: {}", e)))?;

    debug!(user_id = %user.id, "MFA setup initiated, awaiting verification");

    Ok(Json(MfaSetupResponse {
        success:        true,
        secret:         setup.secret,
        otpauth_uri:    setup.otpauth_uri,
        qr_code_base64: setup.qr_code_base64,
        backup_codes:   setup.backup_codes,
    }))
}

/// Verify TOTP code to finalize MFA setup (called after enable)
///
/// This endpoint finalizes MFA setup by verifying the user can generate valid codes.
/// After successful verification, MFA is marked as enabled.
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - MFA verify request containing the TOTP code
///
/// # Returns
///
/// Success response if the code is valid and MFA is enabled
pub async fn mfa_verify_setup_handler(
    state: &AppState,
    user: MiddlewareUser,
    req: MfaVerifyRequest,
) -> Result<Json<SuccessResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Find the user
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    // Get the TOTP secret (must have been set during enable step)
    let totp_secret = db_user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::bad_request("MFA setup has not been initiated"))?;

    // Check if MFA is already enabled (this endpoint is for finalizing setup)
    if db_user.mfa_enabled {
        return Err(AppError::conflict("MFA is already enabled"));
    }

    // Verify the TOTP code
    let is_valid = verify_totp_code(totp_secret, &req.code, MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("TOTP verification error: {}", e)))?;

    if !is_valid {
        return Err(AppError::unauthorized(
            "Invalid verification code. Please try again with a new code from your authenticator app.",
        ));
    }

    // Enable MFA
    let mut active_model: entity::users::ActiveModel = db_user.into();
    active_model.mfa_enabled = Set(true);
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to enable MFA: {}", e)))?;

    debug!(user_id = %user.id, "MFA successfully enabled");

    Ok(Json(SuccessResponse {
        success: true,
        message: "MFA has been successfully enabled".to_string(),
    }))
}

/// Verify MFA during login (when MFA is enabled and user has an mfa_token)
///
/// # Arguments
///
/// * `state` - Application state
/// * `mfa_token` - Temporary token from login response
/// * `req` - MFA verify request
///
/// # Returns
///
/// MFA verify response with full authentication tokens
pub async fn mfa_verify_login_handler(
    state: &AppState,
    mfa_token: &str,
    req: MfaVerifyRequest,
) -> Result<Json<MfaVerifyResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Validate the MFA token (it's a short-lived JWT with special claims)
    let claims = auth::jwt::validate_token(&state.jwt_config, mfa_token)?;

    // Ensure this is an MFA token (check for mfa_pending role)
    if !claims.roles.contains(&"mfa_pending".to_string()) {
        return Err(AppError::unauthorized("Invalid MFA token"));
    }

    // Find the user
    let db_user = UsersEntity::find_by_id(&claims.sub)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::unauthorized("User not found"))?;

    // Get TOTP secret
    let totp_secret = db_user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::internal("MFA is enabled but no TOTP secret found"))?;

    // Verify the code
    let is_valid = verify_totp_code(totp_secret, &req.code, MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("TOTP verification error: {}", e)))?;

    if !is_valid {
        return Err(AppError::unauthorized("Invalid MFA code"));
    }

    // Load actual user roles
    let user_roles = auth::roles::get_user_roles(&state.db, &db_user.id).await?;

    // Generate full authentication tokens
    let refresh_token_str = generate_refresh_token();
    crate::refresh_tokens::create_refresh_token(
        &state.db,
        &db_user.id,
        &refresh_token_str,
        REFRESH_TOKEN_TTL_SECONDS,
    )
    .await?;

    let tokens = AuthTokens {
        access_token:  create_access_token(&state.jwt_config, &db_user.id, &db_user.email, &user_roles)?,
        refresh_token: refresh_token_str,
        expires_in:    state.jwt_config.expiration_seconds,
        token_type:    "Bearer".to_string(),
    };

    let user_response = AuthenticatedUser {
        id:           db_user.id.clone(),
        email:        db_user.email,
        display_name: format!(
            "{} {}",
            db_user.first_name.unwrap_or_default(),
            db_user.last_name.unwrap_or_default()
        )
        .trim()
        .to_string(),
        roles:        user_roles,
    };

    debug!(user_id = %db_user.id, "MFA verification successful, login complete");

    Ok(Json(MfaVerifyResponse {
        success: true,
        tokens:  Some(tokens),
        user:    Some(user_response),
    }))
}

/// Verify MFA using a backup code during login
///
/// # Arguments
///
/// * `state` - Application state
/// * `mfa_token` - Temporary token from login response
/// * `req` - Backup code request
///
/// # Returns
///
/// MFA verify response with full authentication tokens
pub async fn mfa_verify_backup_code_handler(
    state: &AppState,
    mfa_token: &str,
    req: MfaBackupCodeRequest,
) -> Result<Json<MfaVerifyResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Validate the MFA token
    let claims = auth::jwt::validate_token(&state.jwt_config, mfa_token)?;

    if !claims.roles.contains(&"mfa_pending".to_string()) {
        return Err(AppError::unauthorized("Invalid MFA token"));
    }

    // Find the user
    let db_user = UsersEntity::find_by_id(&claims.sub)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::unauthorized("User not found"))?;

    // Get and verify the backup code
    let codes_json = db_user
        .backup_codes
        .as_ref()
        .map(|v| v.to_string())
        .ok_or_else(|| AppError::bad_request("No backup codes available"))?;

    let hashed_codes = deserialize_backup_codes(&codes_json)
        .map_err(|e| AppError::internal(format!("Failed to parse backup codes: {}", e)))?;

    let remaining_codes = verify_and_consume_backup_code(&req.backup_code, hashed_codes, &db_user.id)
        .map_err(|_| AppError::unauthorized("Invalid backup code"))?;

    // Update the backup codes in database
    let updated_codes_json = serialize_backup_codes(&remaining_codes)
        .map_err(|e| AppError::internal(format!("Failed to serialize backup codes: {}", e)))?;

    let mut active_model: entity::users::ActiveModel = db_user.clone().into();
    active_model.backup_codes = Set(Some(updated_codes_json));
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update backup codes: {}", e)))?;

    // Load user roles and generate tokens
    let user_roles = auth::roles::get_user_roles(&state.db, &db_user.id).await?;

    let refresh_token_str = generate_refresh_token();
    crate::refresh_tokens::create_refresh_token(
        &state.db,
        &db_user.id,
        &refresh_token_str,
        30 * 24 * 60 * 60,
    )
    .await?;

    let tokens = AuthTokens {
        access_token:  create_access_token(&state.jwt_config, &db_user.id, &db_user.email, &user_roles)?,
        refresh_token: refresh_token_str,
        expires_in:    state.jwt_config.expiration_seconds,
        token_type:    "Bearer".to_string(),
    };

    let user_response = AuthenticatedUser {
        id:           db_user.id.clone(),
        email:        db_user.email.clone(),
        display_name: format!(
            "{} {}",
            db_user.first_name.unwrap_or_default(),
            db_user.last_name.unwrap_or_default()
        )
        .trim()
        .to_string(),
        roles:        user_roles,
    };

    debug!(
        user_id = %db_user.id,
        remaining_codes = remaining_codes.len(),
        "MFA backup code used successfully"
    );

    Ok(Json(MfaVerifyResponse {
        success: true,
        tokens:  Some(tokens),
        user:    Some(user_response),
    }))
}

/// Disable MFA for the authenticated user
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - Disable request with password and verification code
///
/// # Returns
///
/// Success response
pub async fn mfa_disable_handler(
    state: &AppState,
    user: MiddlewareUser,
    req: MfaDisableRequest,
) -> Result<Json<SuccessResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Find the user
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    // Check if MFA is actually enabled
    if !db_user.mfa_enabled {
        return Err(AppError::bad_request("MFA is not enabled"));
    }

    // Verify current password
    let password_secret = auth::secrecy::SecretString::from(req.password);
    verify_password(&password_secret, &db_user.password_hash)
        .map_err(|_| AppError::unauthorized("Invalid password"))?;

    // Verify the provided code (either TOTP or backup code)
    let totp_secret = db_user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::internal("MFA enabled but no TOTP secret"))?;

    let totp_valid = verify_totp_code(totp_secret, &req.code, MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("TOTP verification error: {}", e)))?;

    if !totp_valid {
        // Try as backup code
        let codes_json = db_user.backup_codes.as_ref().map(|v| v.to_string());

        let backup_valid = if let Some(json) = codes_json {
            if let Ok(hashed_codes) = deserialize_backup_codes(&json) {
                auth::mfa::check_backup_code_valid(&req.code, &hashed_codes, &db_user.id)
            }
            else {
                false
            }
        }
        else {
            false
        };

        if !backup_valid {
            return Err(AppError::unauthorized(
                "Invalid verification code. Provide a valid TOTP code or backup code.",
            ));
        }
    }

    // Disable MFA - clear secret and backup codes
    let mut active_model: entity::users::ActiveModel = db_user.into();
    active_model.mfa_enabled = Set(false);
    active_model.totp_secret = Set(None);
    active_model.backup_codes = Set(None);
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to disable MFA: {}", e)))?;

    debug!(user_id = %user.id, "MFA disabled");

    Ok(Json(SuccessResponse {
        success: true,
        message: "MFA has been disabled".to_string(),
    }))
}

/// Regenerate backup codes for the authenticated user
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - MFA verify request (current TOTP code required for security)
///
/// # Returns
///
/// New set of backup codes
pub async fn mfa_regenerate_backup_codes_handler(
    state: &AppState,
    user: MiddlewareUser,
    req: MfaVerifyRequest,
) -> Result<Json<MfaBackupCodesResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Find the user
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    // Check if MFA is enabled
    if !db_user.mfa_enabled {
        return Err(AppError::bad_request("MFA is not enabled"));
    }

    // Verify the TOTP code
    let totp_secret = db_user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::internal("MFA enabled but no TOTP secret"))?;

    let is_valid = verify_totp_code(totp_secret, &req.code, MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("TOTP verification error: {}", e)))?;

    if !is_valid {
        return Err(AppError::unauthorized("Invalid TOTP code"));
    }

    // Generate new backup codes
    let new_codes = generate_backup_codes();
    let hashed = hash_backup_codes(&new_codes, &db_user.id);
    let codes_json = serialize_backup_codes(&hashed)
        .map_err(|e| AppError::internal(format!("Failed to serialize backup codes: {}", e)))?;

    // Update in database
    let mut active_model: entity::users::ActiveModel = db_user.into();
    active_model.backup_codes = Set(Some(codes_json));
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update backup codes: {}", e)))?;

    let count = new_codes.len();
    debug!(user_id = %user.id, count, "Backup codes regenerated");

    Ok(Json(MfaBackupCodesResponse {
        success: true,
        backup_codes: new_codes,
        count,
    }))
}

/// Get MFA status for the authenticated user
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
///
/// # Returns
///
/// MFA status response
pub async fn mfa_status_handler(state: &AppState, user: MiddlewareUser) -> Result<Json<MfaStatusResponse>> {
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let backup_codes_remaining = if let Some(codes_value) = &db_user.backup_codes {
        deserialize_backup_codes(&codes_value.to_string())
            .map(|c| c.len())
            .unwrap_or(0)
    }
    else {
        0
    };

    Ok(Json(MfaStatusResponse {
        mfa_enabled: db_user.mfa_enabled,
        backup_codes_remaining,
    }))
}

/// Handle MFA setup when required by global policy
///
/// This endpoint is used when a user logs in and global MFA is enforced,
/// but the user hasn't set up MFA yet. It:
/// 1. Verifies the user's password
/// 2. Generates MFA secret and backup codes
/// 3. Verifies the TOTP code
/// 4. Enables MFA for the user
/// 5. Returns full authentication tokens
///
/// # Arguments
///
/// * `state` - Application state
/// * `mfa_token` - Temporary token from login response (with mfa_required role)
/// * `req` - MFA setup enforce request containing password and TOTP code
///
/// # Returns
///
/// MFA setup response with full authentication tokens
pub async fn mfa_enforce_setup_handler(
    state: &AppState,
    mfa_token: &str,
    req: crate::dto::mfa::MfaSetupEnforceRequest,
) -> Result<Json<crate::dto::mfa::MfaSetupResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Validate the MFA token (it's a short-lived JWT with special claims)
    let claims = auth::jwt::validate_token(&state.jwt_config, mfa_token)?;

    // Ensure this is an MFA required token (check for mfa_required role)
    if !claims.roles.contains(&"mfa_required".to_string()) {
        return Err(AppError::unauthorized("Invalid MFA enforcement token"));
    }

    // Find the user
    let db_user = UsersEntity::find_by_id(&claims.sub)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::unauthorized("User not found"))?;

    // Check if MFA is already enabled
    if db_user.mfa_enabled {
        return Err(AppError::conflict(
            "MFA is already enabled for this account",
        ));
    }

    // Verify current password
    let password_secret = auth::secrecy::SecretString::from(req.password.clone());
    verify_password(&password_secret, &db_user.password_hash)
        .map_err(|_| AppError::unauthorized("Invalid password"))?;

    // Generate MFA setup (secret, QR code, backup codes)
    let setup = generate_mfa_setup(MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("Failed to generate MFA setup: {}", e)))?;

    // Verify the TOTP code before enabling
    let is_valid = verify_totp_code(&setup.secret, &req.code, MFA_ISSUER, &db_user.email)
        .map_err(|e| AppError::internal(format!("TOTP verification error: {}", e)))?;

    if !is_valid {
        return Err(AppError::unauthorized(
            "Invalid verification code. Please try again with a new code from your authenticator app.",
        ));
    }

    // Hash backup codes for storage
    let hashed_codes = hash_backup_codes(&setup.backup_codes, &db_user.id);
    let codes_json = serialize_backup_codes(&hashed_codes)
        .map_err(|e| AppError::internal(format!("Failed to serialize backup codes: {}", e)))?;

    // Enable MFA directly (user has verified the code)
    let user_id = db_user.id.clone();
    let user_email = db_user.email.clone();
    let mut active_model: entity::users::ActiveModel = db_user.into();
    let secret_clone = setup.secret.clone();
    active_model.totp_secret = Set(Some(setup.secret));
    active_model.backup_codes = Set(Some(codes_json));
    active_model.mfa_enabled = Set(true);
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to enable MFA: {}", e)))?;

    // Load actual user roles and generate full tokens
    let user_roles = auth::roles::get_user_roles(&state.db, &user_id).await?;

    let refresh_token_str = generate_refresh_token();
    crate::refresh_tokens::create_refresh_token(
        &state.db,
        &user_id,
        &refresh_token_str,
        REFRESH_TOKEN_TTL_SECONDS,
    )
    .await?;

    let _tokens = crate::dto::auth::AuthTokens {
        access_token:  create_access_token(&state.jwt_config, &user_id, &user_email, &user_roles)?,
        refresh_token: refresh_token_str,
        expires_in:    state.jwt_config.expiration_seconds,
        token_type:    "Bearer".to_string(),
    };

    debug!(user_id = %user_id, "MFA enforcement setup completed, full login issued");

    // Return the setup response with success=true (indicating full login complete)
    Ok(Json(crate::dto::mfa::MfaSetupResponse {
        success:        true,
        secret:         secret_clone,
        otpauth_uri:    setup.otpauth_uri,
        qr_code_base64: setup.qr_code_base64,
        backup_codes:   setup.backup_codes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::mfa::{MfaBackupCodeRequest, MfaDisableRequest, MfaEnableRequest, MfaVerifyRequest};

    #[test]
    fn test_mfa_issuer_constant() {
        assert_eq!(MFA_ISSUER, "Horizon");
    }

    #[test]
    fn test_mfa_enable_request_fields() {
        let req = MfaEnableRequest {
            password: "testpass123".to_string(),
        };
        assert_eq!(req.password, "testpass123");
    }

    #[test]
    fn test_mfa_verify_request_fields() {
        let req = MfaVerifyRequest {
            code: "123456".to_string(),
        };
        assert_eq!(req.code, "123456");
    }

    #[test]
    fn test_mfa_disable_request_fields() {
        let req = MfaDisableRequest {
            password: "disablepass".to_string(),
            code:     "654321".to_string(),
        };
        assert_eq!(req.password, "disablepass");
        assert_eq!(req.code, "654321");
    }

    #[test]
    fn test_mfa_backup_code_request_fields() {
        let req = MfaBackupCodeRequest {
            backup_code: "abcd-efgh-ijkl".to_string(),
        };
        assert_eq!(req.backup_code, "abcd-efgh-ijkl");
    }

    #[test]
    fn test_mfa_setup_response_structure() {
        let response = MfaSetupResponse {
            success:        true,
            secret:         "SECRET123".to_string(),
            otpauth_uri:    "otpauth://totp/Horizon:test@example.com?secret=SECRET123".to_string(),
            qr_code_base64: "base64encoded".to_string(),
            backup_codes:   vec!["code1".to_string(), "code2".to_string()],
        };
        assert!(response.success);
        assert_eq!(response.secret, "SECRET123");
        assert!(response.otpauth_uri.contains("Horizon"));
        assert_eq!(response.backup_codes.len(), 2);
    }

    #[test]
    fn test_mfa_verify_response_structure() {
        let response = MfaVerifyResponse {
            success: true,
            user:    Some(AuthenticatedUser {
                id:           "usr_123".to_string(),
                email:        "test@example.com".to_string(),
                display_name: "Test User".to_string(),
                roles:        vec!["admin".to_string()],
            }),
            tokens:  Some(AuthTokens {
                access_token:  "access_token_here".to_string(),
                refresh_token: "refresh_token_here".to_string(),
                expires_in:    3600,
                token_type:    "Bearer".to_string(),
            }),
        };
        assert!(response.success);
        assert!(response.user.is_some());
        let user = response.user.unwrap();
        assert_eq!(user.id, "usr_123");
        assert!(response.tokens.is_some());
        let tokens = response.tokens.unwrap();
        assert_eq!(tokens.token_type, "Bearer");
        assert_eq!(tokens.expires_in, 3600);
    }

    #[test]
    fn test_mfa_verify_response_no_tokens() {
        let response = MfaVerifyResponse {
            success: false,
            user:    Some(AuthenticatedUser {
                id:           "usr_456".to_string(),
                email:        "fail@example.com".to_string(),
                display_name: "Fail User".to_string(),
                roles:        vec![],
            }),
            tokens:  None,
        };
        assert!(!response.success);
        assert!(response.tokens.is_none());
    }

    #[test]
    fn test_mfa_status_response_enabled() {
        let response = MfaStatusResponse {
            mfa_enabled:            true,
            backup_codes_remaining: 8,
        };
        assert!(response.mfa_enabled);
        assert_eq!(response.backup_codes_remaining, 8);
    }

    #[test]
    fn test_mfa_status_response_disabled() {
        let response = MfaStatusResponse {
            mfa_enabled:            false,
            backup_codes_remaining: 0,
        };
        assert!(!response.mfa_enabled);
        assert_eq!(response.backup_codes_remaining, 0);
    }

    #[test]
    fn test_mfa_backup_codes_response_structure() {
        let response = MfaBackupCodesResponse {
            success:      true,
            backup_codes: vec!["abc".to_string(), "def".to_string(), "ghi".to_string()],
            count:        3,
        };
        assert!(response.success);
        assert_eq!(response.backup_codes.len(), 3);
        assert_eq!(response.count, 3);
    }

    #[test]
    fn test_mfa_backup_codes_response_empty() {
        let response = MfaBackupCodesResponse {
            success:      true,
            backup_codes: vec![],
            count:        0,
        };
        assert!(response.success);
        assert!(response.backup_codes.is_empty());
        assert_eq!(response.count, 0);
    }

    #[test]
    fn test_mfa_issuer_not_empty() {
        assert!(!MFA_ISSUER.is_empty());
        assert!(!MFA_ISSUER.contains(' '));
    }
}
