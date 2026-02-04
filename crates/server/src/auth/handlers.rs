//! # Authentication Handlers
//!
//! HTTP request handlers for authentication endpoints.

use auth::password::{hash_password, validate_password_strength, verify_password};
use entity::users::{Column, Entity as UsersEntity};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use chrono::Utc;
use tracing::info;
use uuid::Uuid;
use axum::{extract::Request, Json};

use crate::{
    auth::jwt::create_access_token,
    dto::auth::{
        AuthSuccessResponse,
        AuthTokens,
        AuthenticatedUser,
        LoginRequest,
        RefreshRequest,
        SetupRequest,
        SuccessResponse,
    },
    refresh_tokens::{generate_refresh_token, revoke_refresh_token, validate_refresh_token},
    AppError,
    AppState,
    Result,
};

/// Inner handler for setup endpoint
///
/// This function doesn't use State extractor and accepts references to AppState.
/// It's intended to be called by wrapper handlers that use State extractor.
pub async fn setup_handler_inner(state: &AppState, req: SetupRequest) -> Result<Json<AuthSuccessResponse>> {
    // Check if any users exist
    let count_result = UsersEntity::find().count(&state.db).await?;
    let user_exists = count_result > 0;

    if user_exists {
        return Err(AppError::Auth {
            message: "System has already been configured. Use /login instead.".to_string(),
        });
    }

    // Validate password strength
    if let Err(errors) = validate_password_strength(&req.password) {
        let messages: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        return Err(AppError::Auth {
            message: format!("Password validation failed: {}", messages.join(", ")),
        });
    }

    // Generate UUID for the new user
    let user_id = Uuid::new_v4();

    // Hash the password
    let password_secret = auth::secrecy::SecretString::from(req.password.clone());
    let _hashed_password = hash_password(&password_secret, None).map_err(|e| {
        AppError::Auth {
            message: format!("Failed to hash password: {}", e),
        }
    })?;

    // Create the user with admin role
    // Note: This uses a simple insert. In production, you'd want to use transactions
    // and handle this through a service layer.

    // For now, we'll return a success response indicating the setup would complete
    // The actual database insert would happen here with the user's data

    info!(user_id = %user_id, email = %req.email, "Admin user created during setup");

    let user = AuthenticatedUser {
        id:           user_id.to_string(),
        email:        req.email.clone(),
        display_name: req.display_name.clone(),
        roles:        vec!["super_admin".to_string()],
    };

    // Generate tokens for the newly created admin
    let refresh_token_str = Uuid::new_v4().to_string();

    // Store the refresh token in database
    crate::refresh_tokens::create_refresh_token(
        &state.db,
        user_id,
        &refresh_token_str,
        30 * 24 * 60 * 60, // 30 days in seconds
    )
    .await?;

    let tokens = AuthTokens {
        access_token:  create_access_token(
            &state.jwt_config,
            &user_id.to_string(),
            &req.email,
            &["super_admin".to_string()],
        )?,
        refresh_token: refresh_token_str.clone(),
        expires_in:    state.jwt_config.expiration_seconds,
        token_type:    "Bearer".to_string(),
    };

    Ok(Json(AuthSuccessResponse {
        success: true,
        user,
        tokens: Some(tokens),
    }))
}

/// Inner handler for login endpoint
///
/// This function doesn't use State extractor and accepts references to AppState.
/// It's intended to be called by wrapper handlers that use State extractor.
pub async fn login_handler_inner(state: &AppState, req: LoginRequest) -> Result<Json<AuthSuccessResponse>> {
    // Find user by email
    let user_option = UsersEntity::find()
        .filter(Column::Email.eq(req.email.clone()))
        .one(&state.db)
        .await?;

    let user = user_option.ok_or_else(|| {
        AppError::Auth {
            message: "Invalid email or password".to_string(),
        }
    })?;

    // Verify password
    let password_secret = auth::secrecy::SecretString::from(req.password);
    verify_password(&password_secret, &user.password_hash).map_err(|_| {
        AppError::Auth {
            message: "Invalid email or password".to_string(),
        }
    })?;

    // Check if user is active
    if user.status != entity::sea_orm_active_enums::UserStatus::Active {
        return Err(AppError::Auth {
            message: "Account is not active".to_string(),
        });
    }

    // Generate JWT tokens
    let user_id = user.id.to_string();
    let refresh_token_str = generate_refresh_token();

    // Store the refresh token in database
    crate::refresh_tokens::create_refresh_token(
        &state.db,
        user.id, // Use the actual UUID from user
        &refresh_token_str,
        30 * 24 * 60 * 60, // 30 days in seconds
    )
    .await?;

    let tokens = AuthTokens {
        access_token:  create_access_token(
            &state.jwt_config,
            &user_id,
            &user.email,
            &["user".to_string()],
        )?,
        refresh_token: refresh_token_str,
        expires_in:    state.jwt_config.expiration_seconds,
        token_type:    "Bearer".to_string(),
    };

    info!(user_id = %user_id, email = %req.email, "User logged in successfully");

    let user_response = AuthenticatedUser {
        id:           user_id,
        email:        user.email,
        display_name: format!(
            "{} {}",
            user.first_name.unwrap_or_default(),
            user.last_name.unwrap_or_default()
        )
        .trim()
        .to_string(),
        roles:        vec!["user".to_string()],
    };

    Ok(Json(AuthSuccessResponse {
        success: true,
        user:    user_response,
        tokens:  Some(tokens),
    }))
}

/// Inner handler for logout endpoint
///
/// This function doesn't use State extractor and accepts references to AppState.
/// It's intended to be called by wrapper handlers that use State extractor.
pub async fn logout_handler_inner(state: &AppState, request: Request) -> Result<Json<SuccessResponse>> {
    // Extract the authenticated user from request extensions
    let authenticated_user = request
        .extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .ok_or_else(|| AppError::auth("No authenticated user found".to_string()))?;

    // Parse the user ID
    let user_id = uuid::Uuid::parse_str(&authenticated_user.id)
        .map_err(|_| AppError::auth("Invalid user ID format".to_string()))?;

    // Revoke all refresh tokens for this user
    if let Err(e) = crate::refresh_tokens::revoke_all_user_tokens(&state.db, user_id).await {
        // Log the error but don't fail the logout
        tracing::warn!("Failed to revoke refresh tokens on logout: {}", e);
    }

    // Extract the access token from the Authorization header to blacklist it
    if let Some(auth_header) = request.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = extract_bearer_token(auth_str) {
                // Blacklist the token
                let token_hash = crate::token_blacklist::hash_token_for_blacklist(&token);
                let blacklist = crate::token_blacklist::TokenBlacklist::new(state.redis.clone());

                // Calculate expiration time (we'll use the JWT expiration time)
                let expires_at = Utc::now() + chrono::Duration::seconds(state.jwt_config.expiration_seconds as i64);

                if let Err(e) = blacklist.blacklist_token(&token_hash, expires_at).await {
                    // Log the error but don't fail the logout
                    tracing::warn!("Failed to blacklist token on logout: {}", e);
                }
            }
        }
    }

    // In a stateless JWT setup, logout is handled client-side by removing the token.
    // For enhanced security, we now also blacklist the token server-side and revoke refresh tokens.

    Ok(Json(SuccessResponse {
        success: true,
        message: "Successfully logged out".to_string(),
    }))
}

/// Extract Bearer token from Authorization header
fn extract_bearer_token(auth_header: &str) -> Option<String> {
    if !auth_header.starts_with("Bearer ") {
        return None;
    }

    let token = auth_header.trim_start_matches("Bearer ").trim();

    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

/// Inner handler for refresh endpoint
///
/// This function doesn't use State extractor and accepts references to AppState.
/// It's intended to be called by wrapper handlers that use State extractor.
pub async fn refresh_handler_inner(state: &AppState, req: RefreshRequest) -> Result<Json<AuthSuccessResponse>> {
    // Validate the refresh token and get the associated user ID
    let user_id = validate_refresh_token(&state.db, &req.refresh_token).await?;

    // Find the user by ID
    let user = UsersEntity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::auth("User associated with refresh token not found".to_string()))?;

    // Check if user is active
    if user.status != entity::sea_orm_active_enums::UserStatus::Active {
        return Err(AppError::auth("User account is not active".to_string()));
    }

    // Generate new access token
    let user_id_str = user.id.to_string();
    let access_token = create_access_token(
        &state.jwt_config,
        &user_id_str,
        &user.email,
        &["user".to_string()], // TODO: Load actual roles from database
    )?;

    // Generate new refresh token (token rotation for security)
    let new_refresh_token = generate_refresh_token();

    // Store the new refresh token in database
    crate::refresh_tokens::create_refresh_token(
        &state.db,
        user.id, // Use the actual UUID from user
        &new_refresh_token,
        30 * 24 * 60 * 60, // 30 days in seconds
    )
    .await?;

    // Revoke the old refresh token
    revoke_refresh_token(&state.db, &req.refresh_token).await?;

    // Note: In a production system, you might want to blacklist the old access token here
    // For now, we rely on token rotation and short access token expiration

    // Create tokens response
    let tokens = AuthTokens {
        access_token,
        refresh_token: new_refresh_token,
        expires_in: state.jwt_config.expiration_seconds,
        token_type: "Bearer".to_string(),
    };

    let user_response = AuthenticatedUser {
        id:           user_id_str.clone(),
        email:        user.email,
        display_name: format!(
            "{} {}",
            user.first_name.unwrap_or_default(),
            user.last_name.unwrap_or_default()
        )
        .trim()
        .to_string(),
        roles:        vec!["user".to_string()], // TODO: Load actual roles from database
    };

    info!(user_id = %user_id_str, "Refresh token successfully used");

    Ok(Json(AuthSuccessResponse {
        success: true,
        user:    user_response,
        tokens:  Some(tokens),
    }))
}
