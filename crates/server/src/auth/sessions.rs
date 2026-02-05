//! # Session Management Handlers
//!
//! HTTP request handlers for session management endpoints.
//! Users can view their active sessions and logout from specific sessions or all sessions.

use axum::{extract::Path, Json};
use entity::user_sessions::{Column, Entity as UserSessionsEntity};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use tracing::info;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;

/// Response for session list
#[derive(Debug, Serialize)]
pub struct SessionsResponse {
    pub success:  bool,
    pub sessions: Vec<SessionInfo>,
}

/// Information about a single session
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id:           String,
    pub user_agent:   Option<String>,
    pub ip_address:   Option<String>,
    pub created_at:   chrono::DateTime<chrono::Utc>,
    pub last_used_at: chrono::DateTime<chrono::Utc>,
}

/// Get all sessions for the authenticated user
pub async fn get_sessions_handler(
    state: &crate::AppState,
    authenticated_user: AuthenticatedUser,
) -> crate::Result<Json<SessionsResponse>> {
    let user_id = Uuid::parse_str(&authenticated_user.id)
        .map_err(|_| crate::AppError::auth("Invalid user ID format".to_string()))?;

    // Query all sessions for this user
    let sessions = UserSessionsEntity::find()
        .filter(Column::UserId.eq(user_id))
        .all(&state.db)
        .await
        .map_err(|e| crate::AppError::database(format!("Failed to fetch sessions: {}", e)))?;

    // Convert to response format
    let session_infos: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|session| {
            SessionInfo {
                id:           session.id.to_string(),
                user_agent:   session.user_agent,
                ip_address:   session.ip_address,
                created_at:   session.created_at.and_utc(),
                last_used_at: session.last_used_at.and_utc(),
            }
        })
        .collect();

    info!(
        user_id = %user_id,
        session_count = session_infos.len(),
        "Retrieved user sessions"
    );

    Ok(Json(SessionsResponse {
        success:  true,
        sessions: session_infos,
    }))
}

/// Delete a specific session
pub async fn delete_session_handler(
    state: &crate::AppState,
    authenticated_user: AuthenticatedUser,
    Path(session_id): Path<String>,
) -> crate::Result<Json<crate::dto::auth::SuccessResponse>> {
    let user_id = Uuid::parse_str(&authenticated_user.id)
        .map_err(|_| crate::AppError::auth("Invalid user ID format".to_string()))?;

    let session_uuid = Uuid::parse_str(&session_id)
        .map_err(|_| crate::AppError::bad_request("Invalid session ID format".to_string()))?;

    // Find the session
    let session = UserSessionsEntity::find()
        .filter(Column::Id.eq(session_uuid))
        .one(&state.db)
        .await
        .map_err(|e| crate::AppError::database(format!("Failed to find session: {}", e)))?
        .ok_or_else(|| crate::AppError::not_found("Session not found".to_string()))?;

    // Verify the session belongs to the authenticated user
    if session.user_id != user_id {
        return Err(crate::AppError::forbidden(
            "Session does not belong to authenticated user".to_string(),
        ));
    }

    // Delete the session
    UserSessionsEntity::delete_by_id(session_uuid)
        .exec(&state.db)
        .await
        .map_err(|e| crate::AppError::database(format!("Failed to delete session: {}", e)))?;

    info!(
        user_id = %user_id,
        session_id = %session_id,
        "Session deleted"
    );

    Ok(Json(crate::dto::auth::SuccessResponse {
        success: true,
        message: format!("Session {} deleted successfully", session_id),
    }))
}

/// Delete all sessions for the authenticated user (logout everywhere)
pub async fn delete_all_sessions_handler(
    state: &crate::AppState,
    authenticated_user: AuthenticatedUser,
) -> crate::Result<Json<crate::dto::auth::SuccessResponse>> {
    let user_id = Uuid::parse_str(&authenticated_user.id)
        .map_err(|_| crate::AppError::auth("Invalid user ID format".to_string()))?;

    // Delete all sessions
    let delete_result = UserSessionsEntity::delete_many()
        .filter(Column::UserId.eq(user_id))
        .exec(&state.db)
        .await
        .map_err(|e| crate::AppError::database(format!("Failed to delete sessions: {}", e)))?;

    info!(
        user_id = %user_id,
        deleted_count = delete_result.rows_affected,
        "All user sessions deleted"
    );

    Ok(Json(crate::dto::auth::SuccessResponse {
        success: true,
        message: format!(
            "All {} sessions deleted successfully",
            delete_result.rows_affected
        ),
    }))
}
