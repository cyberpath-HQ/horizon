//! # Settings Handlers
//!
//! HTTP request handlers for system settings endpoints.

use axum::{extract::Path, Json};
use chrono::Utc;
use entity::system_settings::Entity as SystemSettingsEntity;
use error::{AppError, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use validator::Validate;

use crate::{middleware::auth::AuthenticatedUser, AppState};

/// Default system settings to seed on first run
const DEFAULT_SETTINGS: &[(&str, &str, &str)] = &[
    // Module settings - enable/disable core application modules
    (
        "module_assets",
        "true",
        "Enable or disable the Assets management module. This module provides inventory and asset tracking \
         capabilities.",
    ),
    (
        "module_software",
        "true",
        "Enable or disable the Software module. This module manages software inventory and license tracking.",
    ),
    (
        "module_security",
        "true",
        "Enable or disable the Security module. This module provides security configuration and policy management.",
    ),
    (
        "module_network",
        "true",
        "Enable or disable the Network module. This module handles network infrastructure mapping and monitoring.",
    ),
    (
        "module_vulnerabilities",
        "true",
        "Enable or disable the Vulnerabilities module. This module tracks and manages security vulnerabilities.",
    ),
    (
        "module_bia",
        "true",
        "Enable or disable the Business Impact Analysis module. This module manages BIA assessments and continuity \
         planning.",
    ),
    (
        "module_vendors",
        "true",
        "Enable or disable the Vendors module. This module manages vendor relationships and third-party risk.",
    ),
    // Security settings
    (
        "require_mfa",
        "false",
        "Require multi-factor authentication for all users. When enabled, all users must set up MFA to access the \
         system.",
    ),
];

/// Seed default settings if they don't exist
pub async fn seed_default_settings(state: &AppState) -> Result<()> {
    // Check if settings table is empty
    let count = SystemSettingsEntity::find().count(&state.db).await?;

    if count == 0 {
        info!("Seeding default system settings...");

        for (key, value, description) in DEFAULT_SETTINGS {
            let setting = entity::system_settings::ActiveModel {
                id:          Set(cuid2::cuid()),
                key:         Set(key.to_string()),
                value:       Set(value.to_string()),
                description: Set(Some(description.to_string())),
                updated_at:  Set(Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap())),
            };

            setting
                .insert(&state.db)
                .await
                .map_err(|e| AppError::database(format!("Failed to seed setting {}: {}", key, e)))?;
        }

        info!("Default system settings seeded successfully");
    }

    Ok(())
}

/// Response type for a single setting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingResponse {
    pub id:          String,
    pub key:         String,
    pub value:       String,
    pub description: Option<String>,
    pub updated_at:  String,
}

/// Response type for list of settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsListResponse {
    pub settings: Vec<SettingResponse>,
}

/// Request type for updating a setting
#[derive(Debug, Clone, Validate, Deserialize)]
pub struct UpdateSettingRequest {
    #[validate(length(min = 1, message = "Value cannot be empty"))]
    pub value: String,
}

/// Check if a setting is enabled (true/false)
pub async fn is_setting_enabled(state: &AppState, key: &str) -> Result<bool> {
    let setting = SystemSettingsEntity::find()
        .filter(entity::system_settings::Column::Key.eq(key))
        .one(&state.db)
        .await?;

    if let Some(s) = setting {
        Ok(s.value.to_lowercase() == "true")
    }
    else {
        Ok(false)
    }
}

/// Get a setting value by key
pub async fn get_setting_value(state: &AppState, key: &str) -> Result<Option<String>> {
    let setting = SystemSettingsEntity::find()
        .filter(entity::system_settings::Column::Key.eq(key))
        .one(&state.db)
        .await?;

    Ok(setting.map(|s| s.value))
}

/// List all system settings (super-admin only)
pub async fn list_settings_handler(state: &AppState, _user: AuthenticatedUser) -> Result<Json<SettingsListResponse>> {
    let settings = SystemSettingsEntity::find()
        .all(&state.db)
        .await?
        .into_iter()
        .map(|s| {
            SettingResponse {
                id:          s.id,
                key:         s.key,
                value:       s.value,
                description: s.description,
                updated_at:  s.updated_at.to_rfc3339(),
            }
        })
        .collect();

    debug!("Listed all system settings");

    Ok(Json(SettingsListResponse {
        settings,
    }))
}

/// Get a single setting by key (super-admin only)
pub async fn get_setting_handler(
    state: &AppState,
    _user: AuthenticatedUser,
    Path(key): Path<String>,
) -> Result<Json<SettingResponse>> {
    let setting = SystemSettingsEntity::find()
        .filter(entity::system_settings::Column::Key.eq(&key))
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Setting with key '{}' not found", key)))?;

    debug!(key = %key, "Retrieved system setting");

    Ok(Json(SettingResponse {
        id:          setting.id,
        key:         setting.key,
        value:       setting.value,
        description: setting.description,
        updated_at:  setting.updated_at.to_rfc3339(),
    }))
}

/// Update a setting by key (super-admin only)
pub async fn update_setting_handler(
    state: &AppState,
    _user: AuthenticatedUser,
    Path(key): Path<String>,
    Json(req): Json<UpdateSettingRequest>,
) -> Result<Json<SettingResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Find existing setting
    let setting = SystemSettingsEntity::find()
        .filter(entity::system_settings::Column::Key.eq(&key))
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Setting with key '{}' not found", key)))?;

    // Update the setting
    let mut active_model: entity::system_settings::ActiveModel = setting.into();
    active_model.value = Set(req.value);
    active_model.updated_at = Set(Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()));

    let updated = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update setting: {}", e)))?;

    debug!(key = %key, "System setting updated");

    Ok(Json(SettingResponse {
        id:          updated.id,
        key:         updated.key,
        value:       updated.value,
        description: updated.description,
        updated_at:  updated.updated_at.to_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setting_response_structure() {
        let response = SettingResponse {
            id:          "set_123".to_string(),
            key:         "require_mfa".to_string(),
            value:       "true".to_string(),
            description: Some("Test description".to_string()),
            updated_at:  "2024-01-01T00:00:00Z".to_string(),
        };

        assert_eq!(response.id, "set_123");
        assert_eq!(response.key, "require_mfa");
        assert_eq!(response.value, "true");
        assert!(response.description.is_some());
    }

    #[test]
    fn test_settings_list_response_structure() {
        let settings = vec![
            SettingResponse {
                id:          "set_1".to_string(),
                key:         "require_mfa".to_string(),
                value:       "false".to_string(),
                description: None,
                updated_at:  "2024-01-01T00:00:00Z".to_string(),
            },
            SettingResponse {
                id:          "set_2".to_string(),
                key:         "module_assets".to_string(),
                value:       "true".to_string(),
                description: Some("Enable assets".to_string()),
                updated_at:  "2024-01-01T00:00:00Z".to_string(),
            },
        ];

        let response = SettingsListResponse {
            settings,
        };
        assert_eq!(response.settings.len(), 2);
    }

    #[test]
    fn test_update_setting_request_validation() {
        let req = UpdateSettingRequest {
            value: "true".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_update_setting_request_empty_value() {
        let req = UpdateSettingRequest {
            value: "".to_string(),
        };
        assert!(req.validate().is_err());
    }
}
