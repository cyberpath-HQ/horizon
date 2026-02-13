//! # Team Handlers
//!
//! HTTP request handlers for team CRUD and member management endpoints.

use axum::Json;
use chrono::Utc;
use entity::{
    sea_orm_active_enums::TeamMemberRole,
    team_members::{Column as MemberColumn, Entity as TeamMembersEntity},
    teams::{Column as TeamColumn, Entity as TeamsEntity},
    users::Entity as UsersEntity,
};
use error::{AppError, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use tracing::info;
use validator::Validate;
use permissions_macro::with_permission;
use auth::permissions::{Permission, TeamAction};

use crate::{
    dto::{
        teams::{
            AddTeamMemberRequest,
            CreateTeamRequest,
            TeamListQuery,
            TeamListResponse,
            TeamMemberResponse,
            TeamMembersResponse,
            TeamResponse,
            UpdateTeamMemberRequest,
            UpdateTeamRequest,
        },
        users::PaginationInfo,
    },
    middleware::auth::AuthenticatedUser,
    utils::escape_like_wildcards,
    AppState,
};

/// Create a new team
///
/// The authenticated user becomes the team manager and is added as `owner` member.
///
/// The created team response
#[with_permission(Permission::Teams(TeamAction::Create))]
pub async fn create_team_handler(
    state: &AppState,
    user: AuthenticatedUser,
    req: CreateTeamRequest,
) -> Result<Json<TeamResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Generate slug from name
    let slug = slugify(&req.name);

    // Check for slug uniqueness
    let existing = TeamsEntity::find()
        .filter(TeamColumn::Slug.eq(&slug))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AppError::conflict("A team with this name already exists"));
    }

    // Validate parent_team_id if provided
    if let Some(ref parent_id) = req.parent_team_id {
        let parent = TeamsEntity::find_by_id(parent_id).one(&state.db).await?;
        if parent.is_none() {
            return Err(AppError::not_found("Parent team not found"));
        }
    }

    let now = Utc::now().naive_utc();
    let team = entity::teams::ActiveModel {
        name: Set(req.name.clone()),
        slug: Set(slug),
        description: Set(req.description),
        parent_team_id: Set(req.parent_team_id),
        manager_id: Set(user.id.clone()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let created_team = team
        .insert(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to create team: {}", e)))?;

    // Add the creator as an owner member
    let member = entity::team_members::ActiveModel {
        team_id: Set(created_team.id.clone()),
        user_id: Set(user.id.clone()),
        role: Set(TeamMemberRole::Owner),
        joined_at: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    member
        .insert(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to add creator as team member: {}", e)))?;

    info!(team_id = %created_team.id, user_id = %user.id, "Team created");

    Ok(Json(team_model_to_response(&created_team, Some(1))))
}

/// Get a single team by ID
///
/// The team response
#[with_permission(Permission::Teams(TeamAction::Read))]
pub async fn get_team_handler(state: &AppState, user: AuthenticatedUser, team_id: &str) -> Result<Json<TeamResponse>> {
    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    let member_count = TeamMembersEntity::find()
        .filter(MemberColumn::TeamId.eq(team_id))
        .count(&state.db)
        .await
        .unwrap_or(0);

    Ok(Json(team_model_to_response(&team, Some(member_count))))
}

/// List all teams with pagination and search
///
/// # Arguments
///
/// * `state` - Application state
/// Paginated team list
#[with_permission(Permission::Teams(TeamAction::Read))]
pub async fn list_teams_handler(
    state: &AppState,
    user: AuthenticatedUser,
    query: TeamListQuery,
) -> Result<Json<TeamListResponse>> {
    let page = query.page();
    let per_page = query.per_page();

    let mut base_query = TeamsEntity::find().filter(TeamColumn::DeletedAt.is_null());

    if let Some(ref search) = query.search {
        let escaped_search = escape_like_wildcards(search);
        let pattern = format!("%{}%", escaped_search);
        base_query = base_query.filter(
            Condition::any()
                .add(TeamColumn::Name.like(&pattern))
                .add(TeamColumn::Slug.like(&pattern)),
        );
    }

    let total = base_query
        .clone()
        .count(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to count teams: {}", e)))?;

    let total_pages = if total == 0 {
        0
    }
    else {
        total.div_ceil(per_page)
    };

    let teams = base_query
        .order_by_asc(TeamColumn::Name)
        .paginate(&state.db, per_page)
        .fetch_page(page.saturating_sub(1))
        .await
        .map_err(|e| AppError::database(format!("Failed to fetch teams: {}", e)))?;

    let team_responses: Vec<TeamResponse> = teams
        .iter()
        .map(|t| team_model_to_response(t, None))
        .collect();

    Ok(Json(TeamListResponse {
        success:    true,
        teams:      team_responses,
        pagination: PaginationInfo {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Update a team
///
/// Only the team manager, team owners, or admins can update a team.
///
/// # Arguments
///
/// * `state` - Application state
/// Updated team response
#[with_permission(Permission::Teams(TeamAction::Update))]
pub async fn update_team_handler(
    state: &AppState,
    user: AuthenticatedUser,
    team_id: &str,
    req: UpdateTeamRequest,
) -> Result<Json<TeamResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    // Authorization: team manager, owner member, or admin
    if !can_manage_team(state, &user, &team).await? {
        return Err(AppError::forbidden(
            "You do not have permission to update this team",
        ));
    }

    let mut active_model: entity::teams::ActiveModel = team.into();

    if let Some(name) = req.name {
        let new_slug = slugify(&name);
        // Verify new slug is unique (ignoring the current team)
        let existing = TeamsEntity::find()
            .filter(TeamColumn::Slug.eq(&new_slug))
            .filter(TeamColumn::Id.ne(team_id))
            .one(&state.db)
            .await?;
        if existing.is_some() {
            return Err(AppError::conflict("A team with this name already exists"));
        }
        active_model.name = Set(name);
        active_model.slug = Set(new_slug);
    }
    if let Some(description) = req.description {
        active_model.description = Set(Some(description));
    }
    if let Some(manager_id) = req.manager_id {
        // Verify the new manager exists
        let manager = UsersEntity::find_by_id(&manager_id).one(&state.db).await?;
        if manager.is_none() {
            return Err(AppError::not_found("New manager user not found"));
        }
        active_model.manager_id = Set(manager_id);
    }
    active_model.updated_at = Set(Utc::now().naive_utc());

    let updated = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update team: {}", e)))?;

    info!(team_id = %team_id, user_id = %user.id, "Team updated");

    Ok(Json(team_model_to_response(&updated, None)))
}

/// Soft-delete a team
///
/// Success response
#[with_permission(Permission::Teams(TeamAction::Delete))]
pub async fn delete_team_handler(
    state: &AppState,
    user: AuthenticatedUser,
    team_id: &str,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    if !can_manage_team(state, &user, &team).await? {
        return Err(AppError::forbidden(
            "You do not have permission to delete this team",
        ));
    }

    let mut active_model: entity::teams::ActiveModel = team.into();
    active_model.deleted_at = Set(Some(Utc::now().naive_utc()));
    active_model.updated_at = Set(Utc::now().naive_utc());
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to delete team: {}", e)))?;

    info!(team_id = %team_id, user_id = %user.id, "Team soft-deleted");

    Ok(Json(crate::dto::auth::SuccessResponse {
        success: true,
        message: "Team deleted successfully".to_string(),
    }))
}

/// Add a member to a team
///
/// Team member response for the added member
#[with_permission(Permission::Teams(TeamAction::MembersAdd))]
pub async fn add_team_member_handler(
    state: &AppState,
    user: AuthenticatedUser,
    team_id: &str,
    req: AddTeamMemberRequest,
) -> Result<Json<TeamMemberResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Check permissions
    let permission_service = auth::permissions::PermissionService::new(state.db.clone());
    permission_service
        .require_permission_for_roles(
            &user.roles,
            auth::permissions::Permission::Teams(auth::permissions::TeamAction::MembersAdd),
        )
        .await?;

    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    if !can_manage_team(state, &user, &team).await? {
        return Err(AppError::forbidden(
            "You do not have permission to manage team members",
        ));
    }

    // Verify the user to add exists
    let target_user = UsersEntity::find_by_id(&req.user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    // Parse role
    let role = parse_team_member_role(&req.role)?;

    // Check for existing membership
    let existing = TeamMembersEntity::find()
        .filter(MemberColumn::TeamId.eq(team_id))
        .filter(MemberColumn::UserId.eq(&req.user_id))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AppError::conflict("User is already a member of this team"));
    }

    let now = Utc::now().naive_utc();
    let member = entity::team_members::ActiveModel {
        team_id: Set(team_id.to_string()),
        user_id: Set(req.user_id.clone()),
        role: Set(role.clone()),
        joined_at: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let created_member = member
        .insert(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to add team member: {}", e)))?;

    info!(team_id = %team_id, target_user_id = %req.user_id, user_id = %user.id, "Team member added");

    let display_name = format!(
        "{} {}",
        target_user.first_name.unwrap_or_default(),
        target_user.last_name.unwrap_or_default()
    )
    .trim()
    .to_string();

    Ok(Json(TeamMemberResponse {
        id: created_member.id,
        user_id: created_member.user_id,
        email: target_user.email,
        display_name,
        role: format!("{:?}", role).to_lowercase(),
        joined_at: created_member.joined_at.to_string(),
    }))
}

/// Update a team member's role
///
/// Updated team member response
#[with_permission(Permission::Teams(TeamAction::MembersUpdate))]
pub async fn update_team_member_handler(
    state: &AppState,
    user: AuthenticatedUser,
    team_id: &str,
    member_id: &str,
    req: UpdateTeamMemberRequest,
) -> Result<Json<TeamMemberResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    if !can_manage_team(state, &user, &team).await? {
        return Err(AppError::forbidden(
            "You do not have permission to manage team members",
        ));
    }

    let member = TeamMembersEntity::find_by_id(member_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team member not found"))?;

    if member.team_id != team_id {
        return Err(AppError::not_found("Team member not found in this team"));
    }

    let role = parse_team_member_role(&req.role)?;

    let mut active_model: entity::team_members::ActiveModel = member.clone().into();
    active_model.role = Set(role.clone());
    active_model.updated_at = Set(Utc::now().naive_utc());

    let updated = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update team member: {}", e)))?;

    // Look up user details
    let member_user = UsersEntity::find_by_id(&updated.user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::internal("Member user not found"))?;

    let display_name = format!(
        "{} {}",
        member_user.first_name.unwrap_or_default(),
        member_user.last_name.unwrap_or_default()
    )
    .trim()
    .to_string();

    info!(
        team_id = %team_id,
        member_id = %member_id,
        new_role = %format!("{:?}", role),
        user_id = %user.id,
        "Team member role updated"
    );

    Ok(Json(TeamMemberResponse {
        id: updated.id,
        user_id: updated.user_id,
        email: member_user.email,
        display_name,
        role: role.to_string(),
        joined_at: updated.joined_at.to_string(),
    }))
}

/// Remove a member from a team
///
/// Success response
#[with_permission(Permission::Teams(TeamAction::MembersRemove))]
pub async fn remove_team_member_handler(
    state: &AppState,
    user: AuthenticatedUser,
    team_id: &str,
    member_id: &str,
) -> Result<Json<crate::dto::auth::SuccessResponse>> {
    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    if !can_manage_team(state, &user, &team).await? {
        return Err(AppError::forbidden(
            "You do not have permission to manage team members",
        ));
    }

    let member = TeamMembersEntity::find_by_id(member_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team member not found"))?;

    if member.team_id != team_id {
        return Err(AppError::not_found("Team member not found in this team"));
    }

    // Prevent removing the last owner
    if member.role == TeamMemberRole::Owner {
        let owner_count = TeamMembersEntity::find()
            .filter(MemberColumn::TeamId.eq(team_id))
            .filter(MemberColumn::Role.eq(TeamMemberRole::Owner))
            .count(&state.db)
            .await
            .unwrap_or(0);
        if owner_count <= 1 {
            return Err(AppError::bad_request(
                "Cannot remove the last owner. Transfer ownership first.",
            ));
        }
    }

    entity::team_members::Entity::delete_by_id(member_id)
        .exec(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to remove team member: {}", e)))?;

    info!(team_id = %team_id, member_id = %member_id, user_id = %user.id, "Team member removed");

    Ok(Json(crate::dto::auth::SuccessResponse {
        success: true,
        message: "Team member removed".to_string(),
    }))
}

/// List the members of a team
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// Team members list response
#[with_permission(Permission::Teams(TeamAction::MembersRead))]
pub async fn list_team_members_handler(
    state: &AppState,
    user: AuthenticatedUser,
    team_id: &str,
) -> Result<Json<TeamMembersResponse>> {
    // Verify team exists
    let team = TeamsEntity::find_by_id(team_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("Team not found"))?;

    if team.deleted_at.is_some() {
        return Err(AppError::not_found("Team not found"));
    }

    let members = TeamMembersEntity::find()
        .filter(MemberColumn::TeamId.eq(team_id))
        .find_also_related(UsersEntity)
        .all(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to fetch team members: {}", e)))?;

    let member_responses: Vec<TeamMemberResponse> = members
        .into_iter()
        .map(|(m, user_opt)| {
            let (email, display_name) = match user_opt {
                Some(u) => {
                    let dn = format!(
                        "{} {}",
                        u.first_name.unwrap_or_default(),
                        u.last_name.unwrap_or_default()
                    )
                    .trim()
                    .to_string();
                    (u.email, dn)
                },
                None => ("unknown".to_string(), "Unknown User".to_string()),
            };
            TeamMemberResponse {
                id: m.id,
                user_id: m.user_id,
                email,
                display_name,
                role: m.role.to_string(),
                joined_at: m.joined_at.to_string(),
            }
        })
        .collect();

    Ok(Json(TeamMembersResponse {
        success: true,
        members: member_responses,
    }))
}

/// Check if a user can manage a team (is manager, owner, or admin)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user
/// * `team` - The team model
///
/// # Returns
///
/// `true` if the user can manage the team
pub async fn can_manage_team(state: &AppState, user: &AuthenticatedUser, team: &entity::teams::Model) -> Result<bool> {
    // System admins can manage any team
    if user
        .roles
        .iter()
        .any(|r| r == "super_admin" || r == "admin")
    {
        return Ok(true);
    }

    // Team manager can manage
    if team.manager_id == user.id {
        return Ok(true);
    }

    // Team owners can manage
    let is_owner = TeamMembersEntity::find()
        .filter(MemberColumn::TeamId.eq(&team.id))
        .filter(MemberColumn::UserId.eq(&user.id))
        .filter(MemberColumn::Role.eq(TeamMemberRole::Owner))
        .one(&state.db)
        .await?
        .is_some();

    Ok(is_owner)
}

/// Generate a URL-friendly slug from a team name
///
/// # Arguments
///
/// * `name` - The team name
///
/// # Returns
///
/// A URL-friendly slug
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            }
            else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a team member role string into the enum
///
/// # Arguments
///
/// * `role_str` - The role string (owner, admin, member, viewer)
///
/// # Returns
///
/// The team member role enum variant
fn parse_team_member_role(role_str: &str) -> Result<TeamMemberRole> {
    match role_str.to_lowercase().as_str() {
        "owner" => Ok(TeamMemberRole::Owner),
        "admin" => Ok(TeamMemberRole::Admin),
        "member" => Ok(TeamMemberRole::Member),
        "viewer" => Ok(TeamMemberRole::Viewer),
        _ => {
            Err(AppError::bad_request(
                "Invalid role. Must be one of: owner, admin, member, viewer",
            ))
        },
    }
}

/// Convert a team entity model to a response DTO
fn team_model_to_response(team: &entity::teams::Model, member_count: Option<u64>) -> TeamResponse {
    TeamResponse {
        id: team.id.clone(),
        name: team.name.clone(),
        slug: team.slug.clone(),
        description: team.description.clone(),
        parent_team_id: team.parent_team_id.clone(),
        manager_id: team.manager_id.clone(),
        member_count,
        created_at: team.created_at.to_string(),
        updated_at: team.updated_at.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify_simple() {
        assert_eq!(slugify("Engineering"), "engineering");
    }

    #[test]
    fn test_slugify_with_spaces() {
        assert_eq!(slugify("Backend Team"), "backend-team");
    }

    #[test]
    fn test_slugify_with_special_chars() {
        assert_eq!(slugify("My Team! @#$ 2024"), "my-team-2024");
    }

    #[test]
    fn test_slugify_consecutive_dashes() {
        assert_eq!(slugify("Team---Name"), "team-name");
    }

    #[test]
    fn test_slugify_leading_trailing_dashes() {
        assert_eq!(slugify(" Team Name "), "team-name");
    }

    #[test]
    fn test_slugify_already_slugified() {
        assert_eq!(slugify("my-team"), "my-team");
    }

    #[test]
    fn test_parse_team_member_role_valid() {
        assert_eq!(
            parse_team_member_role("owner").unwrap(),
            TeamMemberRole::Owner
        );
        assert_eq!(
            parse_team_member_role("admin").unwrap(),
            TeamMemberRole::Admin
        );
        assert_eq!(
            parse_team_member_role("member").unwrap(),
            TeamMemberRole::Member
        );
        assert_eq!(
            parse_team_member_role("viewer").unwrap(),
            TeamMemberRole::Viewer
        );
    }

    #[test]
    fn test_parse_team_member_role_case_insensitive() {
        assert_eq!(
            parse_team_member_role("OWNER").unwrap(),
            TeamMemberRole::Owner
        );
        assert_eq!(
            parse_team_member_role("Admin").unwrap(),
            TeamMemberRole::Admin
        );
    }

    #[test]
    fn test_parse_team_member_role_invalid() {
        assert!(parse_team_member_role("superadmin").is_err());
        assert!(parse_team_member_role("").is_err());
        assert!(parse_team_member_role("moderator").is_err());
    }

    #[test]
    fn test_team_model_to_response() {
        let team = entity::teams::Model {
            id:             "team_abc123".to_string(),
            name:           "Backend".to_string(),
            slug:           "backend".to_string(),
            description:    Some("Backend engineering".to_string()),
            parent_team_id: None,
            manager_id:     "usr_manager".to_string(),
            created_at:     chrono::NaiveDateTime::default(),
            updated_at:     chrono::NaiveDateTime::default(),
            deleted_at:     None,
        };

        let response = team_model_to_response(&team, Some(5));
        assert_eq!(response.id, "team_abc123");
        assert_eq!(response.name, "Backend");
        assert_eq!(response.slug, "backend");
        assert_eq!(response.member_count, Some(5));
    }

    #[test]
    fn test_team_model_to_response_no_member_count() {
        let team = entity::teams::Model {
            id:             "team_xyz".to_string(),
            name:           "Frontend".to_string(),
            slug:           "frontend".to_string(),
            description:    None,
            parent_team_id: Some("team_parent".to_string()),
            manager_id:     "usr_mgr".to_string(),
            created_at:     chrono::NaiveDateTime::default(),
            updated_at:     chrono::NaiveDateTime::default(),
            deleted_at:     None,
        };

        let response = team_model_to_response(&team, None);
        assert!(response.member_count.is_none());
        assert_eq!(response.parent_team_id, Some("team_parent".to_string()));
    }

    #[test]
    fn test_team_list_query_defaults() {
        let q = TeamListQuery {
            page:     None,
            per_page: None,
            search:   None,
        };
        assert_eq!(q.page(), 1);
        assert_eq!(q.per_page(), 20);
    }

    #[test]
    fn test_team_list_query_clamp() {
        let q = TeamListQuery {
            page:     Some(0),
            per_page: Some(1000),
            search:   None,
        };
        assert_eq!(q.page(), 1);
        assert_eq!(q.per_page(), 100);
    }

    #[test]
    fn test_can_manage_team_admin_roles() {
        // Test that admin roles are recognized
        let user_admin = AuthenticatedUser {
            id:    "user1".to_string(),
            email: "admin@test.com".to_string(),
            roles: vec!["admin".to_string()],
        };
        let user_super = AuthenticatedUser {
            id:    "user2".to_string(),
            email: "super@test.com".to_string(),
            roles: vec!["super_admin".to_string()],
        };
        let user_regular = AuthenticatedUser {
            id:    "user3".to_string(),
            email: "user@test.com".to_string(),
            roles: vec!["user".to_string()],
        };

        // Note: This test only checks the role-based logic, not the DB-dependent parts
        // For full testing, integration tests are needed
        assert!(user_admin
            .roles
            .iter()
            .any(|r| r == "super_admin" || r == "admin"));
        assert!(user_super
            .roles
            .iter()
            .any(|r| r == "super_admin" || r == "admin"));
        assert!(!user_regular
            .roles
            .iter()
            .any(|r| r == "super_admin" || r == "admin"));
    }
}
