//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated from the database schema.

pub mod api_keys;
pub mod sea_orm_active_enums;
pub use api_keys::Entity as ApiKeys;
pub mod roles;
pub use roles::Entity as Roles;
pub mod team_members;
pub use team_members::Entity as TeamMembers;
pub mod teams;
pub use teams::Entity as Teams;
pub mod user_roles;
pub use user_roles::Entity as UserRoles;
pub mod users;
pub use users::Entity as Users;
pub mod refresh_tokens;
pub use refresh_tokens::Entity as RefreshTokens;
