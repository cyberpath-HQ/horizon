//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated from the database schema.

pub mod sea_orm_active_enums;
pub mod team_members;
pub use team_members::Entity as TeamMembers;
pub mod teams;
pub use teams::Entity as Teams;
pub mod users;
pub use users::Entity as Users;
