//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated and managed using the entity reconciliation script.

pub mod team_members;
pub mod teams;
pub mod users;

pub use team_members::Entity as TeamMembers;
pub use teams::Entity as Teams;
pub use users::Entity as Users;
