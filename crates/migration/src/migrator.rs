//! # Database Migrator
//!
//! This module implements the Sea-ORM migrator trait for managing database schema changes.
//! The migrator coordinates all migration operations and maintains the migration history.

use sea_orm_migration::prelude::*;

use crate::migrators::m20260202_init::M20230101Init;

/// The main migrator that coordinates all migration operations
///
/// This struct implements the `MigratorTrait` and is responsible for:
/// - Loading all available migrations
/// - Executing migrations in order
/// - Tracking migration history in the database
///
/// # Example
///
/// ```rust,ignore
/// use sea_orm_migration::prelude::*;
/// use crate::migration::migrator::Migrator;
///
/// Migrator::up(&db, None).await?;
/// ```
#[derive(Debug)]
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    /// The migrations managed by this migrator
    ///
    /// Add new migrations to this list as they are created.
    /// Migrations are executed in the order they appear in this list.
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            // Initial schema migration - must be first
            Box::new(M20230101Init),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrations_count() {
        // Verify we have at least one migration
        let migrations = Migrator::migrations();
        assert!(!migrations.is_empty(), "Expected at least one migration");
    }
}
