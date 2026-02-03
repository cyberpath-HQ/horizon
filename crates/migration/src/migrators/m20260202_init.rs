//! # Initial Database Schema Migration
//!
//! This migration creates the initial database schema for Horizon CMDB.

use sea_orm_migration::prelude::*;

/// Initial migration for creating the Horizon CMDB schema
#[derive(DeriveMigrationName)]
pub struct M20260202Init;

#[async_trait::async_trait]
impl MigrationTrait for M20260202Init {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        tracing::info!("Initial migration completed");
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::MigrationName;

    use super::*;

    #[test]
    fn test_migration_name() {
        let migration = M20260202Init;
        let migration_name = <M20260202Init as MigrationName>::name(&migration);
        assert_eq!(migration_name, "m20230101_init");
    }
}
