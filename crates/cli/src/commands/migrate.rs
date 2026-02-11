//! # CLI Migration Command
//!
//! Database migration handling for the Horizon CLI.

use error::Result;
use migration::MigratorTrait as _;
use tracing::info;

use crate::{commands::MigrateArgs, config::DatabaseConfig};

/// Runs database migrations
///
/// # Arguments
///
/// * `config` - Database configuration
/// * `args` - Migrate command arguments
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[allow(
    clippy::cognitive_complexity,
    reason = "Migration logic requires comprehensive error handling"
)]
pub async fn migrate(config: &DatabaseConfig, args: MigrateArgs) -> Result<()> {
    info!(
        target: "migrate",
        dry_run = %args.dry_run,
        rollback = %args.rollback,
        "Running database migrations..."
    );

    // Build database URL from configuration
    let database_url = crate::config::build_database_url(config);

    // Connect to database
    let db = migration::connect_to_database(&database_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to database: {}", e))?;

    if args.dry_run {
        // Dry run mode - just show what would happen
        info!(target: "migrate", "Dry run mode - migrations would be applied");

        // Get pending migrations
        let pending = migration::Migrator::get_pending_migrations(&db)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get pending migrations: {}", e))?;

        info!(
            target: "migrate",
            pending_count = %pending.len(),
            "Pending migrations found"
        );

        for m in &pending {
            info!(target: "migrate", migration = %m.name(), "Would apply");
        }

        return Ok(());
    }

    if args.rollback {
        // Rollback the last migration
        info!(target: "migrate", "Rolling back the last migration...");

        migration::Migrator::down(&db, None)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to rollback migration: {}", e))?;

        info!(target: "migrate", "Rollback completed successfully");
        return Ok(());
    }

    // Run migrations
    migration::Migrator::up(&db, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;

    info!(target: "migrate", "Migrations completed successfully");
    Ok(())
}
