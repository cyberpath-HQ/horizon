//! # Seed Data Management
//!
//! This module provides utilities for seeding the database with
//! initial data including enum values, default configurations, and
//! reference data.

use ::error::{AppError, SeedResult};

/// Trait for seed data providers
///
/// Implement this trait to provide seed data for the database.
#[async_trait::async_trait]
pub trait SeedProvider {
    /// The name of this seed
    fn name(&self) -> &str;

    /// Runs the seed operation
    ///
    /// # Arguments
    ///
    /// * `db` - The database connection
    ///
    /// # Errors
    ///
    /// Returns an error if the seed operation fails.
    async fn run(&self, _db: &crate::SeaDb) -> Result<SeedResult, AppError>;
}

/// Runs all registered seed providers
///
/// # Arguments
///
/// * `db` - The database connection
/// * `verbose` - Whether to print verbose output
///
/// # Errors
///
/// Returns an error if any seed operation fails.
pub async fn run_all_seeds(_db: &crate::SeaDb, _verbose: bool) -> Result<Vec<SeedResult>, AppError> {
    let mut results = Vec::new();

    // Seed providers would be registered here
    // For now, return empty results as seeds will be implemented in later phases

    tracing::info!("Seed data module initialized (seeds will be populated in later phases)");

    Ok(results)
}
