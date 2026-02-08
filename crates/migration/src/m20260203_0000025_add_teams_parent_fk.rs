use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add foreign key for parent team (self-referencing for hierarchy)
        // This must be done in a separate migration because PostgreSQL
        // doesn't allow self-referential FKs in the same transaction as table creation
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_teams_parent_team_id")
                    .from(Teams::Table, Teams::ParentTeamId)
                    .to(Teams::Table, Teams::Id)
                    .on_delete(ForeignKeyAction::SetNull)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_teams_parent_team_id")
                    .table(Teams::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Teams {
    Table,
    ParentTeamId,
    Id,
}
