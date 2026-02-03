use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create teams table
        manager
            .create_table(
                Table::create()
                    .table(Teams::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Teams::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Teams::Name).string().not_null())
                    .col(ColumnDef::new(Teams::Slug).string().not_null().unique_key())
                    .col(ColumnDef::new(Teams::Description).text().null())
                    .col(ColumnDef::new(Teams::ParentTeamId).uuid().null())
                    .col(ColumnDef::new(Teams::ManagerId).uuid().not_null())
                    .col(
                        ColumnDef::new(Teams::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Teams::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Teams::DeletedAt).timestamp().null())
                    .to_owned(),
            )
            .await?;

        // Add foreign key for parent team (self-referencing for hierarchy)
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

        // Add foreign key for manager (will reference users table after users migration)
        // This is added in the next migration after users table is created

        // Create indexes
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_teams_slug")
                    .table(Teams::Table)
                    .col(Teams::Slug)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_teams_parent_team_id")
                    .table(Teams::Table)
                    .col(Teams::ParentTeamId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_teams_manager_id")
                    .table(Teams::Table)
                    .col(Teams::ManagerId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Teams::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Teams {
    Table,
    Id,
    Name,
    Slug,
    Description,
    ParentTeamId,
    ManagerId,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}
