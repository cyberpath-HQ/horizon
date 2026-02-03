use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create teams table using schema helpers
        manager
            .create_table(
                Table::create()
                    .table(Teams::Table)
                    .if_not_exists()
                    .col(pk_auto(Teams::Id))
                    .col(string(Teams::Name).not_null())
                    .col(string(Teams::Slug).not_null().unique_key())
                    .col(text(Teams::Description).null())
                    .col(uuid(Teams::ParentTeamId).null())
                    .col(uuid(Teams::ManagerId).not_null())
                    .col(
                        timestamp(Teams::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Teams::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp(Teams::DeletedAt).null())
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

        // Create indexes
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
