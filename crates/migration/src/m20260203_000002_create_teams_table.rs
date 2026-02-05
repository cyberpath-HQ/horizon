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
                    .col(
                        text(Teams::Id)
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("cuid2(32, 'team_')")),
                    )
                    .col(string(Teams::Name).not_null())
                    .col(string(Teams::Slug).not_null().unique_key())
                    .col(text(Teams::Description).null())
                    .col(text(Teams::ParentTeamId).null())
                    .col(text(Teams::ManagerId).not_null())
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
