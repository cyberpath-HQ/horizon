use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add foreign key for teams.manager_id -> users.id
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_teams_manager_id")
                    .from(Teams::Table, Teams::ManagerId)
                    .to(Users::Table, Users::Id)
                    .on_delete(ForeignKeyAction::Restrict)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_teams_manager_id")
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
    #[allow(dead_code)]
    Id,
    ManagerId,
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
}
