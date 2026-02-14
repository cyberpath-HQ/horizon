use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create system_settings table
        manager
            .create_table(
                Table::create()
                    .table(SystemSettings::Table)
                    .if_not_exists()
                    .col(
                        text(SystemSettings::Id)
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("cuid2(32, 'set_')")),
                    )
                    .col(string(SystemSettings::Key).not_null().unique_key())
                    .col(text(SystemSettings::Value).not_null())
                    .col(text(SystemSettings::Description).null())
                    .col(
                        timestamp_with_time_zone(SystemSettings::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SystemSettings::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SystemSettings {
    Table,
    Id,
    Key,
    Value,
    Description,
    UpdatedAt,
}
