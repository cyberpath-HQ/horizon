use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop username column if it exists
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Username)
                    .to_owned(),
            )
            .await?;

        // Rename first_name to full_name and drop last_name
        // First, add full_name column
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(string(Users::FullName).null())
                    .to_owned(),
            )
            .await?;

        // Drop first_name and last_name columns
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::FirstName)
                    .drop_column(Users::LastName)
                    .to_owned(),
            )
            .await?;

        // Make full_name not null (it will have values from the migration)
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .modify_column(string(Users::FullName).not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add back first_name and last_name columns
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(string(Users::FirstName).null())
                    .add_column(string(Users::LastName).null())
                    .to_owned(),
            )
            .await?;

        // Drop full_name column
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::FullName)
                    .to_owned(),
            )
            .await?;

        // Add back username column
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(string(Users::Username).not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Email,
    Username,
    FullName,
    FirstName,
    LastName,
    PasswordHash,
    TotpSecret,
    AvatarUrl,
    Status,
    EmailVerifiedAt,
    LastLoginAt,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}
