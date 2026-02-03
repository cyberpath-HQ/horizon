use sea_orm_migration::{prelude::*, sea_query::extension::postgres::Type};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create user_status enum type
        manager
            .create_type(
                Type::create()
                    .as_enum(UserStatus::Table)
                    .values(vec![
                        UserStatus::Active,
                        UserStatus::Inactive,
                        UserStatus::Suspended,
                        UserStatus::PendingVerification,
                    ])
                    .to_owned(),
            )
            .await?;

        // Create users table with authentication fields
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).uuid().not_null().primary_key())
                    .col(
                        ColumnDef::new(Users::Email)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Username)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::PasswordHash).string().not_null())
                    .col(ColumnDef::new(Users::TotpSecret).string().null())
                    .col(ColumnDef::new(Users::FirstName).string().null())
                    .col(ColumnDef::new(Users::LastName).string().null())
                    .col(ColumnDef::new(Users::AvatarUrl).string().null())
                    .col(
                        ColumnDef::new(Users::Status)
                            .custom(UserStatus::Table)
                            .not_null()
                            .default(Expr::cust("'pending_verification'")),
                    )
                    .col(ColumnDef::new(Users::EmailVerifiedAt).timestamp().null())
                    .col(ColumnDef::new(Users::LastLoginAt).timestamp().null())
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Users::DeletedAt).timestamp().null())
                    .to_owned(),
            )
            .await?;

        // Create indexes for common queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_email")
                    .table(Users::Table)
                    .col(Users::Email)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_username")
                    .table(Users::Table)
                    .col(Users::Username)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_status")
                    .table(Users::Table)
                    .col(Users::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        // Drop enum type
        manager
            .drop_type(Type::drop().if_exists().name(UserStatus::Table).to_owned())
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
    PasswordHash,
    TotpSecret,
    FirstName,
    LastName,
    AvatarUrl,
    Status,
    EmailVerifiedAt,
    LastLoginAt,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}

#[derive(DeriveIden)]
pub enum UserStatus {
    Table,
    #[sea_orm(string_value = "active")]
    Active,
    #[sea_orm(string_value = "inactive")]
    Inactive,
    #[sea_orm(string_value = "suspended")]
    Suspended,
    #[sea_orm(string_value = "pending_verification")]
    PendingVerification,
}
