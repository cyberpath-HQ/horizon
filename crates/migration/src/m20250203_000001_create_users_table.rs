use sea_orm_migration::{prelude::*, schema::*, sea_query::extension::postgres::Type};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create enum type first
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

        // Create users table using schema helpers
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(pk_auto(Users::Id))
                    .col(string(Users::Email).not_null().unique_key())
                    .col(string(Users::Username).not_null().unique_key())
                    .col(string(Users::PasswordHash).not_null())
                    .col(string(Users::TotpSecret).null())
                    .col(string(Users::FirstName).null())
                    .col(string(Users::LastName).null())
                    .col(string(Users::AvatarUrl).null())
                    .col(enumeration_null(
                        Users::Status,
                        UserStatus::Table,
                        vec![
                            UserStatus::Active,
                            UserStatus::Inactive,
                            UserStatus::Suspended,
                            UserStatus::PendingVerification,
                        ],
                    ))
                    .col(timestamp(Users::EmailVerifiedAt).null())
                    .col(timestamp(Users::LastLoginAt).null())
                    .col(
                        timestamp(Users::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Users::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp(Users::DeletedAt).null())
                    .to_owned(),
            )
            .await?;

        // Create index for status
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

        manager
            .drop_type(Type::drop().name(UserStatus::Table).to_owned())
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
