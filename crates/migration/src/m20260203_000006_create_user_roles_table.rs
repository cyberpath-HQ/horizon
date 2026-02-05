use sea_orm_migration::{prelude::*, schema::*};
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create user_roles table
        manager
            .create_table(
                Table::create()
                    .table(UserRoles::Table)
                    .if_not_exists()
                    .col(
                        text(UserRoles::Id)
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("cuid2(32, 'urole_')")),
                    )
                    .col(text(UserRoles::UserId).not_null())
                    .col(text(UserRoles::RoleId).not_null())
                    .col(
                        ColumnDef::new(UserRoles::ScopeType)
                            .custom(Alias::new("role_scope_type"))
                            .not_null()
                            .default(Expr::cust("'global'")),
                    )
                    .col(text(UserRoles::ScopeId).null())
                    .col(timestamp(UserRoles::ExpiresAt).null())
                    .col(
                        timestamp(UserRoles::AssignedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(UserRoles::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(UserRoles::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Add foreign key for user
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_user_roles_user_id")
                    .from(UserRoles::Table, UserRoles::UserId)
                    .to(Users::Table, Users::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // Add foreign key for role
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_user_roles_role_id")
                    .from(UserRoles::Table, UserRoles::RoleId)
                    .to(Roles::Table, Roles::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // Create unique constraint for user + role + scope combination
        // Use COALESCE to handle NULL scope_id for global roles
        manager
            .get_connection()
             .execute_unprepared(r#"CREATE UNIQUE INDEX IF NOT EXISTS "idx_user_roles_user_role_scope_unique" ON "user_roles" ("user_id", "role_id", "scope_type", COALESCE("scope_id", 'h8ks3j2k9j3h8k2s3j4k5m6n7o8p9q0'))"#)
            .await?;

        // Create indexes for common queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_user_roles_user_id")
                    .table(UserRoles::Table)
                    .col(UserRoles::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_user_roles_role_id")
                    .table(UserRoles::Table)
                    .col(UserRoles::RoleId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_user_roles_expires_at")
                    .table(UserRoles::Table)
                    .col(UserRoles::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserRoles::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum UserRoles {
    Table,
    Id,
    UserId,
    RoleId,
    ScopeType,
    ScopeId,
    ExpiresAt,
    AssignedAt,
    CreatedAt,
    UpdatedAt,
}

// Reference to users table
#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
}

// Reference to roles table
#[derive(DeriveIden)]
pub enum Roles {
    Table,
    Id,
}

// Reference for scope type enum
#[derive(DeriveIden)]
#[allow(dead_code)]
pub enum RoleScopeType {
    Table,
    #[sea_orm(string_value = "global")]
    Global,
    #[sea_orm(string_value = "team")]
    Team,
    #[sea_orm(string_value = "asset")]
    Asset,
}
