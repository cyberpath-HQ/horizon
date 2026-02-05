use sea_orm_migration::{prelude::*, schema::*};
use sea_query::extension::postgres::Type;
use serde_json::json;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create role_scope_type enum type
        manager
            .create_type(
                Type::create()
                    .as_enum(RoleScopeType::Table)
                    .values(vec![
                        RoleScopeType::Global,
                        RoleScopeType::Team,
                        RoleScopeType::Asset,
                    ])
                    .to_owned(),
            )
            .await?;

        // Create roles table
        manager
            .create_table(
                Table::create()
                    .table(Roles::Table)
                    .if_not_exists()
                    .col(
                        text(Roles::Id)
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("'h8ks3j2k9j3h8k2s3j4k5m6n7o8p9q0'")), // Default to super_admin CUID2
                    )
                    .col(string(Roles::Name).not_null())
                    .col(string(Roles::Slug).not_null().unique_key())
                    .col(text(Roles::Description).null())
                    .col(
                        ColumnDef::new(Roles::Permissions)
                            .json()
                            .not_null()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .col(boolean(Roles::IsSystem).not_null().default(false))
                    .col(
                        timestamp(Roles::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Roles::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Create indexes
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_roles_slug")
                    .table(Roles::Table)
                    .col(Roles::Slug)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_roles_is_system")
                    .table(Roles::Table)
                    .col(Roles::IsSystem)
                    .to_owned(),
            )
            .await?;

        // Insert default system roles using raw SQL for proper UUID handling
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(Roles::Table)
                    .columns([
                        Roles::Id,
                        Roles::Name,
                        Roles::Slug,
                        Roles::Description,
                        Roles::Permissions,
                        Roles::IsSystem,
                    ])
                    .values_panic([
                        "h8ks3j2k9j3h8k2s3j4k5m6n7o8p9q0".into(),
                        "Super Admin".into(),
                        "super_admin".into(),
                        "Full system access with all permissions".into(),
                        json!(["*:*"]).into(),
                        true.into(),
                    ])
                    .values_panic([
                        "i9lt4k3l0k4i9l3t4l5n7o9p0q1r2s3".into(),
                        "Admin".into(),
                        "admin".into(),
                        "Full access to most features except system configuration".into(),
                        json!([
                            "users:*",
                            "teams:*",
                            "assets:*",
                            "software:*",
                            "vulnerabilities:*",
                            "configurations:*",
                            "network:*",
                            "reports:*"
                        ])
                        .into(),
                        true.into(),
                    ])
                    .values_panic([
                        "j0mu5l4m1l5j0m4u5m6n8o0p1r2s3t4".into(),
                        "Manager".into(),
                        "manager".into(),
                        "Team management with read/write access to assigned resources".into(),
                        json!([
                            "users:read",
                            "teams:read",
                            "teams:write",
                            "assets:read",
                            "assets:write",
                            "software:read",
                            "vulnerabilities:read",
                            "network:read"
                        ])
                        .into(),
                        true.into(),
                    ])
                    .values_panic([
                        "k1nv6m5n2m6k1n5v6n7o9p2r3s4t5u6".into(),
                        "Viewer".into(),
                        "viewer".into(),
                        "Read-only access to all resources".into(),
                        json!([
                            "users:read",
                            "teams:read",
                            "assets:read",
                            "software:read",
                            "vulnerabilities:read",
                            "configurations:read",
                            "network:read"
                        ])
                        .into(),
                        true.into(),
                    ])
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Roles::Table).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(RoleScopeType::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Roles {
    Table,
    Id,
    Name,
    Slug,
    Description,
    Permissions,
    IsSystem,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum RoleScopeType {
    Table,
    #[sea_orm(string_value = "global")]
    Global,
    #[sea_orm(string_value = "team")]
    Team,
    #[sea_orm(string_value = "asset")]
    Asset,
}
