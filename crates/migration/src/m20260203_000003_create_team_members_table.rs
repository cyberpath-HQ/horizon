use sea_orm_migration::{prelude::*, schema::*, sea_query::extension::postgres::Type};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create team_member_role enum type
        manager
            .create_type(
                Type::create()
                    .as_enum(TeamMemberRole::Table)
                    .values(vec![
                        TeamMemberRole::Owner,
                        TeamMemberRole::Admin,
                        TeamMemberRole::Member,
                        TeamMemberRole::Viewer,
                    ])
                    .to_owned(),
            )
            .await?;

        // Create team_members table using schema helpers
        manager
            .create_table(
                Table::create()
                    .table(TeamMembers::Table)
                    .if_not_exists()
                    .col(pk_auto(TeamMembers::Id))
                    .col(uuid(TeamMembers::TeamId).not_null())
                    .col(uuid(TeamMembers::UserId).not_null())
                    .col(
                        enumeration(
                            TeamMembers::Role,
                            TeamMemberRole::Table,
                            vec![
                                TeamMemberRole::Owner,
                                TeamMemberRole::Admin,
                                TeamMemberRole::Member,
                                TeamMemberRole::Viewer,
                            ],
                        )
                        .default("member"),
                    )
                    .col(
                        timestamp(TeamMembers::JoinedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(TeamMembers::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(TeamMembers::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Add foreign key for team
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_team_members_team_id")
                    .from(TeamMembers::Table, TeamMembers::TeamId)
                    .to(Teams::Table, Teams::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // Add foreign key for user
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_team_members_user_id")
                    .from(TeamMembers::Table, TeamMembers::UserId)
                    .to(Users::Table, Users::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // Create unique constraint to prevent duplicate memberships
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_team_members_team_user_unique")
                    .table(TeamMembers::Table)
                    .col(TeamMembers::TeamId)
                    .col(TeamMembers::UserId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create indexes for common queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_team_members_user_id")
                    .table(TeamMembers::Table)
                    .col(TeamMembers::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TeamMembers::Table).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(TeamMemberRole::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum TeamMembers {
    Table,
    Id,
    TeamId,
    UserId,
    Role,
    JoinedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum TeamMemberRole {
    Table,
    #[sea_orm(string_value = "owner")]
    Owner,
    #[sea_orm(string_value = "admin")]
    Admin,
    #[sea_orm(string_value = "member")]
    Member,
    #[sea_orm(string_value = "viewer")]
    Viewer,
}

// Reference to users table
#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
}

// Reference to teams table
#[derive(DeriveIden)]
pub enum Teams {
    Table,
    Id,
}
