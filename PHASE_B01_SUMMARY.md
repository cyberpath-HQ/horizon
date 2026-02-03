# Phase B-01: User and Team Database Schema

**Implementation Date:** February 3, 2025  
**Status:** ✅ COMPLETE  
**PR Ready:** Yes

---

## Overview

Phase B-01 implements the foundational authentication database schema for Horizon, establishing the core entities for user management, team organization, and team membership with role-based access control.

## Deliverables

### 1. Database Migrations

Four comprehensive migration files have been created to establish the authentication schema:

#### **M20250203_000001: Create Users Table** 
Location: `crates/migration/src/m20250203_000001_create_users_table.rs`

**Table: `users`**
- `id` (UUID, PK): Unique user identifier
- `email` (String, UNIQUE): User email address
- `username` (String, UNIQUE): Username for login
- `password_hash` (String): Argon2id hashed password
- `totp_secret` (String, Optional): TOTP MFA secret
- `first_name` (String, Optional): User first name
- `last_name` (String, Optional): User last name
- `avatar_url` (String, Optional): Profile avatar URL
- `status` (Enum, Not Null): User account status
  - `active`: Account is usable
  - `inactive`: User-disabled account
  - `suspended`: Admin-suspended account
  - `pending_verification`: Awaiting email verification
- `email_verified_at` (Timestamp, Optional): Email verification timestamp
- `last_login_at` (Timestamp, Optional): Last successful login time
- `created_at` (Timestamp): Account creation time
- `updated_at` (Timestamp): Last modification time
- `deleted_at` (Timestamp, Optional): Soft-delete timestamp

**Indexes:**
- Unique index on `email`
- Unique index on `username`
- Index on `status` for queries

#### **M20250203_000002: Create Teams Table**
Location: `crates/migration/src/m20250203_000002_create_teams_table.rs`

**Table: `teams`**
- `id` (UUID, PK): Unique team identifier
- `name` (String): Team display name
- `slug` (String, UNIQUE): URL-safe team identifier
- `description` (Text, Optional): Team description
- `parent_team_id` (UUID, Optional): Parent team for hierarchy
- `manager_id` (UUID): Team manager (FK to users)
- `created_at` (Timestamp): Team creation time
- `updated_at` (Timestamp): Last modification time
- `deleted_at` (Timestamp, Optional): Soft-delete timestamp

**Relationships:**
- Self-referential foreign key for hierarchical teams (on_delete: SET_NULL)
- Foreign key to users for manager (on_delete: RESTRICT)

**Indexes:**
- Unique index on `slug`
- Index on `parent_team_id`
- Index on `manager_id`

#### **M20250203_000003: Create Team Members Table**
Location: `crates/migration/src/m20250203_000003_create_team_members_table.rs`

**Table: `team_members`**
- `id` (UUID, PK): Unique membership identifier
- `team_id` (UUID, FK): Reference to team
- `user_id` (UUID, FK): Reference to user
- `role` (Enum): Member's role within team
  - `owner`: Full control
  - `admin`: Administrative control
  - `member`: Standard member access
  - `viewer`: Read-only access
- `joined_at` (Timestamp): Membership creation time
- `created_at` (Timestamp): Record creation time
- `updated_at` (Timestamp): Last modification time

**Constraints:**
- Foreign key to teams (on_delete: CASCADE)
- Foreign key to users (on_delete: CASCADE)
- Unique constraint on (team_id, user_id) to prevent duplicate memberships

**Indexes:**
- Unique index on (team_id, user_id)
- Index on `team_id`
- Index on `user_id`

#### **M20250203_000004: Add Teams Manager Foreign Key**
Location: `crates/migration/src/m20250203_000004_add_teams_manager_fk.rs`

This migration establishes the foreign key relationship from `teams.manager_id` to `users.id`. It's separated from the teams creation to avoid circular dependency issues with migration execution order.

### 2. Sea-ORM Entity Definitions

A new `entity` crate has been created at `crates/entity/` containing fully typed, serializable entities for database interaction.

#### **Entity Crate Structure**
```
crates/entity/
├── Cargo.toml          # Entity crate configuration
├── src/
│   ├── lib.rs          # Entity crate exports
│   ├── users.rs        # Users entity
│   ├── teams.rs        # Teams entity
│   └── team_members.rs # TeamMembers entity
```

#### **Users Entity** (`users.rs`)
- **Model**: Full user record with all database fields
- **Relations**:
  - `TeamMembers`: One-to-many relationship
  - `ManagedTeams`: Teams managed by user (has_many)
- **Enum**: `UserStatus` with Display impl
- **Customization Regions**: Preserved for manual additions

#### **Teams Entity** (`teams.rs`)
- **Model**: Complete team record
- **Relations**:
  - `ParentTeam`: Hierarchical self-reference (belongs_to)
  - `ChildTeams`: Child teams (has_many)
  - `Manager`: Team manager (belongs_to users)
  - `TeamMembers`: Team members (has_many)
- **Customization Regions**: Preserved for manual additions

#### **Team Members Entity** (`team_members.rs`)
- **Model**: Membership relationship record
- **Relations**:
  - `Team`: Parent team (belongs_to)
  - `User`: Member user (belongs_to)
- **Enum**: `TeamMemberRole` with Display impl
- **Customization Regions**: Preserved for manual additions

#### **Key Features**
- ✅ Full serde serialization/deserialization support
- ✅ Custom enum implementations with database mapping
- ✅ Proper relationship definitions
- ✅ Display trait implementations for enums
- ✅ Customization regions marked with special comments

### 3. Entity Generation and Reconciliation Script

Created: `scripts/generate-entities.sh`

A production-ready bash script that automates entity generation and customization preservation.

**Features:**
- Generates entities from live PostgreSQL schema using sea-orm-cli
- Preserves customizations within marked regions:
  ```rust
  // CUSTOMIZATION REGION START: <name>
  // ... custom code here ...
  // CUSTOMIZATION REGION END
  ```
- Automatic backup creation before modifications
- Dry-run capability for safe testing
- Verbose logging for debugging
- Code formatting via `cargo fmt`
- Entity validation via `cargo check`

**Usage:**
```bash
# Generate entities from database
./scripts/generate-entities.sh "postgresql://user:pass@localhost/horizon"

# Dry-run mode (preview changes)
./scripts/generate-entities.sh "postgresql://..." --dry-run

# Verbose output
./scripts/generate-entities.sh "postgresql://..." --verbose

# All options
./scripts/generate-entities.sh "postgresql://..." --dry-run --verbose
```

**Workflow:**
1. Validates sea-orm-cli installation
2. Generates fresh entities from database schema
3. Extracts customizations from existing files
4. Injects customizations into generated entities
5. Updates lib.rs exports
6. Formats code with cargo fmt
7. Validates via cargo check

### 4. Workspace Integration

**Updated Files:**
- `Cargo.toml` (workspace root): Added `crates/entity` to members list
- `crates/entity/Cargo.toml`: New entity crate with dependencies:
  - `sea-orm` (workspace)
  - `serde` (workspace)
  - `chrono` (0.4.40, with serde feature)
  - `uuid` (1.11.0, with v4 and serde features)

---

## Database Design Decisions

### 1. User Status Enumeration
Instead of nullable fields or boolean flags, we use an explicit `user_status` enum to clearly represent user account state:
- **Active**: Normal usage
- **Inactive**: User-initiated deactivation
- **Suspended**: Administrative action
- **Pending Verification**: New accounts awaiting email confirmation

### 2. Team Hierarchy
The `parent_team_id` field with self-referential foreign key enables unlimited team nesting:
- Creates flexible organizational structures
- `SET_NULL` on delete allows orphaning without cascading deletion
- Supports multi-level team hierarchies

### 3. Team Member Roles (RBAC)
Four role tiers enable granular access control:
- **Owner**: Full team control
- **Admin**: Management capabilities
- **Member**: Standard resource access
- **Viewer**: Read-only access

This provides a foundation for B-02 RBAC implementation.

### 4. Soft Deletes
All three tables support soft deletes via `deleted_at`:
- Enables audit trails and recovery
- Preserves referential integrity
- Supports compliance requirements

### 5. Cascading Deletes
- Team members cascade with team/user deletion (data cleanliness)
- Manager cannot be deleted while managing teams (RESTRICT)
- Maintains data consistency

### 6. Unique Constraints
- Email and username unique per user (login identifiers)
- Team slug unique globally (URL-safe identifiers)
- (team_id, user_id) composite unique (no duplicate memberships)

---

## Architecture Decisions

### Entity Generation Strategy

Rather than manually maintaining Sea-ORM entities, we implemented an **idempotent reconciliation script** that:

1. **Generates fresh entities** from the live database schema using sea-orm-cli
2. **Preserves customizations** within clearly marked regions
3. **Maintains consistency** across the codebase
4. **Enables CI/CD integration** for schema-driven development

This approach follows best practices from production ORMs and enables:
- ✅ Single source of truth (database schema)
- ✅ Automatic entity updates when schema changes
- ✅ Safe customizations that survive regeneration
- ✅ No manual entity synchronization burden

### Customization Regions

Entities contain marked regions for safe customizations:

```rust
// CUSTOMIZATION REGION START: <identifier>
// Your custom code here
// CUSTOMIZATION REGION END
```

The script preserves these regions during regeneration, enabling:
- Custom validation methods
- Additional trait implementations
- Helper functions
- Documentation

---

## Testing and Validation

✅ **Migration Compilation**: All 4 migrations compile without errors  
✅ **Entity Compilation**: Entity crate passes `cargo check`  
✅ **Workspace Integration**: Entity crate integrated into workspace  
✅ **Type Safety**: Full Rust type safety with Sea-ORM enums  
✅ **Serialization**: serde support for JSON APIs

---

## Migration Execution

To apply these migrations to your PostgreSQL database:

```bash
# Set DATABASE_URL
export DATABASE_URL="postgresql://user:password@localhost:5432/horizon"

# Run migrations
cd crates/migration
cargo run -- up

# Rollback (if needed)
cargo run -- down
```

---

## Next Steps (Phase B-02 onwards)

The authentication schema established in B-01 provides the foundation for:

- **B-02**: Role-Based Access Control (RBAC) Schema
  - `roles` table with permissions
  - `user_roles` table with scope and expiration
  - `api_keys` table for programmatic access

- **B-03**: Password Authentication Implementation
  - Argon2id password hashing
  - Registration endpoint
  - Login endpoint

- **B-04 through B-07**: JWT tokens, MFA, API endpoints, security middleware

---

## Files Delivered

```
crates/
├── entity/                                      [NEW]
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── users.rs
│       ├── teams.rs
│       └── team_members.rs
│
└── migration/src/
    ├── m20250203_000001_create_users_table.rs
    ├── m20250203_000002_create_teams_table.rs
    ├── m20250203_000003_create_team_members_table.rs
    └── m20250203_000004_add_teams_manager_fk.rs

scripts/
└── generate-entities.sh                         [NEW]

Root:
├── Cargo.toml (updated - added entity crate)
└── PHASE_B01_SUMMARY.md (this file)
```

---

## Design Patterns Used

### 1. **Sea-ORM Relationships**
- Proper `DeriveRelation` enums
- Correct `Related` trait implementations
- Bidirectional relationship support

### 2. **Enum Mapping**
- `#[sea_orm(...)]` macros for database mapping
- String values for database compatibility
- Display trait for logging/UI

### 3. **Customization Preservation**
- Comment-based region markers
- Regex-based content extraction
- Idempotent reconciliation logic

### 4. **Database Design**
- UUID primary keys (no sequential IDs)
- Explicit enums over booleans
- Soft deletes via `deleted_at`
- Proper indexing for common queries

---

## Security Considerations

✅ **Password Hashing**: Database schema ready for Argon2id (B-03)  
✅ **Soft Deletes**: Enables audit trail creation  
✅ **Role-Based**: Foundation for RBAC in B-02  
✅ **UUID Keys**: Prevents ID enumeration attacks  
✅ **Constraints**: Database enforces uniqueness and relationships  

---

## Documentation

All code includes:
- ✅ Module-level documentation
- ✅ Enum variant documentation
- ✅ Relationship documentation
- ✅ Customization region comments
- ✅ Field descriptions

---

## Verification Checklist

- [x] All 4 migrations compile
- [x] Entity crate compiles
- [x] Entities integrated into workspace
- [x] All relationships properly defined
- [x] Enums properly mapped to database
- [x] Entity generation script created
- [x] Customization regions marked
- [x] Documentation complete
- [x] No compilation warnings (except migration deprecations)

---

## Issues and Notes

1. **Original migration sample code** (m20220101_000001) contains `todo!()` macros and warnings - this is expected for the placeholder migration. It can be removed once other migrations are verified working.

2. **Type annotations in Relation traits**: Uses `RelationDef` return type (not `impl RelationTrait`) as required by Sea-ORM 2.0-rc.30 API.

3. **UUID dependency**: Added `uuid` crate with v4 and serde features for entity primary keys.

---

**Phase B-01 is complete and ready for PR review.**

For questions or modifications, refer to the implementation details in each source file's comments and customization regions.
