#!/usr/bin/env bash
#
# Entity Generation Script for Horizon CMDB
#
# This script generates Sea-ORM entities from the database schema using sea-orm-cli.
# It automatically discovers all tables in the database and generates corresponding entities.
#
# Usage:
#   ./scripts/generate-entities.sh [database_url] [--dry-run] [--verbose]
#
# Environment Variables:
#   DATABASE_URL: PostgreSQL connection string
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTITY_DIR="$PROJECT_ROOT/crates/entity/src"
DRY_RUN=false
VERBOSE=false
: "${DATABASE_URL=}"  # Only initialize if not already set

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Safe URL display - redact credentials
safe_url() {
    local url="$1"
    if [[ "$url" =~ ^([^:]+://[^@]+@)(.+)$ ]]; then
        # Contains credentials - redact everything after ://
        echo "${BASH_REMATCH[1]}[REDACTED]${BASH_REMATCH[2]}"
    else
        # No credentials, show as-is (or just show host)
        echo "[REDACTED - contains credentials]"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 <database_url> [--dry-run] [--verbose]"
                echo ""
                echo "Arguments:"
                echo "  database_url    PostgreSQL connection string"
                echo "  --dry-run       Preview changes without applying"
                echo "  --verbose, -v   Verbose output"
                echo ""
                echo "Environment Variables:"
                echo "  DATABASE_URL    PostgreSQL connection string (alternative to argument)"
                exit 0
                ;;
            *)
                if [ -z "$DATABASE_URL" ]; then
                    DATABASE_URL="$1"
                else
                    log_error "Unknown argument: $1"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Check DATABASE_URL
    if [ -z "$DATABASE_URL" ]; then
        log_error "Database URL not provided. Use: $0 <database_url> [--dry-run]"
        log_error "Or set DATABASE_URL environment variable"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check sea-orm-cli
    if ! command -v sea-orm-cli &> /dev/null; then
        log_error "sea-orm-cli not found. Install with: cargo install sea-orm-cli"
        exit 1
    fi
    log_success "sea-orm-cli found: $(sea-orm-cli --version 2>&1 || echo "unknown version")"

    # Check cargo
    if ! command -v cargo &> /dev/null; then
        log_warning "cargo not found - some features may not work"
    fi

    # Ensure entity directory exists
    if [ ! -d "$ENTITY_DIR" ]; then
        log_info "Creating entity directory: $ENTITY_DIR"
        mkdir -p "$ENTITY_DIR"
    fi
}

# Generate entities using sea-orm-cli
generate_entities() {
    log_step "Generating entities from database schema..."

    # Run sea-orm-cli generate entity
    # This will automatically discover all tables and generate entities
    local cmd=(
        "sea-orm-cli"
        "generate"
        "entity"
        "--lib"
        "-u" "$DATABASE_URL"
        "-o" "$ENTITY_DIR"
        "--with-serde" "both"
        "--impl-active-model-behavior"
        "--entity-format" "dense"
        "--serde-skip-hidden-column"
    )

    if [ "$VERBOSE" = true ]; then
        log_info "Running: ${cmd[*]}"
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would run: ${cmd[*]}"
        return 0
    fi

    if ! "${cmd[@]}"; then
        log_error "Entity generation failed"
        return 1
    fi

    log_success "Entities generated successfully"

    # List generated files
    local generated_count
    rm -f "$ENTITY_DIR/lib.rs"  # Remove lib.rs to avoid counting it
    rm -f "$ENTITY_DIR/mod.rs"  # Remove mod.rs to avoid counting it
    rm -f "$ENTITY_DIR/prelude.rs"  # Remove prelude.rs to avoid counting it
    generated_count=$(find "$ENTITY_DIR" -name "*.rs" -type f | wc -l)
    log_info "Generated $generated_count entity files"
}

# Update lib.rs to export all entities
update_lib_rs() {
    log_step "Updating lib.rs..."

    # Get list of entity modules from generated files
    local entity_files=("$ENTITY_DIR"/*.rs)
    local modules_list=""

    for file in "${entity_files[@]}"; do
        local filename
        filename=$(basename "$file")
        if [ -f "$file" ] && [ "$filename" != "lib.rs" ] && [ "$filename" != "mod.rs" ] && [ "$filename" != "prelude.rs" ] && [ "$filename" != "sea_orm_active_enums.rs" ]; then
            local module_name
            module_name=$(basename "$file" .rs)
            modules_list="${modules_list}pub mod ${module_name};"$'\n'

            # Extract the module name in PascalCase for Entity name
            local pascal_module
            pascal_module=$(echo "$module_name" | sed -r 's/(^|_)([a-z])/\U\2/g')
            modules_list="${modules_list}pub use ${module_name}::Entity as ${pascal_module};"$'\n'
        fi
    done

    # Generate new lib.rs with correct format
    local lib_content="//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated from the database schema.

pub mod sea_orm_active_enums;
${modules_list}
"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would update lib.rs with entity exports"
        echo "$lib_content"
        return 0
    fi

    echo "$lib_content" > "$ENTITY_DIR/lib.rs"
    log_success "lib.rs updated"
}

# Format generated code
format_code() {
    log_step "Formatting generated code..."

    if ! command -v cargo &> /dev/null; then
        log_warning "cargo not found, skipping format"
        return
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would format code with cargo fmt"
        return
    fi

    cd "$PROJECT_ROOT"
    if cargo fmt --package entity 2>/dev/null; then
        log_success "Code formatted"
    else
        log_warning "Code formatting failed, continuing anyway"
    fi
}

# Validate generated entities
validate_entities() {
    log_step "Validating generated entities..."

    if ! command -v cargo &> /dev/null; then
        log_warning "cargo not found, skipping validation"
        return
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would validate entities with cargo check"
        return
    fi

    cd "$PROJECT_ROOT"
    if cargo check --package entity 2>/dev/null; then
        log_success "Entities validated successfully"
    else
        log_error "Entity validation failed"
        return 1
    fi
}

# ============================================================================
# SECURITY: Inject serde skip attributes for sensitive fields
# This ensures sensitive fields like password_hash and totp_secret are not
# serialized by default, preventing accidental exposure in API responses.
# This function is idempotent and safe to run multiple times.
# ============================================================================
inject_security_attributes() {
    log_step "Injecting security attributes for sensitive fields..."

    # Define sensitive field patterns (field name only, pattern is built below)
    local sensitive_fields=("password_hash" "totp_secret")

    local modified_count=0

    for field_name in "${sensitive_fields[@]}"; do
        # Find entity files containing this field
        while IFS= read -r entity_file; do
            if [ -f "$entity_file" ]; then
                # Check if serde skip is already applied to avoid duplicates
                if ! grep -B1 "pub ${field_name}:" "$entity_file" 2>/dev/null | grep -q "serde(skip_serializing)"; then
                    if [ "$DRY_RUN" = true ]; then
                        log_info "[DRY-RUN] Would add #[serde(skip_serializing)] to ${field_name} in $(basename "$entity_file")"
                    else
                        # Use awk to insert the serde attribute with proper indentation (4 spaces)
                        # Pattern: "^    pub field_name:" matches field declarations in generated entities
                        awk -v field="pub ${field_name}:" '
                            $0 ~ field {
                                print "    #[serde(skip_serializing)]"
                            }
                            { print }
                        ' "$entity_file" > "${entity_file}.tmp" && mv "${entity_file}.tmp" "$entity_file"
                        log_info "Added security attribute to ${field_name} in $(basename "$entity_file")"
                        ((modified_count++)) || true
                    fi
                else
                    log_info "Security attribute already present for ${field_name} in $(basename "$entity_file")"
                fi
            fi
        done < <(grep -l "pub ${field_name}:" "$ENTITY_DIR"/*.rs 2>/dev/null | head -1)
    done

    if [ "$DRY_RUN" = true ]; then
        return 0
    fi

    if [ $modified_count -gt 0 ]; then
        log_success "Security attributes injected in $modified_count field(s)"
    else
        log_info "No new security attributes needed"
    fi
}

# Main execution
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    echo "  Horizon Entity Generation Script"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""

    parse_args "$@"

    echo ""
    echo "Configuration:"
    echo "  Database URL: $(safe_url "$DATABASE_URL")"
    echo "  Entity Dir:   $ENTITY_DIR"
    echo "  Dry Run:      $DRY_RUN"
    echo "  Verbose:      $VERBOSE"
    echo ""

    check_prerequisites

    # Generate entities
    generate_entities || exit 1

    # Update lib.rs
    update_lib_rs

    # Inject security attributes for sensitive fields
    inject_security_attributes

    # Format code
    format_code

    # Validate entities
    validate_entities || exit 1

    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    log_success "Entity generation completed successfully!"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log_info "Run without --dry-run to apply changes."
    else
        log_info "Generated entities are ready in: $ENTITY_DIR"
    fi
    echo ""
}

# Run main
main "$@"
