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
DATABASE_URL=""

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
        DATABASE_URL="${DATABASE_URL:-}"
        if [ -z "$DATABASE_URL" ]; then
            log_error "Database URL not provided. Use: $0 <database_url> [--dry-run]"
            exit 1
        fi
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
        if [ -f "$file" ] && [ "$(basename "$file")" != "lib.rs" ]; then
            local module_name
            module_name=$(basename "$file" .rs)
            modules_list="${modules_list}pub mod ${module_name};"$'\n'

            # Extract entity name for re-export
            local entity_name
            entity_name=$(grep -oP 'pub struct Entity\s*;' "$file" 2>/dev/null | \
                         sed 's/pub struct Entity\s*;.*//' | \
                         head -1 | \
                         xargs)
            if [ -n "$entity_name" ]; then
                # Extract the module name in PascalCase for Entity name
                local pascal_module
                pascal_module=$(echo "$module_name" | sed -r 's/(^|_)([a-z])/\U\2/g')
                modules_list="${modules_list}pub use ${module_name}::Entity as ${pascal_module};"$'\n'
            fi
        fi
    done

    # Generate new lib.rs
    local lib_content="//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated from the database schema.

$modules_list
"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would update lib.rs with entity exports"
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
    echo "  Database URL: ${DATABASE_URL:0:50}..."
    echo "  Entity Dir:   $ENTITY_DIR"
    echo "  Dry Run:      $DRY_RUN"
    echo "  Verbose:      $VERBOSE"
    echo ""

    check_prerequisites

    # Generate entities
    generate_entities || exit 1

    # Update lib.rs
    update_lib_rs

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
