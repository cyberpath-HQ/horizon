#!/usr/bin/env bash
#
# Entity Generation and Reconciliation Script
# 
# This script generates Sea-ORM entities from the database schema while preserving
# customizations made within designated regions marked with:
#   CUSTOMIZATION REGION START: <name>
#   CUSTOMIZATION REGION END
#
# Usage:
#   ./scripts/generate-entities.sh [database_url] [--dry-run] [--verbose]
#
# Environment Variables:
#   DATABASE_URL: PostgreSQL connection string (can also be passed as first argument)
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTITY_DIR="$PROJECT_ROOT/crates/entity/src"
MIGRATION_DIR="$PROJECT_ROOT/crates/migration"
DRY_RUN=false
VERBOSE=false

# Parse arguments
DATABASE_URL="${1:-${DATABASE_URL:-}}"
if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}Error: DATABASE_URL not provided${NC}"
    echo "Usage: $0 <database_url> [--dry-run] [--verbose]"
    exit 1
fi

while [[ $# -gt 1 ]]; do
    case "$2" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Helper functions
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

# Check if Sea-ORM CLI is installed
check_sea_orm_cli() {
    if ! command -v sea-orm-cli &> /dev/null; then
        log_error "sea-orm-cli not found. Install with: cargo install sea-orm-cli"
        exit 1
    fi
    log_success "sea-orm-cli found"
}

# Extract customization regions from a file
extract_customizations() {
    local file=$1
    local -n customizations=$2
    
    if [ ! -f "$file" ]; then
        return
    fi
    
    local in_region=false
    local region_name=""
    local region_content=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*//[[:space:]]*CUSTOMIZATION\ REGION\ START:[[:space:]]*(.+)$ ]]; then
            in_region=true
            region_name="${BASH_REMATCH[1]}"
            region_content="$line"
        elif [[ "$line" =~ ^[[:space:]]*//[[:space:]]*CUSTOMIZATION\ REGION\ END$ ]]; then
            if [ "$in_region" = true ]; then
                region_content+=$'\n'"$line"
                customizations["$region_name"]="$region_content"
                in_region=false
                region_name=""
                region_content=""
            fi
        elif [ "$in_region" = true ]; then
            region_content+=$'\n'"$line"
        fi
    done < "$file"
}

# Insert customization regions into a file
inject_customizations() {
    local file=$1
    local -n customizations=$2
    local temp_file="$file.tmp"
    
    if [ ! -f "$file" ]; then
        cp "$file.gen" "$file"
        return
    fi
    
    local in_region=false
    local region_name=""
    local found_start=false
    
    {
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*//[[:space:]]*CUSTOMIZATION\ REGION\ START:[[:space:]]*(.+)$ ]]; then
                in_region=true
                region_name="${BASH_REMATCH[1]}"
                found_start=false
                
                # Output the region from customizations if it exists
                if [ -n "${customizations[$region_name]:-}" ]; then
                    echo "${customizations[$region_name]}"
                    found_start=true
                else
                    echo "$line"
                fi
            elif [[ "$line" =~ ^[[:space:]]*//[[:space:]]*CUSTOMIZATION\ REGION\ END$ ]]; then
                if [ "$in_region" = true ] && [ "$found_start" = true ]; then
                    echo "$line"
                    in_region=false
                    region_name=""
                elif [ "$in_region" = true ]; then
                    echo "$line"
                    in_region=false
                    region_name=""
                fi
            elif [ "$in_region" = true ] && [ "$found_start" = true ]; then
                # Skip lines inside regions we're replacing
                continue
            else
                echo "$line"
            fi
        done < "$file.gen"
    } > "$temp_file"
    
    mv "$temp_file" "$file"
}

# Generate entities using sea-orm-cli
generate_entities() {
    log_info "Generating entities from database..."
    
    cd "$MIGRATION_DIR"
    
    local sea_orm_cmd=(
        "sea-orm-cli"
        "generate"
        "entity"
        "-u" "$DATABASE_URL"
        "-o" "../entity/src"
        "--with-serde" "both"
        "--impl-active-model-behavior"
        "--entity-format" "dense"
        "--serde-skip-hidden-column"
    )
    
    if [ "$VERBOSE" = true ]; then
        log_info "Running: ${sea_orm_cmd[*]}"
    fi
    
    if ! "${sea_orm_cmd[@]}"; then
        log_error "Entity generation failed"
        return 1
    fi
    
    log_success "Entities generated"
}

# Reconcile customizations
reconcile_customizations() {
    log_info "Reconciling customizations..."
    
    local entity_files=(
        "$ENTITY_DIR/users.rs"
        "$ENTITY_DIR/teams.rs"
        "$ENTITY_DIR/team_members.rs"
    )
    
    for file in "${entity_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_warning "File not found: $file (skipping)"
            continue
        fi
        
        local -A customizations
        extract_customizations "$file" customizations
        
        if [ ${#customizations[@]} -gt 0 ]; then
            log_info "Found ${#customizations[@]} customization region(s) in $(basename "$file")"
            
            if [ "$DRY_RUN" = false ]; then
                # Backup original
                cp "$file" "$file.bak"
                
                # Inject customizations
                inject_customizations "$file" customizations
                
                log_success "Customizations injected into $(basename "$file")"
            else
                log_info "[DRY-RUN] Would inject customizations into $(basename "$file")"
            fi
        fi
    done
}

# Update lib.rs to export all entities
update_lib_rs() {
    log_info "Updating lib.rs..."
    
    local lib_file="$ENTITY_DIR/lib.rs"
    
    # Generate new lib.rs content
    cat > "$lib_file.gen" << 'EOF'
//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated and managed using the entity reconciliation script.

pub mod team_members;
pub mod teams;
pub mod users;

pub use team_members::Entity as TeamMembers;
pub use teams::Entity as Teams;
pub use users::Entity as Users;
EOF
    
    if [ "$DRY_RUN" = false ]; then
        mv "$lib_file.gen" "$lib_file"
        log_success "lib.rs updated"
    else
        log_info "[DRY-RUN] Would update lib.rs"
    fi
}

# Format generated code
format_code() {
    log_info "Formatting generated code..."
    
    if ! command -v cargo &> /dev/null; then
        log_warning "cargo not found, skipping format"
        return
    fi
    
    if [ "$DRY_RUN" = false ]; then
        cd "$PROJECT_ROOT"
        if ! cargo fmt --package entity 2>/dev/null; then
            log_warning "Code formatting failed, continuing anyway"
        else
            log_success "Code formatted"
        fi
    else
        log_info "[DRY-RUN] Would format code"
    fi
}

# Validate generated entities
validate_entities() {
    log_info "Validating generated entities..."
    
    if [ "$DRY_RUN" = false ]; then
        cd "$PROJECT_ROOT"
        if ! cargo check --package entity 2>/dev/null; then
            log_error "Entity validation failed"
            return 1
        fi
        log_success "Entities validated"
    else
        log_info "[DRY-RUN] Would validate entities"
    fi
}

# Main execution
main() {
    log_info "Starting entity generation and reconciliation"
    [ "$DRY_RUN" = true ] && log_warning "Running in DRY-RUN mode - no changes will be made"
    
    check_sea_orm_cli
    generate_entities || return 1
    reconcile_customizations
    update_lib_rs
    format_code
    validate_entities || return 1
    
    log_success "Entity generation and reconciliation completed successfully!"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "DRY-RUN complete. Run without --dry-run to apply changes."
    fi
}

# Run main
main "$@"
