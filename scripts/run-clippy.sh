#!/bin/bash

# Parse arguments
FIX_FLAG=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            FIX_FLAG="--fix --allow-dirty"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--fix]"
            exit 1
            ;;
    esac
done

# Check for cargo-workspaces subcommand
if ! cargo workspaces list &>/dev/null; then
    echo "cargo-workspaces not found. Installing via cargo install..."
    cargo install cargo-workspaces
fi

# List workspace elements and filter out 'entity'
echo "Listing workspace elements..."
workspace_elements=$(cargo workspaces list 2>/dev/null | grep -v "^entity$" || true)

if [ -z "$workspace_elements" ]; then
    echo "No workspace elements found."
    exit 0
fi

# Run clippy for each element
for element in $workspace_elements; do
    echo "Running clippy for: $element"
    if ! cargo clippy -p "$element" --all-features $FIX_FLAG -- -D warnings --no-deps; then
        echo "Clippy failed for: $element"
        exit 1
    fi
done

echo "All clippy checks passed!"
