#!/bin/bash

# Script to run code coverage using grcov
# Excludes src-tauri from coverage
# Requires PostgreSQL and Redis to be running

set -e

# Check if DATABASE_URL is set, otherwise use default test database
if [ -z "$DATABASE_URL" ]; then
    export DATABASE_URL="postgres://horizon:horizon_secret_password_change_in_production@localhost:5432/horizon"
fi

# Check if REDIS_URL is set, otherwise use default test Redis
if [ -z "$REDIS_URL" ]; then
    export REDIS_URL="redis://localhost:6379"
fi

echo "Using DATABASE_URL: $DATABASE_URL"
echo "Using REDIS_URL: $REDIS_URL"

# Check if PostgreSQL is running by trying to connect
echo "Checking if PostgreSQL is available..."
POSTGRES_AVAILABLE=false

# Try using sqlx to connect (most reliable check with our tools)
if command -v sqlx &> /dev/null; then
    # Try connecting to the default postgres database to verify PostgreSQL is running
    # Parse URL allowing optional password: postgres://user(:pass)?@host:port/db
    DB_USER=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\1|')
    DB_PASS=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\3|')
    DB_HOST=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\4|')
    DB_PORT=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\5|')

    # Construct URL for sqlx, omitting password if not present
    if [ -n "$DB_PASS" ]; then
        TEST_URL="postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/postgres"
    else
        TEST_URL="postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/postgres"
    fi

    if export DATABASE_URL="$TEST_URL" && \
       timeout 10 sqlx database create &>/dev/null; then
        POSTGRES_AVAILABLE=true
    fi
fi

# Try using psql if available
if [ "$POSTGRES_AVAILABLE" = false ] && command -v psql &> /dev/null; then
    DB_USER=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\1|')
    DB_PASS=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\3|')
    DB_HOST=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\4|')
    DB_PORT=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:@]+)(:([^@]+))?@([^:]+):([0-9]+)/(.+)|\5|')

    # Always unset any pre-existing PGPASSWORD first, then set if we have a password
    unset PGPASSWORD 2>/dev/null || true
    if [ -n "$DB_PASS" ]; then
        export PGPASSWORD="$DB_PASS"
    fi
    if timeout 10 psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT 1;" &>/dev/null; then
        POSTGRES_AVAILABLE=true
    fi
    unset PGPASSWORD 2>/dev/null || true
fi

if [ "$POSTGRES_AVAILABLE" = false ]; then
    echo ""
    echo "=========================================="
    echo "ERROR: PostgreSQL is not running!"
    echo "=========================================="
    echo ""
    echo "The coverage script requires PostgreSQL to be running."
    echo ""
    echo "Please start PostgreSQL first:"
    echo "  - On macOS with Homebrew:"
    echo "    brew services start postgresql"
    echo ""
    echo "  - On Linux with systemd:"
    echo "    sudo systemctl start postgresql"
    echo ""
    echo "  - Using Docker:"
    echo "    docker run -d \\"
    echo "      --name horizon-postgres \\"
    echo "      -e POSTGRES_USER=horizon \\"
    echo "      -e POSTGRES_PASSWORD=horizon_secret_password_change_in_production \\"
    echo "      -p 5432:5432 \\"
    echo "      postgres"
    echo ""
    echo "  - Or create a PostgreSQL instance on your preferred hosting service"
    echo ""
    echo "Once PostgreSQL is running, re-run this script."
    echo "=========================================="
    exit 1
fi

echo "PostgreSQL is available."

# Save original DATABASE_URL
ORIGINAL_DATABASE_URL="$DATABASE_URL"

# Extract connection details from DATABASE_URL
# Format: postgres://user:password@host:port/database
DB_USER=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)|\1|')
DB_PASS=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)|\2|')
DB_HOST=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)|\3|')
DB_PORT=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)|\4|')
DB_NAME=$(echo "$DATABASE_URL" | sed -E 's|postgres://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)|\5|')

# Create the database if it doesn't exist
echo "Checking if database '$DB_NAME' exists..."

# Try using psql first (preferred)
if command -v psql &> /dev/null; then
    export PGPASSWORD="$DB_PASS"
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        echo "Database '$DB_NAME' already exists."
    else
        echo "Database '$DB_NAME' does not exist. Creating it..."
        if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE \"$DB_NAME\";" 2>/dev/null; then
            echo "Database '$DB_NAME' created successfully."
        else
            echo "Warning: Could not create database. Attempting to continue..."
        fi
    fi
    unset PGPASSWORD 2>/dev/null || true
# Fall back to sqlx CLI if psql is not available
elif command -v sqlx &> /dev/null; then
    echo "psql not found, using sqlx CLI..."
    # Try to create database using sqlx
    export DATABASE_URL="$ORIGINAL_DATABASE_URL"
    if ! sqlx database create &>/dev/null; then
        echo "Database '$DB_NAME' does not exist. Creating it..."
        if sqlx database create 2>/dev/null; then
            echo "Database '$DB_NAME' created successfully."
        else
            echo "Warning: Could not create database using sqlx."
        fi
    else
        echo "Database '$DB_NAME' already exists."
    fi
else
    echo "Warning: Neither psql nor sqlx CLI found. Database creation may fail."
    echo "Please ensure PostgreSQL is running and the database exists."
fi

# Restore original DATABASE_URL
export DATABASE_URL="$ORIGINAL_DATABASE_URL"

echo "Running database migrations..."
cargo run --package migration --features cli -- -u "$DATABASE_URL" fresh

echo "Installing grcov if not present..."
echo "Creating profile directory..."
mkdir -p target/profraw
mkdir -p target/coverage

# Clean any existing profraw files
rm -f target/profraw/*.profraw

echo "Running tests with coverage instrumentation (excluding src-tauri)..."
RUST_TEST_THREADS=1 RUSTFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE="target/profraw/cyberpath-%p-%m.profraw" cargo test --workspace --exclude ui

echo "Generating coverage report..."
grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t html \
    --branch \
    --ignore-not-existing \
    --ignore "*/src-tauri/*" \
    --ignore "*/.cargo/*" \
    --ignore "*/.docker/**" \
    --ignore "*/entity/src/*.rs" \
    --ignore "*/migration/src/*.rs" \
    -o ./target/coverage/html

echo "Coverage report generated at ./target/coverage/html/index.html"

# Optional: Generate lcov for CI
grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t lcov \
    --branch \
    --ignore-not-existing \
    --ignore "*/src-tauri/*" \
    --ignore "*/.cargo/*" \
    --ignore "*/.docker/**" \
    --ignore "*/entity/src/*.rs" \
    --ignore "*/migration/src/*.rs" \
    -o ./target/coverage/lcov.info
echo "LCOV report generated at ./target/coverage/lcov.info"

echo "Generating additional coverage formats..."

grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t cobertura \
    --branch \
    --ignore-not-existing \
    --ignore "*/src-tauri/*" \
    --ignore "*/.cargo/*" \
    --ignore "*/.docker/**" \
    --ignore "*/entity/src/*.rs" \
    --ignore "*/migration/src/*.rs" \
    -o ./target/coverage/cobertura.xml

grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t markdown \
    --branch \
    --ignore-not-existing \
    --ignore "*/src-tauri/*" \
    --ignore "*/.cargo/*" \
    --ignore "*/.docker/**" \
    --ignore "*/entity/src/*.rs" \
    --ignore "*/migration/src/*.rs" \
    -o ./target/coverage/coverage.md

echo "Additional coverage reports generated in ./target/coverage/"
