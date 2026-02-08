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
    -o ./target/coverage/coverage.md

echo "Additional coverage reports generated in ./target/coverage/"
