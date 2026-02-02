#!/bin/bash

# Script to run code coverage using grcov
# Excludes src-tauri from coverage

set -e

echo "Installing grcov if not present..."
cargo install grcov || echo "grcov already installed"

echo "Creating profile directory..."
mkdir -p target/profraw
mkdir -p target/coverage

# Clean any existing profraw files
rm -f target/profraw/*.profraw

echo "Running tests with coverage instrumentation (excluding src-tauri)..."
RUSTFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE="target/profraw/cyberpath-%p-%m.profraw" cargo test --workspace --exclude ui

echo "Generating coverage report..."
grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t html \
    --branch \
    --ignore-not-existing \
    --ignore "*/src-tauri/*" \
    --ignore "*/.cargo/*" \
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
    -o ./target/coverage/cobertura.xml

grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t markdown \
    --branch \
    --ignore-not-existing \
    --ignore "*/src-tauri/*" \
    --ignore "*/.cargo/*" \
    -o ./target/coverage/coverage.md

echo "Additional coverage reports generated in ./target/coverage/"
