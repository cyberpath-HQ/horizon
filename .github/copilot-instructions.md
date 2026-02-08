# Cyberpath Sentinel AI Coding Guidelines

> **IMPORTANT NOTE**: Never leave TODOs, stub code, or uncompleted functions unless explicitly asked to do so. All code
> must be fully implemented, tested, and documented.

## Development Workflow

- Build: `cargo build` (workspace setup with crates/sentinel/)
- Test: `cargo test` (run from root)
- Format: `cargo fmt --all`
- Lint: `cargo clippy --all-features -- -D warnings`

## Quality Assurance

- **Documentation**: For each feature or function implemented, provide thorough documentation at the function level (doc
  comments) and inline comments explaining complex logic. All public APIs must have comprehensive docs explaining
  purpose, parameters, return values, and examples.
- **Unit Testing**: Each and every function must be unit tested wherever it is located. Tests must cover edge cases
  (e.g., empty inputs, invalid data, boundary conditions). Test coverage must be at least 90% across the codebase. Tests
  should be documented as standard code with clear names and comments.
- **Benchmarking**: For each non-test function, wherever it is, define benchmarks using `criterion` crate to measure
  performance. Benchmarks must check both best-case and worst-case path executions each and every time, ensuring
  performance regressions are caught early.

Reference `IMPLEMENTATION_PLAN.md` for component APIs and phase details.
