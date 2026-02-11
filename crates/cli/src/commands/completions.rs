//! # CLI Completions Command
//!
//! Shell completions generation for the Horizon CLI.

use clap::Command;
use clap_complete::Shell;
use error::Result;

/// Generates shell completions for the CLI
///
/// # Arguments
///
/// * `shell` - The shell to generate completions for
/// * `cmd` - The CLI command to generate completions for
///
/// # Returns
///
/// A `Result` indicating success or failure.
pub fn completions(shell: Shell, cmd: &mut Command) -> Result<()> {
    clap_complete::generate(shell, cmd, "horizon", &mut std::io::stdout());
    Ok(())
}
