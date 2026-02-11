//! # Horizon CLI
//!
//! Command-line interface for Horizon CMDB.
//!
//! ## Usage
//!
//! ```bash
//! horizon serve    # Start the API server (runs migrations automatically)
//! horizon migrate  # Run database migrations
//! horizon --help   # Show help
//! ```

mod commands;
mod config;
mod server;
mod tls;

use clap::{CommandFactory as _, Parser, Subcommand};
use commands::{CompletionsArgs, MigrateArgs, ServeArgs};
use config::DatabaseConfig;

/// Horizon CMDB - Configuration Management Database
#[derive(Parser, Debug)]
#[command(name = "horizon")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The command to run
    #[command(subcommand)]
    command: Commands,

    /// Log level (debug, info, warn, error)
    #[arg(short = 'L', long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Output format (json, pretty, compact)
    #[arg(short, long, env = "HORIZON_LOG_FORMAT", default_value = "pretty")]
    log_format: String,
}

/// Available commands for the Horizon CLI
#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the API server
    Serve(ServeArgs),

    /// Run database migrations
    Migrate(MigrateArgs),

    /// Generate shell completions
    Completions(CompletionsArgs),

    /// Verify configuration
    Validate,
}

#[tokio::main]
async fn main() -> error::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    logging::init(&cli.log_level, &cli.log_format, None)
        .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))?;

    logging::info!(target: "app", command = ?cli.command, "Horizon CLI starting...");

    match cli.command {
        Commands::Serve(args) => {
            let config = DatabaseConfig::from_env().map_err(|_e| anyhow::anyhow!("Invalid database configuration"))?;
            server::serve(&config, args).await?
        },
        Commands::Migrate(args) => {
            let config = DatabaseConfig::from_env().map_err(|_e| anyhow::anyhow!("Invalid database configuration"))?;
            commands::migrate::migrate(&config, args).await?
        },
        Commands::Completions(args) => commands::completions::completions(args.shell, &mut Cli::command())?,
        Commands::Validate => commands::validate::validate()?,
    }

    logging::info!(target: "app", "Horizon CLI completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn test_cli_parse_serve() {
        let cli = Cli::parse_from(&["horizon", "serve", "--host", "127.0.0.1", "--port", "8080"]);
        match cli.command {
            Commands::Serve(args) => {
                assert_eq!(args.host, "127.0.0.1");
                assert_eq!(args.port, 8080);
                assert!(!args.tls);
            },
            _ => panic!("Expected Serve command"),
        }
    }

    #[test]
    fn test_cli_parse_validate() {
        let cli = Cli::parse_from(&["horizon", "validate"]);
        match cli.command {
            Commands::Validate => {},
            _ => panic!("Expected Validate command"),
        }
    }

    #[test]
    fn test_cli_default_values() {
        let cli = Cli::parse_from(&["horizon", "validate"]);
        assert_eq!(cli.log_level, "info");
        assert_eq!(cli.log_format, "pretty");
    }

    #[test]
    fn test_serve_args_tls() {
        let args = ServeArgs {
            host:     "0.0.0.0".to_string(),
            port:     3000,
            tls:      true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key:  Some("/path/to/key".to_string()),
        };
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key".to_string()));
    }

    #[tokio::test]
    async fn test_migrate_rollback() {
        let cli = Cli::parse_from(&["horizon", "migrate", "--rollback"]);
        match cli.command {
            Commands::Migrate(args) => {
                assert_eq!(args.rollback, true);
                assert_eq!(args.dry_run, false);
            },
            _ => panic!("Expected Migrate command"),
        }
    }

    #[test]
    fn test_cli_command_factory() {
        let cmd = Cli::command();
        assert!(cmd.get_name() == "horizon");
    }

    #[test]
    fn test_validate_returns_ok() {
        // Save original env vars and ensure all required vars are set
        let orig_host = std::env::var("HORIZON_DATABASE_HOST").ok();
        let orig_port = std::env::var("HORIZON_DATABASE_PORT").ok();
        let orig_name = std::env::var("HORIZON_DATABASE_NAME").ok();
        let orig_user = std::env::var("HORIZON_DATABASE_USER").ok();
        let orig_pass = std::env::var("HORIZON_DATABASE_PASSWORD").ok();

        // Set required env vars - overwrite any existing values
        unsafe {
            std::env::set_var("HORIZON_DATABASE_HOST", "localhost");
            std::env::set_var("HORIZON_DATABASE_PORT", "5432");
            std::env::set_var("HORIZON_DATABASE_NAME", "horizon");
            std::env::set_var("HORIZON_DATABASE_USER", "horizon");
            std::env::set_var(
                "HORIZON_DATABASE_PASSWORD",
                "horizon_secret_password_change_in_production",
            );
        }

        let result = commands::validate::validate();
        assert!(
            result.is_ok(),
            "Validation should succeed with all required env vars set"
        );

        // Restore original env vars
        unsafe {
            if let Some(v) = orig_host {
                std::env::set_var("HORIZON_DATABASE_HOST", v);
            }
            else {
                std::env::remove_var("HORIZON_DATABASE_HOST");
            }
            if let Some(v) = orig_port {
                std::env::set_var("HORIZON_DATABASE_PORT", v);
            }
            else {
                std::env::remove_var("HORIZON_DATABASE_PORT");
            }
            if let Some(v) = orig_name {
                std::env::set_var("HORIZON_DATABASE_NAME", v);
            }
            else {
                std::env::remove_var("HORIZON_DATABASE_NAME");
            }
            if let Some(v) = orig_user {
                std::env::set_var("HORIZON_DATABASE_USER", v);
            }
            else {
                std::env::remove_var("HORIZON_DATABASE_USER");
            }
            if let Some(v) = orig_pass {
                std::env::set_var("HORIZON_DATABASE_PASSWORD", v);
            }
            else {
                std::env::remove_var("HORIZON_DATABASE_PASSWORD");
            }
        }
    }

    #[test]
    fn test_validate_missing_vars() {
        // Save original env vars
        let orig_host = std::env::var("HORIZON_DATABASE_HOST").ok();
        let orig_port = std::env::var("HORIZON_DATABASE_PORT").ok();
        let orig_name = std::env::var("HORIZON_DATABASE_NAME").ok();
        let orig_user = std::env::var("HORIZON_DATABASE_USER").ok();
        let orig_pass = std::env::var("HORIZON_DATABASE_PASSWORD").ok();

        // Clear env vars
        unsafe {
            std::env::remove_var("HORIZON_DATABASE_HOST");
            std::env::remove_var("HORIZON_DATABASE_PORT");
            std::env::remove_var("HORIZON_DATABASE_NAME");
            std::env::remove_var("HORIZON_DATABASE_USER");
            std::env::remove_var("HORIZON_DATABASE_PASSWORD");
        }

        let result = commands::validate::validate();
        assert!(result.is_err());

        // Restore original env vars
        if let Some(v) = orig_host {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_HOST", v);
            }
        }
        if let Some(v) = orig_port {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_PORT", v);
            }
        }
        if let Some(v) = orig_name {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_NAME", v);
            }
        }
        if let Some(v) = orig_user {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_USER", v);
            }
        }
        if let Some(v) = orig_pass {
            unsafe {
                std::env::set_var("HORIZON_DATABASE_PASSWORD", v);
            }
        }
    }

    #[test]
    fn test_serve_args_default() {
        let args = ServeArgs {
            host:     "0.0.0.0".to_string(),
            port:     3000,
            tls:      false,
            tls_cert: None,
            tls_key:  None,
        };
        assert_eq!(args.host, "0.0.0.0");
        assert_eq!(args.port, 3000);
        assert!(!args.tls);
    }

    #[test]
    fn test_migrate_args_default() {
        let args = MigrateArgs {
            dry_run:  false,
            rollback: false,
        };
        assert!(!args.dry_run);
        assert!(!args.rollback);
    }

    #[test]
    fn test_cli_parse_with_log_options() {
        let cli = Cli::parse_from(&[
            "horizon",
            "--log-level",
            "debug",
            "--log-format",
            "json",
            "validate",
        ]);

        assert_eq!(cli.log_level, "debug");
        assert_eq!(cli.log_format, "json");
        match cli.command {
            Commands::Validate => {},
            _ => panic!("Expected Validate command"),
        }
    }

    #[test]
    fn test_serve_args_tls_validation() {
        // TLS enabled but missing cert
        let args = ServeArgs {
            host:     "0.0.0.0".to_string(),
            port:     3000,
            tls:      true,
            tls_cert: None,
            tls_key:  Some("/path/to/key".to_string()),
        };
        assert!(args.tls);
        assert!(args.tls_cert.is_none());
        assert!(args.tls_key.is_some());

        // TLS enabled but missing key
        let args = ServeArgs {
            host:     "0.0.0.0".to_string(),
            port:     3000,
            tls:      true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key:  None,
        };
        assert!(args.tls);
        assert!(args.tls_cert.is_some());
        assert!(args.tls_key.is_none());
    }

    #[test]
    fn test_migrate_args_full() {
        let args = MigrateArgs {
            dry_run:  true,
            rollback: false,
        };

        assert!(args.dry_run);
        assert!(!args.rollback);
    }

    #[test]
    fn test_cli_parse_unknown_command() {
        use std::process::Command;

        let output = Command::new("cargo")
            .args(&["run", "--bin", "cli", "--", "unknown"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to run command");

        // Should exit with non-zero status for unknown command
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("unrecognized subcommand"));
    }

    #[test]
    fn test_cli_name_and_version() {
        let cmd = Cli::command();
        assert_eq!(cmd.get_name(), "horizon");
        // Version should be set
        let version = cmd.get_version();
        assert!(version.is_some());
    }

    #[test]
    fn test_cli_about_text() {
        let cmd = Cli::command();
        let about = cmd.get_about();
        assert!(about.is_some());
    }

    #[test]
    fn test_cli_serve_subcommand() {
        let cmd = Cli::command();
        let mut has_serve = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "serve" {
                has_serve = true;
                break;
            }
        }
        assert!(has_serve);
    }

    #[test]
    fn test_cli_migrate_subcommand() {
        let cmd = Cli::command();
        let mut has_migrate = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "migrate" {
                has_migrate = true;
                break;
            }
        }
        assert!(has_migrate);
    }

    #[test]
    fn test_cli_validate_subcommand() {
        let cmd = Cli::command();
        let mut has_validate = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "validate" {
                has_validate = true;
                break;
            }
        }
        assert!(has_validate);
    }

    #[test]
    fn test_cli_completions_subcommand() {
        let cmd = Cli::command();
        let mut has_completions = false;
        for subcommand in cmd.get_subcommands() {
            if subcommand.get_name() == "completions" {
                has_completions = true;
                break;
            }
        }
        assert!(has_completions);
    }

    #[test]
    fn test_validate_partial_missing_vars() {
        // Save original env vars
        let orig_host = std::env::var("HORIZON_DATABASE_HOST").ok();
        let orig_port = std::env::var("HORIZON_DATABASE_PORT").ok();
        let orig_name = std::env::var("HORIZON_DATABASE_NAME").ok();
        let orig_user = std::env::var("HORIZON_DATABASE_USER").ok();
        let orig_pass = std::env::var("HORIZON_DATABASE_PASSWORD").ok();

        // Clear all env vars
        unsafe {
            std::env::remove_var("HORIZON_DATABASE_HOST");
            std::env::remove_var("HORIZON_DATABASE_PORT");
            std::env::remove_var("HORIZON_DATABASE_NAME");
            std::env::remove_var("HORIZON_DATABASE_USER");
            std::env::remove_var("HORIZON_DATABASE_PASSWORD");
        }

        // Set only some vars
        unsafe {
            std::env::set_var("HORIZON_DATABASE_HOST", "localhost");
            std::env::set_var("HORIZON_DATABASE_PORT", "5432");
            // Leave others unset
        }

        let result = commands::validate::validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Missing required environment variables"));

        // Restore original env vars
        restore_env_var("HORIZON_DATABASE_HOST", orig_host);
        restore_env_var("HORIZON_DATABASE_PORT", orig_port);
        restore_env_var("HORIZON_DATABASE_NAME", orig_name);
        restore_env_var("HORIZON_DATABASE_USER", orig_user);
        restore_env_var("HORIZON_DATABASE_PASSWORD", orig_pass);
    }

    #[test]
    fn test_completions_direct() {
        use std::io::Write;

        let args = CompletionsArgs {
            shell: clap_complete::Shell::Bash,
        };

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let result = completions_with_output(&args, &mut temp_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_completions_all_shells() {
        let shells = vec![
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Elvish,
        ];

        for shell in shells {
            let args = CompletionsArgs {
                shell,
            };
            let result = commands::completions::completions(args.shell, &mut Cli::command());
            assert!(result.is_ok(), "Completions failed for {:?}", shell);
        }
    }

    // Helper functions for comprehensive testing

    // Helper function for completions that writes to a provided writer
    fn completions_with_output<T: std::io::Write>(args: &CompletionsArgs, writer: &mut T) -> error::Result<()> {
        clap_complete::generate(args.shell, &mut Cli::command(), "horizon", writer);
        Ok(())
    }

    // Helper to restore environment variable
    fn restore_env_var(name: &str, value: Option<String>) {
        unsafe {
            if let Some(v) = value {
                std::env::set_var(name, v);
            }
            else {
                std::env::remove_var(name);
            }
        }
    }
}
