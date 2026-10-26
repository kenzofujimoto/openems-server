//! Privileged lifecycle helper used by systemd, kept separate from enrollment and policy APIs.
use clap::{Parser, Subcommand};
use openems_agent::config::{AgentConfig, default_config_path};
use openems_agent::error::Result;
use openems_agent::linux_support;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "openems-platform", about = "Linux lifecycle and owned configuration recovery")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    DnsPrepare {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    DnsRemove {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    PolicyRemove {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print dependency capabilities without changing the machine.
    Capabilities,
}

fn execute(command: Command) -> Result<()> {
    match command {
        Command::DnsPrepare { config } => {
            linux_support::dns_prepare(&AgentConfig::from_file(&config.unwrap_or_else(default_config_path))?)
        }
        Command::DnsRemove { config } => {
            linux_support::dns_remove(&AgentConfig::from_file(&config.unwrap_or_else(default_config_path))?.state_path)
        }
        Command::PolicyRemove { config } => linux_support::remove_policy(
            &AgentConfig::from_file(&config.unwrap_or_else(default_config_path))?.state_path,
        ),
        Command::Capabilities => {
            println!(
                "{}",
                serde_json::to_string(&linux_support::capability_tags()).expect("string list serialization")
            );
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
