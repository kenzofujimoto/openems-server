use clap::{Args, Parser, Subcommand};
use openems_agent::app;
use openems_agent::config::{AgentConfig, default_config_path};
use openems_agent::error::{AgentError, Result};
use openems_agent::hosts::{DEFAULT_HOSTS, clear_hosts};
use openems_agent::logging::stderr_logger;
use openems_agent::runtime::StopSignal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "openems-agent", version, about = "openems endpoint agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Synchronize, enforce and report once, then exit.
    RunOnce(RunArgs),
    /// Run in the foreground until interrupted.
    Run(RunArgs),
    /// Remove the managed block from the hosts file.
    CleanupHosts {
        #[arg(long)]
        hosts_file: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Entry point used by the Windows Service Control Manager.
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

#[derive(Args)]
struct RunArgs {
    /// agent.json to read instead of command-line options.
    #[arg(long, conflicts_with_all = ["server", "devid"])]
    config: Option<PathBuf>,
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    devid: Option<String>,
    #[arg(long, default_value = "Default")]
    vdom: String,
    #[arg(long)]
    hosts_file: Option<PathBuf>,
    #[arg(long)]
    state_path: Option<PathBuf>,
    #[arg(long, default_value_t = 15)]
    interval: u64,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    block_page: bool,
    #[arg(long, default_value_t = 80)]
    block_page_port: u16,
    #[arg(long)]
    allow_insecure_http: bool,
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn resolve(args: RunArgs) -> Result<AgentConfig> {
    if let Some(path) = args.config {
        return AgentConfig::from_file(&path);
    }
    let (Some(server), Some(devid)) = (args.server, args.devid) else {
        return Err(AgentError::Config("--server and --devid are required without --config".into()));
    };
    let mut config = AgentConfig::new(server, devid);
    config.vdom = args.vdom;
    config.hosts_path = args.hosts_file.unwrap_or(config.hosts_path);
    config.state_path = args.state_path.unwrap_or(config.state_path);
    config.interval = args.interval;
    config.dry_run = args.dry_run;
    config.block_page = args.block_page;
    config.block_page_port = args.block_page_port;
    config.allow_insecure_http = args.allow_insecure_http;
    config.invitation = non_empty_env("OPENEMS_INVITATION");
    config.device_token = non_empty_env("OPENEMS_DEVICE_TOKEN");
    config.validate()?;
    Ok(config)
}

fn execute(command: Command) -> Result<ExitCode> {
    match command {
        Command::RunOnce(args) => {
            let enforced = app::run_once(resolve(args)?, stderr_logger())?;
            Ok(if enforced { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        Command::Run(args) => {
            app::run(resolve(args)?, stderr_logger(), Arc::new(StopSignal::default()))?;
            Ok(ExitCode::SUCCESS)
        }
        Command::CleanupHosts { hosts_file, config } => {
            let path = match (hosts_file, config) {
                (Some(path), _) => path,
                (None, Some(config)) => AgentConfig::from_file(&config)?.hosts_path,
                (None, None) if default_config_path().exists() => {
                    AgentConfig::from_file(&default_config_path())?.hosts_path
                }
                (None, None) => PathBuf::from(DEFAULT_HOSTS),
            };
            clear_hosts(&path)?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::Service => {
            openems_agent::service::run_dispatcher()
                .map_err(|error| AgentError::Local(format!("service dispatcher failed: {error}")))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse().command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
