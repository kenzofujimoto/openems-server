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
    /// Write a protected agent.json for the service.
    Configure(ConfigureArgs),
    /// Prepare a reversible installer transaction (Windows SYSTEM).
    InstallerPrepare(InstallerArgs),
    /// Restore the state captured by an installer transaction.
    InstallerRollback {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Remove private snapshots after a successful installer transaction.
    InstallerCommit {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Install this machine's HTTPS block-page root explicitly (Windows SYSTEM).
    InstallBlockPageTrust {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Remove only this installation's HTTPS root and protected authority file.
    RemoveBlockPageTrust {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Register the agent as an auto-start Windows service with failure recovery.
    #[cfg(windows)]
    InstallService {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Start the service right after registering it.
        #[arg(long)]
        start: bool,
    },
    /// Stop and remove the Windows service and its hosts block.
    #[cfg(windows)]
    UninstallService {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Set restart-on-failure actions on the installed service (used by the MSI).
    #[cfg(windows)]
    #[command(hide = true)]
    ConfigureRecovery,
    /// Entry point used by the Windows Service Control Manager.
    #[cfg(windows)]
    #[command(hide = true)]
    Service {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Args)]
struct InstallerArgs {
    #[arg(long)]
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
    invitation: Option<String>,
    #[arg(long)]
    block_page: bool,
    #[arg(long)]
    block_page_https: bool,
    #[arg(long)]
    dns_filter: bool,
    #[arg(long)]
    anti_bypass: bool,
    #[arg(long, conflicts_with_all = ["server", "devid", "hosts_file", "invitation", "block_page", "block_page_https", "dns_filter", "anti_bypass"])]
    remove: bool,
}

#[derive(Args)]
struct ConfigureArgs {
    /// Where to write agent.json (defaults to the service location).
    #[arg(long)]
    config_path: Option<PathBuf>,
    #[arg(long)]
    server: String,
    /// Defaults to the computer name.
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
    block_page: bool,
    #[arg(long, default_value_t = 80)]
    block_page_port: u16,
    #[arg(long)]
    block_page_https: bool,
    #[arg(long, default_value_t = 443)]
    block_page_https_port: u16,
    #[arg(long)]
    authority_path: Option<PathBuf>,
    /// Serve DNS on loopback instead of writing the hosts file.
    #[arg(long)]
    dns_filter: bool,
    #[arg(long, default_value_t = 53)]
    dns_port: u16,
    /// Block direct DNS, DoT and known DoH endpoints; requires --dns-filter.
    #[arg(long)]
    anti_bypass: bool,
    #[arg(long)]
    allow_insecure_http: bool,
    /// One-time enrollment invitation; OPENEMS_INVITATION is used when omitted.
    #[arg(long)]
    invitation: Option<String>,
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
    block_page_https: bool,
    #[arg(long, default_value_t = 443)]
    block_page_https_port: u16,
    #[arg(long)]
    authority_path: Option<PathBuf>,
    /// Serve DNS on loopback instead of writing the hosts file.
    #[arg(long)]
    dns_filter: bool,
    #[arg(long, default_value_t = 53)]
    dns_port: u16,
    /// Block direct DNS, DoT and known DoH endpoints; requires --dns-filter.
    #[arg(long)]
    anti_bypass: bool,
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
    config.block_page_https = args.block_page_https;
    config.block_page_https_port = args.block_page_https_port;
    config.authority_path =
        args.authority_path.unwrap_or_else(|| config.state_path.with_file_name("https").join("authority.json"));
    config.dns_filter = args.dns_filter;
    config.dns_port = args.dns_port;
    config.anti_bypass = args.anti_bypass;
    config.allow_insecure_http = args.allow_insecure_http;
    config.invitation = non_empty_env("OPENEMS_INVITATION");
    config.device_token = non_empty_env("OPENEMS_DEVICE_TOKEN");
    config.validate()?;
    Ok(config)
}

fn configure(args: ConfigureArgs) -> Result<PathBuf> {
    let path = args.config_path.unwrap_or_else(default_config_path);
    let devid = args.devid.unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
    let mut config = AgentConfig::new(args.server, devid);
    config.vdom = args.vdom;
    config.hosts_path = args.hosts_file.unwrap_or(config.hosts_path);
    config.state_path = args.state_path.unwrap_or_else(|| path.with_file_name("state.json"));
    config.interval = args.interval;
    config.block_page = args.block_page;
    config.block_page_port = args.block_page_port;
    config.block_page_https = args.block_page_https;
    config.block_page_https_port = args.block_page_https_port;
    config.authority_path = args.authority_path.unwrap_or_else(|| path.with_file_name("https").join("authority.json"));
    config.dns_filter = args.dns_filter;
    config.dns_port = args.dns_port;
    config.anti_bypass = args.anti_bypass;
    config.allow_insecure_http = args.allow_insecure_http;
    // msiexec passes an empty property when no invitation was given.
    config.invitation =
        args.invitation.filter(|value| !value.is_empty()).or_else(|| non_empty_env("OPENEMS_INVITATION"));
    config.validate()?;
    config.write_file(&path)?;
    Ok(path)
}

fn execute(command: Command) -> Result<ExitCode> {
    match command {
        Command::RunOnce(args) => {
            let config = resolve(args)?;
            if config.block_page_https {
                return Err(AgentError::Config("HTTPS block page requires continuous run".into()));
            }
            if config.dns_filter {
                return Err(AgentError::Config("DNS filter requires continuous run".into()));
            }
            let enforced = app::run_once(config, stderr_logger())?;
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
        Command::Configure(args) => {
            println!("configuration written to {}", configure(args)?.display());
            Ok(ExitCode::SUCCESS)
        }
        Command::InstallerPrepare(args) => {
            let path = args.config.unwrap_or_else(default_config_path);
            if args.remove {
                openems_agent::installer::prepare_removal(&path)?;
            } else {
                let bootstrap = args.server.filter(|server| !server.is_empty()).map(|server| {
                    let devid = args.devid.unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
                    let mut config = AgentConfig::new(server, devid);
                    config.vdom = args.vdom;
                    config.hosts_path = args.hosts_file.unwrap_or(config.hosts_path);
                    config.state_path = path.with_file_name("state.json");
                    config.authority_path = path.with_file_name("https").join("authority.json");
                    config.invitation = args
                        .invitation
                        .filter(|value| !value.is_empty())
                        .or_else(|| non_empty_env("OPENEMS_INVITATION"));
                    config
                });
                openems_agent::installer::prepare(
                    &path,
                    bootstrap,
                    args.block_page,
                    args.block_page_https,
                    args.dns_filter,
                    args.anti_bypass,
                )?;
            }
            println!("installer transaction prepared");
            Ok(ExitCode::SUCCESS)
        }
        Command::InstallerRollback { config } => {
            openems_agent::installer::rollback(&config.unwrap_or_else(default_config_path))?;
            println!("installer transaction restored");
            Ok(ExitCode::SUCCESS)
        }
        Command::InstallerCommit { config } => {
            openems_agent::installer::commit(&config.unwrap_or_else(default_config_path))?;
            println!("installer transaction committed");
            Ok(ExitCode::SUCCESS)
        }
        Command::InstallBlockPageTrust { config } => {
            openems_agent::trust::install(config.as_deref())?;
            println!("local HTTPS root installed");
            Ok(ExitCode::SUCCESS)
        }
        Command::RemoveBlockPageTrust { config } => {
            openems_agent::trust::remove(config.as_deref())?;
            println!("local HTTPS root removed");
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::InstallService { config, start } => {
            openems_agent::service::install(config, start)?;
            println!("service {} installed", openems_agent::service::SERVICE_NAME);
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::UninstallService { config } => {
            openems_agent::service::uninstall(config)?;
            println!("service {} removed; its hosts block was cleared", openems_agent::service::SERVICE_NAME);
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::ConfigureRecovery => {
            openems_agent::service::configure_recovery()?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::Service { config } => {
            openems_agent::service::run_dispatcher(config)?;
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
