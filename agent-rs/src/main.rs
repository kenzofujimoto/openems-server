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
    /// Print a read-only snapshot of applications and USB devices.
    Inventory {
        #[arg(long)]
        state_path: Option<PathBuf>,
    },
    /// Validate and explain controls using supplied fixtures, without changing the machine.
    ControlsPlan {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        inventory: Option<PathBuf>,
    },
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
    /// Stop and remove the Windows service and its hosts block (SYSTEM; needs a code once armed).
    #[cfg(windows)]
    UninstallService {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        uninstall_code: Option<String>,
    },
    /// Remove the service and every protection after a forced MSI removal (SYSTEM; needs a code once armed).
    #[cfg(windows)]
    Cleanup {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        uninstall_code: Option<String>,
    },
    /// Set restart-on-failure actions and permissions on the installed service (used by the MSI).
    #[cfg(windows)]
    #[command(hide = true)]
    ConfigureRecovery,
    /// Start the service again if it was disabled or stopped (run by the SYSTEM scheduled task).
    #[cfg(windows)]
    #[command(hide = true)]
    Watchdog,
    /// Generate uninstall codes without the server, from the master key and the machine's client_id.
    /// The key is read from a file or standard input ("-"), never from the command line.
    UninstallCode {
        #[arg(long, value_name = "PATH")]
        master_key_file: String,
        #[arg(long)]
        client_id: String,
        #[arg(long, default_value_t = 1)]
        counter: u64,
        #[arg(long, default_value_t = 1)]
        count: u64,
    },
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
    /// One-time code from the panel or the offline generator; msiexec passes UNINSTALLCODE here.
    #[arg(long)]
    uninstall_code: Option<String>,
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

/// The uninstall master key from a file or standard input; errors never include the path or the contents.
fn read_master_key(source: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut data = Vec::new();
    let read = if source == "-" {
        std::io::stdin().read_to_end(&mut data).map(|_| ())
    } else {
        std::fs::File::open(source).and_then(|mut file| file.read_to_end(&mut data)).map(|_| ())
    };
    read.map_err(|_| AgentError::Config("could not read the master key file".into()))?;
    let text =
        String::from_utf8(data).map_err(|_| AgentError::Config("the master key file must be UTF-8 text".into()))?;
    openems_agent::uninstall::master_key_from_text(&text)
}

fn execute(command: Command) -> Result<ExitCode> {
    match command {
        Command::Inventory { state_path } => {
            use openems_agent::controls::Backend;
            let state = state_path.unwrap_or_else(|| openems_agent::config::data_dir().join("state.json"));
            let inventory = openems_agent::controls::Machine.inventory(&state)?;
            println!(
                "{}",
                serde_json::to_string(&inventory)
                    .map_err(|_| AgentError::Local("cannot serialize inventory".into()))?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::ControlsPlan { policy, inventory } => {
            let read = |path: &std::path::Path| -> Result<serde_json::Value> {
                let metadata = std::fs::metadata(path)?;
                if metadata.len() > 2 * 1024 * 1024 {
                    return Err(AgentError::Config("planning input exceeds 2 MiB".into()));
                }
                let text = openems_agent::fsutil::read_text_without_bom(path)?;
                serde_json::from_str(&text).map_err(|_| AgentError::Config("planning input must be valid JSON".into()))
            };
            let body = read(&policy)?;
            let inventory = inventory.as_deref().map(read).transpose()?;
            let result = openems_agent::controls::plan(&body, inventory.as_ref())?;
            println!(
                "{}",
                serde_json::to_string(&result)
                    .map_err(|_| AgentError::Local("cannot serialize control plan".into()))?
            );
            Ok(ExitCode::SUCCESS)
        }
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
            // clap's `requires` counts the false default of --remove as present, so check here.
            if args.uninstall_code.is_some() && !args.remove {
                return Err(AgentError::Config("--uninstall-code is only valid with --remove".into()));
            }
            if args.remove {
                let code = args.uninstall_code.filter(|code| !code.is_empty());
                openems_agent::installer::prepare_removal(&path, code.as_deref())?;
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
        Command::UninstallService { config, uninstall_code } => {
            openems_agent::service::uninstall(config, uninstall_code.as_deref())?;
            println!("service {} removed; its hosts block was cleared", openems_agent::service::SERVICE_NAME);
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::Cleanup { config, uninstall_code } => {
            openems_agent::installer::cleanup(&config.unwrap_or_else(default_config_path), uninstall_code.as_deref())?;
            println!("agent service and protections removed");
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::ConfigureRecovery => {
            openems_agent::service::configure_recovery()?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::Watchdog => {
            openems_agent::service::run_watchdog()?;
            Ok(ExitCode::SUCCESS)
        }
        Command::UninstallCode { master_key_file, client_id, counter, count } => {
            if client_id.trim().is_empty() {
                return Err(AgentError::Config("--client-id must not be empty".into()));
            }
            let codes = openems_agent::uninstall::offline_codes(
                &read_master_key(&master_key_file)?,
                &client_id,
                counter,
                count,
            )?;
            if let [(_, code)] = codes.as_slice() {
                println!("{code}");
            } else {
                let width = codes.last().map_or(1, |(counter, _)| counter.to_string().len());
                for (counter, code) in &codes {
                    println!("{counter:>width$}  {code}");
                }
            }
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
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // Never echo uninstall-code arguments: a key typed on the command line would end up in the error.
        Err(error)
            if std::env::args().nth(1).as_deref() == Some("uninstall-code")
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
        {
            eprintln!("error: invalid arguments (the master key is read only through --master-key-file)");
            return ExitCode::from(2);
        }
        Err(error) => error.exit(),
    };
    match execute(cli.command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
