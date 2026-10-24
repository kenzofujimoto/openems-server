//! Entry points shared by the command line and the Windows service.

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::runtime::{Logger, Runtime, StopSignal};
use crate::{blockpage, dns, nrpt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::thread::JoinHandle;
#[cfg(windows)]
use std::time::Duration;

/// One synchronize-enforce-report cycle. Ok(false) means enforcement failed.
pub fn run_once(config: AgentConfig, log: Logger) -> Result<bool> {
    let runtime = Runtime::new(config, log, Arc::new(StopSignal::default()))?;
    Ok(runtime.cycle(0.0))
}

/// Stop and join every listener already started when a later one fails.
fn abort(stop: &StopSignal, workers: Vec<JoinHandle<()>>, error: AgentError) -> AgentError {
    stop.stop();
    for worker in workers {
        let _ = worker.join();
    }
    error
}

/// Apply browser DoH policies now, then re-check every minute so a rewrite by anyone is undone.
#[cfg(windows)]
fn guard_browser_policies(config: &AgentConfig, log: &Logger, stop: &Arc<StopSignal>) -> Result<JoinHandle<()>> {
    use crate::browser_policy::{WindowsRegistry, ensure};
    let originals = config.state_path.with_file_name("browser-policies.json");
    let report = |log: &Logger, changed: Vec<String>| {
        if !changed.is_empty() {
            log(&format!("browser policy applied: {}", changed.join(", ")));
        }
    };
    report(log, ensure(&mut WindowsRegistry, &originals)?);
    let (log, stop) = (Arc::clone(log), Arc::clone(stop));
    Ok(std::thread::Builder::new().name("openems-browser-policy".into()).spawn(move || {
        while !stop.wait(Duration::from_secs(60)) {
            match ensure(&mut WindowsRegistry, &originals) {
                Ok(changed) => report(&log, changed),
                Err(error) => log(&format!("browser policy check failed ({})", error.kind())),
            }
        }
    })?)
}

/// Run until `stop` is signalled; listeners live as long as the loop.
pub fn run(config: AgentConfig, log: Logger, stop: Arc<StopSignal>) -> Result<()> {
    let runtime = Arc::new(Runtime::new(config.clone(), Arc::clone(&log), Arc::clone(&stop))?);
    runtime.blocked_domains.set_doh_blocking(config.dns_filter && config.anti_bypass);
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut routed = false;
    #[cfg(windows)]
    let mut filtered = false;
    // Before any listener or NRPT change, so a failure here leaves nothing to undo.
    #[cfg(windows)]
    if config.anti_bypass {
        workers.push(guard_browser_policies(&config, &log, &stop)?);
    }
    if config.block_page_https {
        let started = crate::authority::Authority::load_or_create(&config.authority_path).and_then(|authority| {
            crate::https_blockpage::start(
                config.block_page_https_port,
                authority,
                Arc::clone(&runtime.blocked_domains),
                Arc::clone(&stop),
            )
        });
        match started {
            Ok((_, worker)) => workers.push(worker),
            Err(error) => return Err(abort(&stop, workers, error)),
        }
    }
    if config.block_page {
        match blockpage::start(config.block_page_port, Arc::clone(&runtime.blocked_domains), Arc::clone(&stop)) {
            Ok(worker) => workers.push(worker),
            Err(error) => return Err(abort(&stop, workers, error)),
        }
    }
    if config.dns_filter {
        let upstreams: Arc<dyn dns::Upstreams> = Arc::new(dns::AdapterUpstreams::default());
        let resolver = |address: SocketAddr| {
            dns::start(
                &[address],
                Arc::clone(&runtime.blocked_domains),
                config.block_page,
                Arc::clone(&upstreams),
                Arc::clone(&stop),
            )
        };
        match resolver(SocketAddr::from((Ipv4Addr::LOCALHOST, config.dns_port))) {
            Ok((_, worker)) => workers.push(worker),
            Err(error) => return Err(abort(&stop, workers, error)),
        }
        let mut servers = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        // IPv6 loopback is optional: hosts with IPv6 disabled still resolve through 127.0.0.1.
        match resolver(SocketAddr::from((Ipv6Addr::LOCALHOST, config.dns_port))) {
            Ok((_, worker)) => {
                workers.push(worker);
                servers.push(IpAddr::V6(Ipv6Addr::LOCALHOST));
            }
            Err(error) => log(&format!("DNS resolver not listening on [::1]: {error}")),
        }
        // NRPT cannot name a port, so only the standard port routes system DNS; other ports are for tests.
        if cfg!(windows) && config.dns_port == 53 {
            if let Err(error) = nrpt::install(&servers) {
                return Err(abort(&stop, workers, error));
            }
            routed = true;
            log("system DNS routed to the local resolver");
            #[cfg(windows)]
            if config.anti_bypass {
                if let Err(error) = crate::wfp::install(crate::doh::addresses()) {
                    // Hand DNS back before failing so the machine is not left without a resolver.
                    if let Err(cleanup) = nrpt::remove() {
                        log(&format!("NRPT rule not removed after filter failure: {cleanup}"));
                    }
                    return Err(abort(&stop, workers, error));
                }
                filtered = true;
                log("direct DNS, DoT and known DoH endpoints blocked for other programs");
            }
        }
    }
    log(&format!("openems-agent {} started for {}", env!("CARGO_PKG_VERSION"), config.devid));
    let result = runtime.run();
    // Graceful stop (including upgrade and shutdown) hands DNS back; a crash never reaches here.
    // Filters go first: without the rule, blocked port 53 would leave other programs without DNS.
    #[cfg(windows)]
    if filtered && let Err(error) = crate::wfp::remove() {
        log(&format!("anti-bypass filters not removed: {error}"));
    }
    if routed && let Err(error) = nrpt::remove() {
        log(&format!("NRPT rule not removed: {error}"));
    }
    stop.stop();
    for worker in workers {
        let _ = worker.join();
    }
    log("openems-agent stopped");
    result
}
