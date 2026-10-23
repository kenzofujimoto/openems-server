//! Entry points shared by the command line and the Windows service.

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::runtime::{Logger, Runtime, StopSignal};
use crate::{blockpage, dns};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::thread::JoinHandle;

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

/// Run until `stop` is signalled; listeners live as long as the loop.
pub fn run(config: AgentConfig, log: Logger, stop: Arc<StopSignal>) -> Result<()> {
    let runtime = Arc::new(Runtime::new(config.clone(), Arc::clone(&log), Arc::clone(&stop))?);
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
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
        match blockpage::start(config.block_page_port, Arc::clone(&stop)) {
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
        // IPv6 loopback is optional: hosts with IPv6 disabled still resolve through 127.0.0.1.
        match resolver(SocketAddr::from((Ipv6Addr::LOCALHOST, config.dns_port))) {
            Ok((_, worker)) => workers.push(worker),
            Err(error) => log(&format!("DNS resolver not listening on [::1]: {error}")),
        }
    }
    log(&format!("openems-agent {} started for {}", env!("CARGO_PKG_VERSION"), config.devid));
    let result = runtime.run();
    stop.stop();
    for worker in workers {
        let _ = worker.join();
    }
    log("openems-agent stopped");
    result
}
