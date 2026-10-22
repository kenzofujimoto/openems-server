//! Entry points shared by the command line and the Windows service.

use crate::blockpage;
use crate::config::AgentConfig;
use crate::error::Result;
use crate::runtime::{Logger, Runtime, StopSignal};
use std::sync::Arc;

/// One synchronize-enforce-report cycle. Ok(false) means enforcement failed.
pub fn run_once(config: AgentConfig, log: Logger) -> Result<bool> {
    let runtime = Runtime::new(config, log, Arc::new(StopSignal::default()))?;
    Ok(runtime.cycle(0.0))
}

/// Run until `stop` is signalled; the block page lives as long as the loop.
pub fn run(config: AgentConfig, log: Logger, stop: Arc<StopSignal>) -> Result<()> {
    let runtime = Arc::new(Runtime::new(config.clone(), Arc::clone(&log), Arc::clone(&stop))?);
    let https_page = if config.block_page_https {
        let authority = crate::authority::Authority::load_or_create(&config.authority_path)?;
        Some(
            crate::https_blockpage::start(
                config.block_page_https_port,
                authority,
                Arc::clone(&runtime.blocked_domains),
                Arc::clone(&stop),
            )?
            .1,
        )
    } else {
        None
    };
    let block_page = if config.block_page {
        match blockpage::start(config.block_page_port, Arc::clone(&stop)) {
            Ok(worker) => Some(worker),
            Err(error) => {
                stop.stop();
                if let Some(worker) = https_page {
                    let _ = worker.join();
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    log(&format!("openems-agent {} started for {}", env!("CARGO_PKG_VERSION"), config.devid));
    let result = runtime.run();
    stop.stop();
    if let Some(worker) = block_page {
        let _ = worker.join();
    }
    if let Some(worker) = https_page {
        let _ = worker.join();
    }
    log("openems-agent stopped");
    result
}
