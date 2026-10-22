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
    let block_page =
        if config.block_page { Some(blockpage::start(config.block_page_port, Arc::clone(&stop))?) } else { None };
    log(&format!("openems-agent {} started for {}", env!("CARGO_PKG_VERSION"), config.devid));
    let result = Runtime::new(config, Arc::clone(&log), Arc::clone(&stop)).map(Arc::new).and_then(Runtime::run);
    stop.stop();
    if let Some(worker) = block_page {
        let _ = worker.join();
    }
    log("openems-agent stopped");
    result
}
