//! Installer configuration updates preserve the existing device registration.

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::fsutil::atomic_write;
use std::path::Path;

/// Enable requested pages without replacing an existing endpoint identity or state.
pub fn configure_install(
    path: &Path,
    bootstrap: Option<AgentConfig>,
    enable_http: bool,
    enable_https: bool,
    enable_dns: bool,
    enable_anti_bypass: bool,
) -> Result<AgentConfig> {
    let original = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut config = if original.is_some() {
        AgentConfig::from_file(path)?
    } else {
        bootstrap
            .clone()
            .ok_or_else(|| AgentError::Config("fresh installation requires bootstrap configuration".into()))?
    };
    if original.is_some()
        && let Some(mut requested) = bootstrap
    {
        requested.validate()?;
        if requested.server != config.server {
            return Err(AgentError::Config("installation cannot change the registered server origin".into()));
        }
    }
    let changed = (enable_http || enable_https) && !config.block_page
        || enable_https && !config.block_page_https
        || enable_dns && !config.dns_filter
        || enable_anti_bypass && !config.anti_bypass;
    config.block_page |= enable_http || enable_https;
    config.block_page_https |= enable_https;
    config.dns_filter |= enable_dns;
    config.anti_bypass |= enable_anti_bypass;
    config.validate()?;
    match original {
        Some(bytes) if changed => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| AgentError::Config("configuration is not valid UTF-8".into()))?;
            let mut value: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
                .map_err(|_| AgentError::Config("configuration is not valid JSON".into()))?;
            value["block_page"] = config.block_page.into();
            value["block_page_https"] = config.block_page_https.into();
            // Untouched options stay absent so upgrades change only what was requested.
            if config.dns_filter {
                value["dns_filter"] = true.into();
            }
            if config.anti_bypass {
                value["anti_bypass"] = true.into();
            }
            let encoded = serde_json::to_vec_pretty(&value).map_err(|error| AgentError::Local(error.to_string()))?;
            atomic_write(path, &encoded, Some(&bytes), true)?;
        }
        Some(_) => {}
        None => config.write_file(path)?,
    }
    Ok(config)
}
