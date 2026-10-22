//! Explicit trust lifecycle. Service startup never invokes installation.
use crate::config::{AgentConfig, default_config_path};
use crate::error::{AgentError, Result};
use std::path::Path;

pub fn install(config: Option<&Path>) -> Result<()> {
    let config = AgentConfig::from_file(config.unwrap_or(&default_config_path()))?;
    if !config.block_page_https || !config.block_page {
        return Err(AgentError::Config("HTTPS block page must be enabled explicitly".into()));
    }
    #[cfg(windows)]
    {
        let authority = crate::authority::Authority::load_or_create(&config.authority_path)?;
        authority.install_with(&mut crate::authority::WindowsTrustStore, || Ok(()))
    }
    #[cfg(not(windows))]
    Err(AgentError::Local("machine trust lifecycle is supported only on Windows".into()))
}

pub fn remove(config: Option<&Path>) -> Result<()> {
    let path = config.map_or_else(default_config_path, Path::to_path_buf);
    if !path.try_exists()? {
        return Ok(());
    }
    let config = AgentConfig::from_file(&path)?;
    if !config.authority_path.try_exists()? {
        return Ok(());
    }
    #[cfg(windows)]
    {
        crate::authority::Authority::remove_managed_trust(
            &config.authority_path,
            &mut crate::authority::WindowsTrustStore,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Err(AgentError::Local("machine trust lifecycle is supported only on Windows".into()))
    }
}
