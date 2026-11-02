//! Build-time identity of the agent, mirroring the panel's `VITE_BRAND` (web/src/lib/brand.ts).
//!
//! The default build is the OpenEMS edition; `cargo build --features rsm` produces the RSM Brasil edition,
//! whose wording is kept byte-for-byte. Python mirror: agent/brand.py. Only user-visible text and the block
//! page change between editions; policy behavior never does.

/// Everything user-visible that differs between editions.
#[derive(Debug, PartialEq, Eq)]
pub struct Brand {
    /// `openems` or `rsm`, as in `--version` and `OPENEMS_AGENT_EDITION` for the Python agent.
    pub id: &'static str,
    /// Tray title and tooltip prefix.
    pub product: &'static str,
    /// Windows service description (same text as the MSI's ServiceInstall).
    pub service_description: &'static str,
    /// Block page template with `{host}`, `{category}` and optionally `{logo}` placeholders.
    pub block_page: &'static str,
    /// PNG embedded as `{logo}`, when the template uses one.
    pub logo: &'static [u8],
}

pub const OPENEMS: Brand = Brand {
    id: "openems",
    product: "OpenEMS Endpoint",
    service_description: "Applies OpenEMS endpoint policies and reports their status to the management server.",
    block_page: include_str!("blockpage-openems.html"),
    logo: &[],
};

pub const RSM: Brand = Brand {
    id: "rsm",
    product: "RSM Endpoint",
    service_description: "Applies RSM endpoint policies and reports their status to the management server.",
    block_page: include_str!("blockpage-rsm.html"),
    logo: include_bytes!("../assets/rsm-logo.png"),
};

/// The edition this binary was built as.
#[cfg(not(feature = "rsm"))]
pub const BRAND: &Brand = &OPENEMS;
#[cfg(feature = "rsm")]
pub const BRAND: &Brand = &RSM;

/// `--version` text for both binaries, e.g. `0.1.0 (openems)`, so tests and installers can tell editions apart.
#[cfg(not(feature = "rsm"))]
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (openems)");
#[cfg(feature = "rsm")]
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (rsm)");
