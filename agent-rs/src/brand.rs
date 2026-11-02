//! Build-time identity shown to people on the machine: tray, local block page and service text.
//! The default is OpenEMS; `--features rsm-brand` builds the RSM Brasil edition with its original wording.

#[cfg(not(feature = "rsm-brand"))]
mod edition {
    pub const PRODUCT: &str = "OpenEMS";
    pub const SERVICE_DESCRIPTION: &str =
        "Applies OpenEMS endpoint policies and reports their status to the management server.";
    pub const LOGO_ALT: &str = "OpenEMS";
    pub const LOGO_MIME: &str = "image/svg+xml";
    pub const LOGO: &[u8] = include_bytes!("../assets/openems-logo.svg");
    pub const FOOTER: &str =
        "OpenEMS &middot; <strong>Pol&iacute;tica de seguran&ccedil;a da sua organiza&ccedil;&atilde;o</strong>";
    pub const THEME: &str = ":root { --blue:#4f46e5; --blue-dark:#3730a3; --green:#22d3ee; --gray:#7a849c;\n    --ink:#111827; --text:#46506a; --line:#e3e7ef; --canvas:#f4f6fa; --badge:#eef0ff;\n    --font:\"IBM Plex Sans\",\"Segoe UI\",\"Helvetica Neue\",Arial,sans-serif; }";
}

#[cfg(feature = "rsm-brand")]
mod edition {
    pub const PRODUCT: &str = "RSM Endpoint";
    pub const SERVICE_DESCRIPTION: &str =
        "Applies RSM endpoint policies and reports their status to the management server.";
    pub const LOGO_ALT: &str = "RSM";
    pub const LOGO_MIME: &str = "image/png";
    pub const LOGO: &[u8] = include_bytes!("../assets/rsm-logo.png");
    pub const FOOTER: &str = "RSM Brasil &middot; <strong>O poder de ser compreendido</strong>";
    pub const THEME: &str = ":root { --blue:#009cde; --blue-dark:#006e9d; --green:#3f9c35; --gray:#888b8d;\n    --ink:#1f2428; --text:#515356; --line:#e7e9ec; --canvas:#f6f7f9; --badge:#e5f5fc;\n    --font:\"Prelo\",\"Noto Sans\",\"Segoe UI\",\"Helvetica Neue\",Arial,sans-serif; }";
}

pub use edition::*;
