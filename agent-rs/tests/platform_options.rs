use openems_agent::app::validate_platform_options;
use openems_agent::config::AgentConfig;

#[test]
fn unsupported_system_features_are_refused_before_starting_listeners() {
    let mut config = AgentConfig::new("http://127.0.0.1:8013", "test-pc");
    for platform in ["linux", "macos"] {
        config.anti_bypass = true;
        assert!(validate_platform_options(&config, platform).is_err());
        config.anti_bypass = false;
        config.block_page_https = true;
        assert!(validate_platform_options(&config, platform).is_err());
        config.block_page_https = false;
    }
    config.dns_filter = true;
    assert!(validate_platform_options(&config, "macos").is_err());
    assert!(validate_platform_options(&config, "linux").is_ok());
    config.dns_port = 1053;
    assert!(validate_platform_options(&config, "macos").is_ok(), "a test listener does not claim system routing");
    config.anti_bypass = true;
    config.block_page_https = true;
    assert!(validate_platform_options(&config, "windows").is_ok());
}
