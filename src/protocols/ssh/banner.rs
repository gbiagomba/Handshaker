pub fn parse_banner(banner: &str) -> Option<&str> {
    if banner.starts_with("SSH-") {
        Some(banner)
    } else {
        None
    }
}
