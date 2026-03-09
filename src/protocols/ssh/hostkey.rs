pub fn key_type_from_name(name: &str) -> &str {
    if name.contains("rsa") {
        "rsa"
    } else if name.contains("ecdsa") {
        "ecdsa"
    } else {
        "unknown"
    }
}
