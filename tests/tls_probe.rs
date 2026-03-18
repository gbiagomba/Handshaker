/// Integration tests for TLS probe fault-tolerance and posture output.
///
/// These tests do NOT require network access: they verify that the module
/// return types are correct and that the probe handles unreachable hosts
/// gracefully (returning Ok rather than a "scan error").
use handshaker::models::{Target};
use handshaker::protocols::tls::{ciphers, versions, certs, alpn, scenarios};

fn unreachable_target() -> Target {
    Target {
        raw: "127.0.0.1:9".to_string(),
        host: "127.0.0.1".to_string(),
        port: 9, // discard port — guaranteed to refuse connections
        scheme: Some("https".to_string()),
    }
}

/// Probing an unreachable host must return Ok (not a scan error).
/// This covers the core bug: `?` propagation that turned expected
/// cipher-not-supported failures into fatal "scan error" findings.
#[tokio::test]
async fn cipher_check_on_unreachable_host_returns_ok() {
    let target = unreachable_target();
    let result = ciphers::check(&target).await;
    assert!(
        result.is_ok(),
        "cipher check on unreachable host must not propagate error: {:?}",
        result.err()
    );
    let (findings, categories) = result.unwrap();
    // When the initial connection is refused, we short-circuit: no findings,
    // empty category list (avoids false-positive "no AEAD" etc.).
    assert!(
        findings.is_empty(),
        "expected no findings for unreachable host (initial connect refused), got: {findings:?}"
    );
    assert!(
        categories.is_empty(),
        "expected empty categories for unreachable host"
    );
}

#[tokio::test]
async fn versions_check_on_unreachable_host_returns_ok() {
    let target = unreachable_target();
    let result = versions::check(&target).await;
    assert!(
        result.is_ok(),
        "versions check on unreachable host must not propagate error: {:?}",
        result.err()
    );
    let (_findings, accepted, rejected) = result.unwrap();
    // All five versions end up in "rejected" since no connection succeeds.
    assert!(accepted.is_empty(), "no versions should be accepted on unreachable host");
    assert!(!rejected.is_empty(), "all versions should be rejected on unreachable host");
    // The module may correctly emit TLS1.2/1.3 "not supported" findings even on
    // connection failure — that is expected and acceptable behavior; we only
    // verify that the call returns Ok and the posture data is sane.
}

#[tokio::test]
async fn certs_check_on_unreachable_host_returns_ok() {
    let target = unreachable_target();
    let result = certs::check(&target).await;
    assert!(
        result.is_ok(),
        "certs check on unreachable host must not propagate error: {:?}",
        result.err()
    );
    let (findings, cert_summary) = result.unwrap();
    assert!(findings.is_empty());
    assert!(cert_summary.is_none(), "no cert summary for unreachable host");
}

#[tokio::test]
async fn alpn_check_on_unreachable_host_returns_ok() {
    let target = unreachable_target();
    let result = alpn::check(&target).await;
    assert!(
        result.is_ok(),
        "alpn check on unreachable host must not propagate error: {:?}",
        result.err()
    );
    let (findings, protos) = result.unwrap();
    assert!(findings.is_empty());
    assert!(protos.is_empty(), "no ALPN protocols for unreachable host");
}

#[tokio::test]
async fn scenarios_check_on_unreachable_host_returns_ok() {
    let target = unreachable_target();
    let result = scenarios::check(&target).await;
    assert!(
        result.is_ok(),
        "scenarios check on unreachable host must not propagate error: {:?}",
        result.err()
    );
    let (findings, fallback_scsv, _renegotiation, _compression) = result.unwrap();
    assert!(findings.is_empty());
    // Fallback SCSV is None when TLS 1.0 is not supported.
    assert!(
        fallback_scsv.is_none(),
        "fallback_scsv should be None when TLS 1.0 not supported"
    );
}
