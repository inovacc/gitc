//! The AWS rule has TWO independent suppressors, and both are deliberate:
//!
//! 1. `filter = entropy(secret) <= 3.0 || matchesAny(secret, [`.+EXAMPLE$`])` —
//!    so the canonical `AKIAIOSFODNN7EXAMPLE` is never a finding.
//! 2. `components = [{ id = "aws-secret-access-key", within = "5L" }]` — a
//!    REQUIRED component, so a lone access-key id is dropped even when it is a
//!    perfectly valid, high-entropy, non-EXAMPLE id.
//!
//! Both directions are asserted so a rule edit that guts either one is caught.
//! Verified against the Go engine, which reports nothing for a lone key and one
//! component set for the pair.

/// Generated at runtime; only the SHAPE matters. 
/// `EXAMPLE_KEY` below stays literal on purpose — it is the published AWS
/// documentation key that the allowlist exists to recognise.
fn real_key() -> String {
    // Reconstructed byte for byte, NOT generated: whether the engine fires
    // depends on this exact string's entropy, so a fresh value would silently
    // change what these tests prove.
    testkeys::reveal("232e3d353f4134345639277d3f2824225f264b37")
}
const EXAMPLE_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn det() -> detect::Detector {
    detect::Detector::with_default_config().expect("catalogue loads")
}

#[test]
fn aws_pair_fires_and_attaches_the_component() {
    let content =
        format!("aws_access_key_id = \"{}\"\naws_secret_access_key = \"{SECRET_KEY}\"\n", real_key());
    let findings = det().detect_string(&content);
    let primary = findings
        .iter()
        .find(|f| f.rule_id == "aws-access-token")
        .unwrap_or_else(|| {
            panic!(
                "expected aws-access-token, got {:?}",
                findings.iter().map(|f| f.rule_id.clone()).collect::<Vec<_>>()
            )
        });
    eprintln!(
        "HIT rule={} line={} masked={} sets={}",
        primary.rule_id,
        primary.start_line,
        detect::masked(primary),
        primary.component_sets.len()
    );
    assert_eq!(primary.component_sets.len(), 1);
}

/// Suppressor 2: the required component. A lone id is NOT a finding.
#[test]
fn lone_aws_key_is_suppressed_by_the_required_component() {
    let findings = det().detect_string(&format!("aws_access_key_id = \"{}\"\n", real_key()));
    assert!(
        !findings.iter().any(|f| f.rule_id == "aws-access-token"),
        "a lone AWS id must not be reported"
    );
}

/// Suppressor 1: the `.+EXAMPLE$` filter — even correctly PAIRED, the canonical
/// example key is suppressed.
#[test]
fn example_key_is_allowlisted_even_when_paired() {
    let content =
        format!("aws_access_key_id = \"{EXAMPLE_KEY}\"\naws_secret_access_key = \"{SECRET_KEY}\"\n");
    let findings = det().detect_string(&content);
    assert!(
        !findings.iter().any(|f| f.rule_id == "aws-access-token"),
        "the .+EXAMPLE$ filter should suppress the canonical example key"
    );
}




