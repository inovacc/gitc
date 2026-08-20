//! The grammar test that matters: every `validate` expression in the SHIPPED
//! catalogue must parse.
//!
//! The filter grammar was derived from all 367 filter expressions, and doing so
//! is what caught the one outlier (`generic-api-key`) that a sample would have
//! missed. The validation grammar gets the same treatment: this reads the real
//! `config/betterleaks.toml` out of the `config` crate's embedded catalogue,
//! extracts all 186 `validate = '''…'''` blocks, and parses each one.
//!
//! A grammar that handles 185 of 186 is not "nearly done" — it is a scanner
//! that cannot validate one provider and would have to say so at load time.



/// Pull the `validate = '''…'''` blocks out of the embedded catalogue.
///
/// Hand-scanned rather than TOML-parsed because `config`'s parser drops the
/// validate expressions (they are not part of the filter surface), and the
/// point here is to read exactly what ships.
fn validate_blocks(toml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = toml;
    while let Some(at) = rest.find("\nvalidate = '''") {
        let after = &rest[at + "\nvalidate = '''".len()..];
        let Some(end) = after.find("'''") else { break };
        out.push(after[..end].to_string());
        rest = &after[end + 3..];
    }
    out
}

#[test]
fn every_shipped_validation_expression_parses() {
    let toml = config::DEFAULT_CONFIG;
    let blocks = validate_blocks(toml);
    assert!(
        blocks.len() >= 186,
        "expected the catalogue's 186 validate expressions, found {}",
        blocks.len()
    );

    let mut failures = Vec::new();
    for (i, src) in blocks.iter().enumerate() {
        if let Err(e) = exprruntime::compile(src) {
            // The first line is enough to identify which rule it belongs to.
            let head = src.trim().lines().next().unwrap_or("").trim();
            failures.push(format!("#{i}: {e:?}\n    {head}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} validation expressions failed to parse:\n{}",
        failures.len(),
        blocks.len(),
        failures
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
