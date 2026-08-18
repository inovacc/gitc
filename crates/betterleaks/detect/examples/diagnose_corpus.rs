//! Diagnose WHY a corpus example is not detected: does no rule's regex match at
//! all, or does a rule match and then a filter expression discard it?
//!
//!     cargo run -p detect --example diagnose_corpus

fn main() {
    let raw = include_str!("../tests/fixtures/leaks_formats.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("parse");
    let cfg = config::default_config().expect("catalogue");
    let d = detect::Detector::with_default_config().expect("engine");

    for det in v.as_array().unwrap() {
        let name = det["name"].as_str().unwrap();
        let examples = det["fake_examples"].as_array().unwrap();
        let hit = examples
            .iter()
            .filter(|e| !d.detect_string(e.as_str().unwrap()).is_empty())
            .count();
        if hit == examples.len() {
            continue;
        }

        // First undetected example — find which rules' regexes DO match it, so we
        // can tell "no rule matches" from "a filter discarded it".
        let sample = examples
            .iter()
            .map(|e| e.as_str().unwrap())
            .find(|s| d.detect_string(s).is_empty())
            .unwrap_or("");

        let mut regex_hits: Vec<&str> = Vec::new();
        for id in &cfg.ordered_rules {
            let r = &cfg.rules[id];
            if let Some(re) = &r.regex {
                if re.is_match(sample) {
                    regex_hits.push(id);
                }
            }
        }

        println!("--- {name}: {hit}/{} ---", examples.len());
        println!("    sample : {}", &sample.chars().take(90).collect::<String>());
        if regex_hits.is_empty() {
            println!("    verdict: NO RULE REGEX MATCHES (rule absent or pattern differs)");
        } else {
            println!("    verdict: regex matched by {regex_hits:?} -> a FILTER discarded it");
            for id in &regex_hits {
                let f = &cfg.rules[*id].filter;
                if !f.trim().is_empty() {
                    println!("      {id} filter: {}", f.replace('\n', " ").trim());
                }
            }
        }
    }
}
