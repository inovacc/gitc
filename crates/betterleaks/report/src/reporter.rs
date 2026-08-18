//! The `Reporter` trait + package constants (port of Go `report/report.go`).

use std::io::{self, Write};

use crate::{CsvReporter, Finding, JsonReporter, JunitReporter, SarifReporter};

// https://cwe.mitre.org/data/definitions/798.html
/// Go `report.CWE`.
pub const CWE: &str = "CWE-798";
/// Go `report.CWE_DESCRIPTION`.
pub const CWE_DESCRIPTION: &str = "Use of Hard-coded Credentials";
/// Go `report.StdoutReportPath` — the `-` sentinel for stdout.
pub const STDOUT_REPORT_PATH: &str = "-";

/// A report emitter (port of Go `report.Reporter`).
///
/// Go's `Write` takes an `io.WriteCloser`; this port uses `&mut dyn Write` — the
/// emitters never call `Close`, and `dyn Write` keeps the trait object-safe so
/// emitters can be dispatched dynamically (as Go's interface allows). Each
/// concrete reporter (`JsonReporter`/`CsvReporter`/`JunitReporter`/`SarifReporter`)
/// also keeps its inherent `write` method; the trait impl delegates to it.
pub trait Reporter {
    fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()>;
}

impl Reporter for JsonReporter {
    fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        JsonReporter::write(self, w, findings)
    }
}

impl Reporter for CsvReporter {
    fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        CsvReporter::write(self, w, findings)
    }
}

impl Reporter for JunitReporter {
    fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        JunitReporter::write(self, w, findings)
    }
}

impl Reporter for SarifReporter {
    fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        SarifReporter::write(self, w, findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reporters are usable behind `dyn Reporter` (Go's interface). Smoke-check
    // that dynamic dispatch produces output.
    #[test]
    fn dyn_reporter_dispatch() {
        let reporters: Vec<Box<dyn Reporter>> = vec![
            Box::new(JsonReporter),
            Box::new(CsvReporter),
            Box::new(SarifReporter {
                ordered_rules: Vec::new(),
            }),
        ];
        let finding = Finding {
            rule_id: "test-rule".to_string(),
            ..Default::default()
        };
        for r in &reporters {
            let mut buf = Vec::new();
            r.write(&mut buf, std::slice::from_ref(&finding)).unwrap();
            assert!(!buf.is_empty());
        }
    }
}
