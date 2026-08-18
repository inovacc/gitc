//! Parse a --replace-text file (Rust port of git-filter-repo's replace-text rules).
//!
//! Parses a `--replace-text` file into an ordered list of literal substitutions
//! followed by regex substitutions. Each line may carry an `==>REPLACEMENT`
//! suffix (default [`DEFAULT_REPLACEMENT`]) and a `regex:` / `glob:` / `literal:`
//! prefix.

use std::error::Error;
use std::fmt;
use std::io::BufRead;

use regex::bytes::Regex;

use super::bytesutil::{decode, glob_to_regex};
use super::pathspec::compile_bytes_regex;

/// The replacement used for a rule that omits an explicit `==>REPLACEMENT`.
pub const DEFAULT_REPLACEMENT: &[u8] = b"***REMOVED***";

/// A literal from→to substitution.
#[derive(Debug, Clone)]
pub struct LiteralReplace {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
}

/// A regular-expression substitution.
pub struct RegexReplace {
    pub re: Regex,
    pub to: Vec<u8>,
}

/// The parsed content of a `--replace-text` file.
#[derive(Default)]
pub struct ReplaceRules {
    pub literals: Vec<LiteralReplace>,
    pub regexes: Vec<RegexReplace>,
}

impl ReplaceRules {
    /// Whether the rule set contains no substitutions.
    pub fn empty(&self) -> bool {
        self.literals.is_empty() && self.regexes.is_empty()
    }

    fn add_line(&mut self, raw: &[u8]) -> Result<(), ReplaceTextError> {
        let mut line = trim_end_crlf(raw);

        let mut replacement: Vec<u8> = DEFAULT_REPLACEMENT.to_vec();
        if let Some(idx) = last_index(line, b"==>") {
            replacement = line[idx + 3..].to_vec();
            line = &line[..idx];
        }

        let pattern: Option<Vec<u8>> = if let Some(p) = line.strip_prefix(b"regex:") {
            Some(p.to_vec())
        } else {
            line.strip_prefix(b"glob:").map(glob_to_regex)
        };

        if let Some(pat) = pattern {
            let re = compile_bytes_regex(&pat).map_err(|e| {
                ReplaceTextError(format!(
                    "invalid replace-text regex {:?} (RE2 does not support backreferences or lookaround): {e}",
                    decode(&pat)
                ))
            })?;
            self.regexes.push(RegexReplace {
                re,
                to: replacement,
            });
            return Ok(());
        }

        if let Some(l) = line.strip_prefix(b"literal:") {
            line = l;
        }
        if line.is_empty() {
            return Ok(());
        }
        self.literals.push(LiteralReplace {
            from: line.to_vec(),
            to: replacement,
        });
        Ok(())
    }
}

/// An error parsing a `--replace-text` file (an RE2-rejected regex, or IO).
#[derive(Debug)]
pub struct ReplaceTextError(pub String);

impl fmt::Display for ReplaceTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ReplaceTextError {}

/// Read a `--replace-text` file and return the parsed rules.
pub fn parse_replace_text(filename: &str) -> Result<ReplaceRules, ReplaceTextError> {
    let f = std::fs::File::open(filename).map_err(|e| ReplaceTextError(e.to_string()))?;
    parse_replace_rules(std::io::BufReader::new(f))
}

/// Parse `--replace-text` directives from `r`, one per line.
pub fn parse_replace_rules(mut r: impl BufRead) -> Result<ReplaceRules, ReplaceTextError> {
    let mut rules = ReplaceRules::default();
    loop {
        let mut line = Vec::new();
        let n = r
            .read_until(b'\n', &mut line)
            .map_err(|e| ReplaceTextError(e.to_string()))?;
        if !line.is_empty() {
            rules.add_line(&line)?;
        }
        if n == 0 {
            return Ok(rules);
        }
    }
}

fn trim_end_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn last_index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> ReplaceRules {
        parse_replace_rules(input.as_bytes()).expect("parse")
    }

    #[test]
    fn sample_fixture_literal() {
        let rules = parse("mod==>modified-by-gremlins\n");
        assert_eq!(rules.literals.len(), 1);
        assert_eq!(rules.regexes.len(), 0);
        assert_eq!(rules.literals[0].from, b"mod");
        assert_eq!(rules.literals[0].to, b"modified-by-gremlins");
    }

    #[test]
    fn default_replacement() {
        let rules = parse("secret\n");
        assert_eq!(rules.literals.len(), 1);
        assert_eq!(rules.literals[0].to, DEFAULT_REPLACEMENT);
    }

    #[test]
    fn prefixes_and_anchored_glob() {
        let rules = parse("literal:foo==>bar\nregex:a.c\nglob:*.log\n\n");
        assert_eq!(rules.literals.len(), 1);
        assert_eq!(rules.literals[0].from, b"foo");
        assert_eq!(rules.literals[0].to, b"bar");
        assert_eq!(rules.regexes.len(), 2, "regex: + glob:");
        assert!(
            rules.regexes[1].re.is_match(b"error.log"),
            "glob *.log matches error.log"
        );
        assert!(
            !rules.regexes[1].re.is_match(b"error.log.1"),
            "anchored glob does not match error.log.1"
        );
    }

    #[test]
    fn regex_backref_error() {
        assert!(
            parse_replace_rules(&b"regex:(a)\\1\n"[..]).is_err(),
            "RE2 must reject a backreference"
        );
    }
}
