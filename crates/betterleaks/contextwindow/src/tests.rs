//! Faithful port of Go `internal/contextwindow/extract_test.go` — all four test
//! functions, with their tables case-for-case.

use super::*;

/// Port of Go `TestParseMatchContext`.
#[test]
fn parse_match_context() {
    struct Case {
        name: &'static str,
        input: &'static str,
        want: Option<Spec>, // None == wantErr
    }
    let z = Spec::default();
    let cases = vec![
        // Zero / empty states
        Case { name: "Empty string", input: "", want: Some(z.clone()) },
        Case { name: "Zero", input: "0", want: Some(z.clone()) },
        Case { name: "Spaces", input: "   ", want: Some(z.clone()) },
        // Cols mode (C)
        Case {
            name: "Implicit cols",
            input: "100",
            want: Some(Spec { mode: Mode::Cols, cols_before: 100, cols_after: 100, ..z.clone() }),
        },
        Case {
            name: "Explicit cols",
            input: "100C",
            want: Some(Spec { mode: Mode::Cols, cols_before: 100, cols_after: 100, ..z.clone() }),
        },
        Case {
            name: "Directed cols",
            input: "-10C, +20C",
            want: Some(Spec { mode: Mode::Cols, cols_before: 10, cols_after: 20, ..z.clone() }),
        },
        // Later tokens do NOT overwrite: each direction keeps its MAX.
        Case {
            name: "Overriding cols",
            input: "10C, -50C",
            want: Some(Spec { mode: Mode::Cols, cols_before: 50, cols_after: 10, ..z.clone() }),
        },
        // Box mode (L, mixed with C for clipping). Note the L amount is
        // decremented by one: "10L" means 10 lines TOTAL, so 9 either side.
        Case {
            name: "Lines only",
            input: "10L",
            want: Some(Spec { mode: Mode::Box, lines_before: 9, lines_after: 9, ..z.clone() }),
        },
        Case {
            name: "Directed lines",
            input: "-2L, +3L",
            want: Some(Spec { mode: Mode::Box, lines_before: 1, lines_after: 2, ..z.clone() }),
        },
        Case {
            name: "Lines and cols mixed (explicit)",
            input: "2L, 15C",
            want: Some(Spec {
                mode: Mode::Box,
                lines_before: 1,
                lines_after: 1,
                cols_before: 15,
                cols_after: 15,
            }),
        },
        Case {
            name: "Lines and cols mixed (implicit C)",
            input: "15, 2L",
            want: Some(Spec {
                mode: Mode::Box,
                lines_before: 1,
                lines_after: 1,
                cols_before: 15,
                cols_after: 15,
            }),
        },
        Case {
            name: "Directed mixed",
            input: "-2L, +10C",
            want: Some(Spec { mode: Mode::Box, lines_before: 1, cols_after: 10, ..z.clone() }),
        },
        // Errors
        Case { name: "Invalid token", input: "10X", want: None },
        Case { name: "Malformed token", input: "10L-", want: None },
        Case {
            name: "Amount overflow",
            input: "999999999999999999999999999999999999999999C",
            want: None,
        },
    ];

    for c in cases {
        match (parse(c.input), &c.want) {
            (Ok(got), Some(want)) => assert_eq!(&got, want, "Parse({:?}) [{}]", c.input, c.name),
            (Err(e), Some(_)) => panic!("Parse({:?}) [{}] errored: {e}", c.input, c.name),
            (Ok(got), None) => panic!("Parse({:?}) [{}] should error, got {got:?}", c.input, c.name),
            (Err(_), None) => {}
        }
    }
}

/// Rebuild the Go test's fixture: a leading `\n`, then 20 lines of 150 chars,
/// each `L<NN>|` followed by a repeated letter. Line 10 carries the secret at
/// column 60.
const MATCH_COL: usize = 60;
const SECRET: &str = "SECRET_KEY_VALUE";

fn uniform_lines() -> Vec<String> {
    (0..20)
        .map(|i| {
            let prefix = format!("L{i:02}|");
            let letter = (b'a' + i as u8) as char;
            if i == 10 {
                let before = MATCH_COL - prefix.len();
                let after = 150 - prefix.len() - before - SECRET.len();
                format!(
                    "{prefix}{}{SECRET}{}",
                    letter.to_string().repeat(before),
                    letter.to_string().repeat(after)
                )
            } else {
                format!("{prefix}{}", letter.to_string().repeat(150 - prefix.len()))
            }
        })
        .collect()
}

fn raw_from(lines: &[String]) -> String {
    format!("\n{}\n", lines.join("\n"))
}

fn match_index(lines: &[String]) -> [usize; 2] {
    // Leading "\n" = 1, then every preceding line plus its "\n".
    let mut start = 1;
    for l in lines.iter().take(10) {
        start += l.len() + 1;
    }
    start += MATCH_COL;
    [start, start + SECRET.len()]
}

fn clip_line(line: &str, cs: usize, ce: usize) -> String {
    let b = line.as_bytes();
    let cs = if b.len() <= cs { 0 } else { cs }; // short line: show it whole
    String::from_utf8_lossy(&b[cs..ce.min(b.len())]).into_owned()
}

fn clip_lines(lines: &[String], from: usize, to: usize, cs: usize, ce: usize) -> String {
    (from..=to)
        .map(|i| clip_line(&lines[i], cs, ce))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Port of Go `TestExtractContext`.
#[test]
fn extract_context() {
    let lines = uniform_lines();
    for (i, l) in lines.iter().enumerate() {
        assert_eq!(l.len(), 150, "line {i} must be 150 bytes (Go fixture invariant)");
    }
    let raw = raw_from(&lines);
    let idx = match_index(&lines);
    assert_eq!(idx[0], 1 + 10 * 151 + MATCH_COL, "Go computes matchStart as 1 + 10*151 + 60");
    assert_eq!(&raw[idx[0]..idx[1]], SECRET);

    let join = |from: usize, to: usize| lines[from..=to].join("\n");

    // Zero spec
    assert_eq!(extract(&raw, idx, &Spec::default()), "");

    // Cols: 5 before, 5 after
    assert_eq!(
        extract(&raw, idx, &Spec { mode: Mode::Cols, cols_before: 5, cols_after: 5, ..Default::default() }),
        raw[idx[0] - 5..idx[1] + 5]
    );

    // Cols: directed -10, +5
    assert_eq!(
        extract(&raw, idx, &Spec { mode: Mode::Cols, cols_before: 10, cols_after: 5, ..Default::default() }),
        raw[idx[0] - 10..idx[1] + 5]
    );

    // Cols: out of bounds clamps to the whole input
    assert_eq!(
        extract(&raw, idx, &Spec { mode: Mode::Cols, cols_before: 10000, cols_after: 10000, ..Default::default() }),
        raw
    );

    // Box: match line only
    assert_eq!(extract(&raw, idx, &Spec { mode: Mode::Box, ..Default::default() }), lines[10]);

    // Box: 2 lines before, 3 after
    assert_eq!(
        extract(&raw, idx, &Spec { mode: Mode::Box, lines_before: 2, lines_after: 3, ..Default::default() }),
        join(8, 13)
    );

    // Box: match line, 10C clip
    assert_eq!(
        extract(&raw, idx, &Spec { mode: Mode::Box, cols_before: 10, cols_after: 10, ..Default::default() }),
        clip_line(&lines[10], MATCH_COL - 10, MATCH_COL + SECRET.len() + 10)
    );

    // Box: 3 lines before/after, 20C clip
    assert_eq!(
        extract(
            &raw,
            idx,
            &Spec { mode: Mode::Box, lines_before: 3, lines_after: 3, cols_before: 20, cols_after: 20 }
        ),
        clip_lines(&lines, 7, 13, MATCH_COL - 20, MATCH_COL + SECRET.len() + 20)
    );
}

/// Port of Go `TestExtractContextMultiLineMatch`. Column clipping is SKIPPED
/// when the match itself spans lines — the first line's column offset does not
/// apply to later lines.
#[test]
fn extract_context_multi_line_match() {
    let raw = "aaa\nbbbSECRET_START\nSECRET_ENDccc\nddd";
    let start = raw.find("SECRET_START").unwrap();
    let end = raw.find("SECRET_END").unwrap() + "SECRET_END".len();
    let got = extract(
        raw,
        [start, end],
        &Spec { mode: Mode::Box, lines_before: 1, lines_after: 1, cols_before: 2, cols_after: 2 },
    );
    assert_eq!(got, "aaa\nbbbSECRET_START\nSECRET_ENDccc\nddd");
}

/// Port of Go `TestExtractContextVaryingLineLengths`. Short lines are shown in
/// FULL rather than clipped to nothing.
#[test]
fn extract_context_varying_line_lengths() {
    let long = |i: usize, c: char| format!("L{i:02}|{}", c.to_string().repeat(146));
    let secret_line = {
        let prefix = "L10|";
        let before = MATCH_COL - prefix.len();
        let after = 150 - prefix.len() - before - SECRET.len();
        format!("{prefix}{}{SECRET}{}", "k".repeat(before), "k".repeat(after))
    };
    let lines: Vec<String> = vec![
        "L00|aa".into(),
        "L01|bb".into(),
        "L02|cc".into(),
        "L03|dd".into(),
        "L04|ee".into(),
        "L05|ff".into(),
        long(6, 'g'),
        "L07|h".into(),
        long(8, 'i'),
        "L09|jj".into(),
        secret_line,
        "L11|lll".into(),
        "L12|m".into(),
        "L13|nn".into(),
        long(14, 'o'),
        long(15, 'p'),
        "L16|q".into(),
        long(17, 'r'),
        long(18, 's'),
        long(19, 't'),
    ];
    let raw = raw_from(&lines);
    let idx = match_index(&lines);
    assert_eq!(&raw[idx[0]..idx[1]], SECRET);

    // 3 lines before/after, 20C clip
    let got = extract(
        &raw,
        idx,
        &Spec { mode: Mode::Box, lines_before: 3, lines_after: 3, cols_before: 20, cols_after: 20 },
    );
    assert_eq!(
        got,
        concat!(
            "L07|h\n",
            "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\n",
            "L09|jj\n",
            "kkkkkkkkkkkkkkkkkkkkSECRET_KEY_VALUEkkkkkkkkkkkkkkkkkkkk\n",
            "L11|lll\n",
            "L12|m\n",
            "L13|nn"
        )
    );

    // 5 lines before/after, 10C clip
    let got = extract(
        &raw,
        idx,
        &Spec { mode: Mode::Box, lines_before: 5, lines_after: 5, cols_before: 10, cols_after: 10 },
    );
    assert_eq!(
        got,
        concat!(
            "L05|ff\n",
            "gggggggggggggggggggggggggggggggggggg\n",
            "L07|h\n",
            "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\n",
            "L09|jj\n",
            "kkkkkkkkkkSECRET_KEY_VALUEkkkkkkkkkk\n",
            "L11|lll\n",
            "L12|m\n",
            "L13|nn\n",
            "oooooooooooooooooooooooooooooooooooo\n",
            "pppppppppppppppppppppppppppppppppppp"
        )
    );
}

/// Characterization (no Go test): `IsZero`, and that an empty token between
/// commas is an error distinct from an invalid token.
#[test]
fn is_zero_and_empty_token() {
    assert!(Spec::default().is_zero());
    assert!(!Spec { mode: Mode::Cols, ..Default::default() }.is_zero());
    let e = parse("10C,,20C").unwrap_err().to_string();
    assert!(e.contains("empty token"), "got {e:?}");
}

/// Characterization: `extract` on empty input returns empty regardless of spec
/// (Go guards `len(raw) == 0` before switching on mode).
#[test]
fn extract_empty_input() {
    assert_eq!(
        extract("", [0, 0], &Spec { mode: Mode::Cols, cols_before: 5, cols_after: 5, ..Default::default() }),
        ""
    );
}

/// Characterization: the token grammar is case-insensitive (`(?i)` in the Go
/// pattern), so a lowercase unit works.
#[test]
fn token_unit_is_case_insensitive() {
    assert_eq!(parse("10l").unwrap(), parse("10L").unwrap());
    assert_eq!(parse("10c").unwrap(), parse("10C").unwrap());
}
