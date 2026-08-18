//! Port of Go `detect/location.go` — maps a byte match range onto line/column
//! coordinates.

/// Go `detect.Location` (all fields unexported there).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    pub start_line: i64,
    pub end_line: i64,
    pub start_column: i64,
    pub end_column: i64,
    pub start_line_index: usize,
    pub end_line_index: usize,
}

/// Go `location(newlineIndices, raw, matchIndex)`.
///
/// Ported quirks, all load-bearing:
/// * a fragment with NO newlines gets one synthesized at `len(raw)`, so the
///   column arithmetic below still works (gitleaks#1037);
/// * when no line ever matches, the secret is assumed to be on the last line of
///   a newline-less diff, and the end index is found by scanning forward for
///   `\n` or `\r`;
/// * `start_column` is 1-based, `end_column` is NOT (`end - prevNewLine`).
pub fn location(newline_indices: &[[usize; 2]], raw: &str, match_index: [usize; 2]) -> Location {
    let mut loc = Location::default();
    let mut prev_newline: usize = 0;
    let mut line_set = false;
    let mut last_line_num: i64 = 0;

    let start = match_index[0];
    let end = match_index[1];

    // gitleaks#1037: synthesize a newline so a fragment without one still
    // produces sane coordinates.
    let synthesized;
    let indices: &[[usize; 2]] = if newline_indices.is_empty() {
        synthesized = [[raw.len(), raw.len() + 1]];
        &synthesized
    } else {
        newline_indices
    };

    for (line_num, pair) in indices.iter().enumerate() {
        last_line_num = line_num as i64;
        let newline_byte_index = pair[0];
        if prev_newline <= start && start < newline_byte_index {
            line_set = true;
            loc.start_line = line_num as i64;
            loc.end_line = line_num as i64;
            loc.start_column = (start - prev_newline) as i64 + 1; // 1-based
            loc.start_line_index = prev_newline;
            loc.end_line_index = newline_byte_index;
        }
        if prev_newline < end && end <= newline_byte_index {
            loc.end_line = line_num as i64;
            loc.end_column = (end - prev_newline) as i64;
            loc.end_line_index = newline_byte_index;
        }
        prev_newline = pair[0];
    }

    if !line_set {
        // Most likely the last line of diff output with no trailing newline.
        loc.start_column = (start.saturating_sub(prev_newline)) as i64 + 1;
        loc.end_column = (end.saturating_sub(prev_newline)) as i64;
        loc.start_line = last_line_num + 1;
        loc.end_line = last_line_num + 1;

        let b = raw.as_bytes();
        let mut i = 0usize;
        while end + i < b.len() {
            if b[end + i] == b'\n' || b[end + i] == b'\r' {
                break;
            }
            i += 1;
        }
        loc.end_line_index = end + i;
    }

    loc
}
