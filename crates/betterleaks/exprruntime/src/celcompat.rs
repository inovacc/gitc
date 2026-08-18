//! Port of Go `internal/exprruntime/celcompat.go` — rewriting the CEL-shaped
//! syntax older configs use into the expr syntax this engine parses.
//!
//! ## Why a rewriter and not a second parser
//!
//! betterleaks used to accept CEL. Configs written then are still in the wild,
//! and they say things like:
//!
//! ```text
//! cel.bind(r, http.get(url, {}), r.status == 200 ? …)
//! finding.?secret.orValue("")
//! r"""raw\string"""
//! s.contains("x")
//! ```
//!
//! None of that parses as expr. Go's answer is a narrow textual rewrite applied
//! BEFORE compilation, and this is that rewrite. It is deliberately not a CEL
//! implementation: anything it does not recognise is left alone and fails at
//! compile time, with both spellings reported, rather than being silently
//! reinterpreted.
//!
//! ## The one thing that must not happen
//!
//! A rewrite that quietly changes what an expression MEANS is worse than no
//! rewrite. Every transformation here is either a pure syntax swap
//! (`.?x` → `?.x`) or a structural one whose bracket matching is quote-aware —
//! because a `(` inside a string literal is not a bracket, and treating it as
//! one would cut an expression in the wrong place and still produce something
//! that compiles.

/// Go `NeedsCELCompat` — is the rewrite worth attempting at all?
///
/// Checked first so an expression already in expr syntax is never touched.
pub fn needs_cel_compat(s: &str) -> bool {
    s.contains("cel.bind(")
        || s.contains("r\"\"\"")
        || s.contains(".?")
        || s.contains("[?\"")
        || s.contains(".orValue(")
        || s.contains(".contains(")
        || s.contains(".replace(")
        || s.contains(".substring(")
        || s.contains(".lastIndexOf(")
        || s.contains("string(time.now_unix())")
        || contains_env_call(s)
}

/// Go `envAliasRe` — `\benv\(`, i.e. a call to bare `env(` on a word boundary,
/// so `myenv(` does not match.
fn contains_env_call(s: &str) -> bool {
    find_env_call(s, 0).is_some()
}

fn find_env_call(s: &str, from: usize) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = from;
    while let Some(rel) = s[i..].find("env(") {
        let at = i + rel;
        let boundary = at == 0 || !is_word_byte(b[at - 1]);
        if boundary {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

fn is_word_byte(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Go `RewriteCELCompat`.
pub fn rewrite_cel_compat(input: &str) -> Result<String, String> {
    let mut out = input.to_string();

    // `cel.bind(name, value, body)` → `(let name = value; body)`, innermost
    // last: each pass rewrites the FIRST occurrence, and a nested bind inside
    // the body is picked up on the next pass.
    while out.contains("cel.bind(") {
        out = rewrite_first_bind(&out)?;
    }

    out = rewrite_raw_strings(&out);
    out = rewrite_optional_array(&out);
    out = rewrite_optional_index(&out);
    out = rewrite_optional_field(&out);

    // `.orValue(x)` → `(… ?? x)`, repeated to a fixed point because one rewrite
    // can expose another.
    loop {
        let next = rewrite_or_value(&out);
        if next == out {
            break;
        }
        out = next;
    }

    for method in ["contains", "replace", "substring", "lastIndexOf"] {
        out = rewrite_method_calls(&out, method)?;
    }

    out = out.replace("string(time.now_unix())", "time.now_unix()");
    out = rewrite_env_alias(&out);
    out = strip_top_level_let_parens(&out);
    Ok(out)
}

/// `r"""…"""` → a backtick raw string.
fn rewrite_raw_strings(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("r\"\"\"") {
        let after = &rest[start + 4..];
        let Some(end) = after.find("\"\"\"") else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push('`');
        out.push_str(&after[..end]);
        out.push('`');
        rest = &after[end + 3..];
    }
    out.push_str(rest);
    out
}

/// Go `celOptArrayRe` — `a.?b[0].?c.orValue(d)` → `(a?.b?.[0]?.c ?? d)`.
///
/// Handled before the general `.?` rule because it spans an index, which the
/// general rule would leave in the CEL spelling.
fn rewrite_optional_array(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;

    'outer: while i < b.len() {
        // base: [A-Za-z0-9_.]+
        if is_base_char(b[i]) && (i == 0 || !is_base_char(b[i - 1])) {
            let base_start = i;
            let mut j = i;
            // `.` is part of the base (`r.json`), but the `.` that begins a
            // `.?` belongs to the optional-field marker. Go's regex backtracks
            // to find that split; scanning has to stop deliberately.
            while j < b.len() && is_base_char(b[j]) {
                if b[j] == '.' && b.get(j + 1) == Some(&'?') {
                    break;
                }
                j += 1;
            }
            // `.?field`
            if let Some((field1, k)) = opt_field(&b, j) {
                // `[digits]`
                if k < b.len() && b[k] == '[' {
                    let mut d = k + 1;
                    while d < b.len() && b[d].is_ascii_digit() {
                        d += 1;
                    }
                    if d > k + 1 && d < b.len() && b[d] == ']' {
                        let index: String = b[k + 1..d].iter().collect();
                        // `.?field`
                        if let Some((field2, m)) = opt_field(&b, d + 1) {
                            // `.orValue(args)` with no nested parens
                            const OR: &str = ".orValue(";
                            let tail: String = b[m..].iter().collect();
                            if let Some(rest) = tail.strip_prefix(OR) {
                                if let Some(close) = rest.find(')') {
                                    if !rest[..close].contains('(') {
                                        let base: String =
                                            b[base_start..j].iter().collect();
                                        let default = &rest[..close];
                                        out.push_str(&format!(
                                            "({base}?.{field1}?.[{index}]?.{field2} ?? {default})"
                                        ));
                                        i = m + OR.len() + close + 1;
                                        continue 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Not the pattern: copy the base through and carry on.
            for c in &b[base_start..j] {
                out.push(*c);
            }
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn is_base_char(c: char) -> bool {
    c == '_' || c == '.' || c.is_ascii_alphanumeric()
}

/// `.?name` at `i`, returning the name and the index just past it.
fn opt_field(b: &[char], i: usize) -> Option<(String, usize)> {
    if i + 2 >= b.len() || b[i] != '.' || b[i + 1] != '?' {
        return None;
    }
    let start = i + 2;
    if !(b[start].is_ascii_alphabetic() || b[start] == '_') {
        return None;
    }
    let mut j = start;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == '_') {
        j += 1;
    }
    Some((b[start..j].iter().collect(), j))
}

/// Go `celOptIndexRe` — `[?"key"]` → `["key"]`.
fn rewrite_optional_index(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("[?\"") {
        let after = &rest[at + 3..];
        let Some(end) = after.find('"') else { break };
        // The key may not contain a quote, matching Go's `[^"]+`.
        out.push_str(&rest[..at]);
        out.push_str(&format!("[\"{}\"", &after[..end]));
        rest = &after[end + 1..];
        // Go's pattern consumes the closing `]` too.
        if let Some(stripped) = rest.strip_prefix(']') {
            out.push(']');
            rest = stripped;
        }
    }
    out.push_str(rest);
    out
}

/// Go `celOptionalRe` — the general `.?name` → `?.name`.
fn rewrite_optional_field(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        if let Some((name, j)) = opt_field(&b, i) {
            out.push_str(&format!("?.{name}"));
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Go `celOrValueRe` — `RECEIVER.orValue(x)` → `(RECEIVER ?? x)`.
///
/// The receiver is scanned BACKWARDS over the same character class Go's
/// pattern allows, plus one optional trailing `[...]`.
/// Go's regex is a `ReplaceAll`, so every eligible occurrence in ONE pass —
/// not just the first. That distinction is load-bearing for a nested
/// `x.?a.orValue(y.?b.orValue("z"))`: the INNER call is the one whose argument
/// has no parentheses, so it is rewritten and the outer is left alone. Handling
/// only the first occurrence would rewrite neither, and the caller's
/// fixed-point loop would terminate immediately with the CEL spelling intact.
fn rewrite_or_value(s: &str) -> String {
    const OR: &str = ".orValue(";
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0usize;
    let mut from = 0usize;

    while let Some(rel) = s[from..].find(OR) {
        let at = from + rel;
        let args_start = at + OR.len();
        let Some(rel_close) = s[args_start..].find(')') else {
            break;
        };
        let close = args_start + rel_close;

        // Go's `([^()]*)` — the argument may not itself contain parentheses.
        if s[args_start..close].contains('(') {
            from = args_start;
            continue;
        }

        // Walk the receiver backwards, allowing one trailing `[...]`.
        let mut start = at;
        if start > 0 && b[start - 1] == b']' {
            if let Some(open) = s[..start].rfind('[') {
                start = open;
            }
        }
        while start > copied && is_or_value_receiver_byte(b[start - 1]) {
            start -= 1;
        }
        if start == at {
            from = args_start;
            continue;
        }

        out.push_str(&s[copied..start]);
        out.push_str(&format!("({} ?? {})", &s[start..at], &s[args_start..close]));
        copied = close + 1;
        from = copied;
    }

    out.push_str(&s[copied..]);
    out
}

/// Go's `[A-Za-z0-9_\]\)"\?\.]` receiver class.
fn is_or_value_receiver_byte(c: u8) -> bool {
    matches!(c, b'_' | b']' | b')' | b'"' | b'?' | b'.') || c.is_ascii_alphanumeric()
}

/// Go `rewriteMethodCalls` — `recv.method(args)` → `method(recv, args)`, except
/// `contains`, which becomes the binary operator.
fn rewrite_method_calls(s: &str, method: &str) -> Result<String, String> {
    let needle = format!(".{method}(");
    let mut s = s.to_string();
    loop {
        let Some(idx) = s.find(&needle) else {
            return Ok(s);
        };
        let Some(recv_start) = receiver_start(&s, idx) else {
            return Err(format!(
                "compat rewrite could not find receiver for .{method}"
            ));
        };
        let args_start = idx + needle.len();
        let args_end = matching_paren(&s, args_start - 1)?;
        let receiver = s[recv_start..idx].trim().to_string();
        let args = s[args_start..args_end].trim().to_string();

        let repl = if method == "contains" {
            format!("({receiver} contains {args})")
        } else if args.is_empty() {
            format!("{method}({receiver})")
        } else {
            format!("{method}({receiver}, {args})")
        };
        s = format!("{}{}{}", &s[..recv_start], repl, &s[args_end + 1..]);
    }
}

/// Go `receiverStart` — walk backwards over the receiver, skipping balanced
/// `(...)` and `[...]` groups.
fn receiver_start(s: &str, dot: usize) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = dot as isize - 1;
    while i >= 0 && matches!(b[i as usize], b' ' | b'\t' | b'\r' | b'\n') {
        i -= 1;
    }
    while i >= 0 {
        match b[i as usize] {
            b')' => {
                let open = matching_open(s, i as usize, b'(', b')')?;
                i = open as isize - 1;
            }
            b']' => {
                let open = matching_open(s, i as usize, b'[', b']')?;
                i = open as isize - 1;
            }
            c if is_receiver_char(c) => i -= 1,
            _ => return Some((i + 1) as usize),
        }
    }
    Some(0)
}

/// Go `isReceiverChar`.
fn is_receiver_char(c: u8) -> bool {
    matches!(c, b'_' | b'.' | b'?' | b'"' | b'\'') || c.is_ascii_alphanumeric()
}

/// Go `matchingOpen` — scan BACKWARDS for the opener, ignoring brackets inside
/// string literals.
fn matching_open(s: &str, close: usize, open_ch: u8, close_ch: u8) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut quote = 0u8;
    let mut i = close as isize;
    while i >= 0 {
        let c = b[i as usize];
        if quote != 0 {
            if c == quote && (i == 0 || b[(i - 1) as usize] != b'\\') {
                quote = 0;
            }
            i -= 1;
            continue;
        }
        match c {
            b'"' | b'\'' | b'`' => quote = c,
            _ if c == close_ch => depth += 1,
            _ if c == open_ch => {
                depth -= 1;
                if depth == 0 {
                    return Some(i as usize);
                }
            }
            _ => {}
        }
        i -= 1;
    }
    None
}

/// Go `matchingParen` — forwards, quote-aware.
fn matching_paren(s: &str, open: usize) -> Result<usize, String> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut quote = 0u8;
    let mut i = open;
    while i < b.len() {
        let c = b[i];
        if quote != 0 {
            if c == b'\\' && i + 1 < b.len() {
                i += 2;
                continue;
            }
            if c == quote {
                quote = 0;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' | b'`' => quote = c,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("unmatched parenthesis in expression".to_string())
}

/// Go `rewriteFirstBind` — `cel.bind(name, value, body)` →
/// `(let name = value; body)`.
fn rewrite_first_bind(s: &str) -> Result<String, String> {
    const BIND: &str = "cel.bind(";
    let Some(idx) = s.find(BIND) else {
        return Ok(s.to_string());
    };
    let start_args = idx + BIND.len();
    let end = matching_paren(s, start_args - 1)?;
    let args = split_top_level_args(&s[start_args..end])?;
    if args.len() != 3 {
        return Err(format!(
            "cel.bind compatibility rewrite expected 3 args, got {}",
            args.len()
        ));
    }
    let name = args[0].trim();
    if name.is_empty() {
        return Err("cel.bind compatibility rewrite found empty binding name".to_string());
    }
    let repl = format!("(let {name} = {}; {})", args[1].trim(), args[2].trim());
    Ok(format!("{}{repl}{}", &s[..idx], &s[end + 1..]))
}

/// Go `splitTopLevelArgs` — split on commas outside every bracket and quote.
fn split_top_level_args(s: &str) -> Result<Vec<String>, String> {
    let b = s.as_bytes();
    let mut args = Vec::new();
    let (mut start, mut paren, mut brace, mut bracket) = (0usize, 0i32, 0i32, 0i32);
    let mut quote = 0u8;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if quote != 0 {
            if c == b'\\' && i + 1 < b.len() {
                i += 2;
                continue;
            }
            if c == quote {
                quote = 0;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' | b'`' => quote = c,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b',' if paren == 0 && brace == 0 && bracket == 0 => {
                args.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
        if paren < 0 || brace < 0 || bracket < 0 {
            return Err("unbalanced expression while splitting cel.bind".to_string());
        }
        i += 1;
    }
    args.push(s[start..].to_string());
    Ok(args)
}

/// Go `envAliasRe` — bare `env(` → `env.get(`.
fn rewrite_env_alias(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut from = 0usize;
    while let Some(at) = find_env_call(s, from) {
        out.push_str(&s[from..at]);
        out.push_str("env.get(");
        from = at + "env(".len();
    }
    out.push_str(&s[from..]);
    out
}

/// Go `stripTopLevelLetParens` — a whole-expression `(let …)` loses the wrapper.
///
/// The bind rewrite always parenthesises, and a top-level `(let x = 1; x)` is
/// legal but noisy; more to the point, Go strips it, so an expression that
/// round-trips through both must strip it too.
fn strip_top_level_let_parens(s: &str) -> String {
    let trimmed = s.trim();
    if !trimmed.starts_with("(let ") || !trimmed.ends_with(')') {
        return s.to_string();
    }
    let Ok(end) = matching_paren(trimmed, 0) else {
        return s.to_string();
    };
    if end != trimmed.len() - 1 {
        return s.to_string();
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let prefix_len = s.len() - s.trim_start().len();
    let suffix_len = s.len() - s.trim_end().len();
    format!("{}{inner}{}", &s[..prefix_len], &s[s.len() - suffix_len..])
}

#[cfg(test)]
mod tests;
