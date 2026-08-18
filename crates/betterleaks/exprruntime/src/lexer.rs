//! Tokenizer for the filter expression language.
//!
//! The token set is derived from the WHOLE shipped corpus (367 filter/prefilter
//! expressions), plus the operators expr-lang supports that a user config could
//! legitimately use even though the catalogue does not (`&&`, `!`, `==`, `!=`).
//! Porting those is faithfulness to the language, not speculation — omitting
//! them would reject a valid config.

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    True,
    False,
    /// `let` — the generic-api-key filter binds five locals.
    Let,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Bang,
    AndAnd,
    OrOr,
    Lt,
    Le,
    Gt,
    Ge,
    EqEq,
    Ne,
    /// `;` terminates a `let`.
    Semi,
    /// `:` — slice separator AND ternary alternative.
    Colon,
    /// `=` in a `let`.
    Assign,
    /// `?` — ternary.
    Question,
    Plus,
    Minus,
    Star,
    Slash,
    /// `{` `}` — MAP LITERALS. Absent from the 367 filter expressions and used
    /// by 186 of the validation ones, for both request headers and the result
    /// object.
    LBrace,
    RBrace,
    /// `?.` — optional chaining. `r.json?.error` must yield nil rather than
    /// erroring when the response body was not JSON, which is the ordinary case
    /// for an invalid credential.
    QuestionDot,
    /// `??` — nil-coalescing, always paired with `?.` in the catalogue.
    QuestionQuestion,
    /// `nil` — the value `?.` produces and `??` tests for.
    Nil,
    /// `#` — expr-lang's implicit element inside a predicate closure, as in
    /// `any(acl, {# not in public_acls})`. Exactly ONE use in the shipped
    /// catalogue, and without it that one rule cannot validate at all.
    Hash,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError(pub String);

/// Split source into tokens. Whitespace (including the newlines the TOML
/// multi-line strings carry) is insignificant.
pub fn lex(src: &str) -> Result<Vec<Tok>, LexError> {
    let b: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    let mut out = Vec::new();

    while i < b.len() {
        let c = b[i];

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // expr uses `//` line comments; the catalogue has none, but a user
        // config may.
        if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }

        match c {
            '(' => { out.push(Tok::LParen); i += 1; }
            ')' => { out.push(Tok::RParen); i += 1; }
            '[' => { out.push(Tok::LBracket); i += 1; }
            ']' => { out.push(Tok::RBracket); i += 1; }
            ',' => { out.push(Tok::Comma); i += 1; }
            '.' => { out.push(Tok::Dot); i += 1; }
            ';' => { out.push(Tok::Semi); i += 1; }
            ':' => { out.push(Tok::Colon); i += 1; }
            '?' => {
                // Longest match first: `??` and `?.` before the ternary `?`.
                if b.get(i + 1) == Some(&'?') { out.push(Tok::QuestionQuestion); i += 2; }
                else if b.get(i + 1) == Some(&'.') { out.push(Tok::QuestionDot); i += 2; }
                else { out.push(Tok::Question); i += 1; }
            }
            '{' => { out.push(Tok::LBrace); i += 1; }
            '#' => { out.push(Tok::Hash); i += 1; }
            '}' => { out.push(Tok::RBrace); i += 1; }
            '+' => { out.push(Tok::Plus); i += 1; }
            '-' => { out.push(Tok::Minus); i += 1; }
            '*' => { out.push(Tok::Star); i += 1; }
            '/' => { out.push(Tok::Slash); i += 1; }
            '&' => {
                if b.get(i + 1) == Some(&'&') { out.push(Tok::AndAnd); i += 2; }
                else { return Err(LexError("single '&' is not an operator".into())); }
            }
            '|' => {
                if b.get(i + 1) == Some(&'|') { out.push(Tok::OrOr); i += 2; }
                else { return Err(LexError("single '|' is not an operator".into())); }
            }
            '<' => {
                if b.get(i + 1) == Some(&'=') { out.push(Tok::Le); i += 2; } else { out.push(Tok::Lt); i += 1; }
            }
            '>' => {
                if b.get(i + 1) == Some(&'=') { out.push(Tok::Ge); i += 2; } else { out.push(Tok::Gt); i += 1; }
            }
            '=' => {
                if b.get(i + 1) == Some(&'=') { out.push(Tok::EqEq); i += 2; }
                else { out.push(Tok::Assign); i += 1; }
            }
            '!' => {
                if b.get(i + 1) == Some(&'=') { out.push(Tok::Ne); i += 2; } else { out.push(Tok::Bang); i += 1; }
            }
            // Backtick RAW string — the form the catalogue uses for regexes so
            // backslashes need no escaping. No escape processing at all.
            '`' => {
                i += 1;
                let start = i;
                while i < b.len() && b[i] != '`' {
                    i += 1;
                }
                if i >= b.len() {
                    return Err(LexError("unterminated ` string".into()));
                }
                out.push(Tok::Str(b[start..i].iter().collect()));
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= b.len() {
                        return Err(LexError(format!("unterminated {quote} string")));
                    }
                    let ch = b[i];
                    if ch == quote {
                        i += 1;
                        break;
                    }
                    if ch == '\\' {
                        i += 1;
                        if i >= b.len() {
                            return Err(LexError("trailing escape".into()));
                        }
                        s.push(match b[i] {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '\\' => '\\',
                            '"' => '"',
                            '\'' => '\'',
                            '`' => '`',
                            other => other,
                        });
                        i += 1;
                        continue;
                    }
                    s.push(ch);
                    i += 1;
                }
                out.push(Tok::Str(s));
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == '.') {
                    i += 1;
                }
                let text: String = b[start..i].iter().collect();
                let n = text
                    .parse::<f64>()
                    .map_err(|_| LexError(format!("bad number {text:?}")))?;
                out.push(Tok::Num(n));
            }
            _ if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                let word: String = b[start..i].iter().collect();
                out.push(match word.as_str() {
                    "true" => Tok::True,
                    "false" => Tok::False,
                    "let" => Tok::Let,
                    "nil" | "null" => Tok::Nil,
                    // `in` and `contains` are OPERATORS in expr-lang, but
                    // `contains` is also a callable builtin. Both stay Idents
                    // here and the parser decides by looking for a following
                    // `(` — lexing them as keywords would break the call form.
                    _ => Tok::Ident(word),
                });
            }
            other => return Err(LexError(format!("unexpected character {other:?}"))),
        }
    }

    Ok(out)
}
