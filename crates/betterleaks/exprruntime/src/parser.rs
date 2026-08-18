//! Recursive-descent parser producing the filter AST.
//!
//! ## The grammar, and how it was derived
//!
//! 366 of the 367 shipped expressions use a tiny language: a call, a numeric
//! comparison, and `||`. The 367th — the **`generic-api-key` catch-all**, the
//! single most important rule in the catalogue — uses substantially more:
//! `let` bindings (including `let _` for a side effect), a ternary, Go-style
//! **slices** (`s[a:b]`), arithmetic, and `min`/`max`/`len`.
//!
//! That one expression is why PORT-PLAN insisted the grammar be derived from
//! the WHOLE corpus. A sample of the other 366 would have produced a parser
//! that silently rejected the catch-all.
//!
//! ## The VALIDATION grammar, derived the same way
//!
//! The 186 `validate` expressions in the same catalogue need substantially
//! more, and the additions were found by parsing all 186 rather than a sample —
//! the last four gaps were each a handful of uses, and one was a single use:
//!
//! | Construct | Uses |
//! |---|---|
//! | `{ "k": v }` map literals | 186 |
//! | `r.status` member access | 426 |
//! | `x in [a, b]` | 152 |
//! | `haystack contains needle` (an OPERATOR) | ~135 |
//! | `?.` / `??` | many |
//! | `let` NESTED inside parens or a branch | 223 lets total |
//! | `s.split(":")` — a builtin in METHOD position | 3 |
//! | `a?.[0]` optional indexing | 1 |
//! | `any(xs, {# not in ys})` — a predicate closure | 1 |
//!
//! The last three are why the corpus test exists. A grammar covering 183 of 186
//! is not "nearly done": it is a scanner that cannot validate three providers.
//!
//! Precedence, loosest to tightest:
//!
//! ```text
//! program  := ('let' (IDENT|'_') '=' expr ';')* expr
//! expr     := ternary
//! ternary  := coalesce ('?' expr ':' expr)?
//! coalesce := or ('??' or)*
//! or       := and ('||' and)*
//! and      := not ('&&' not)*
//! not      := '!' not | cmp
//! cmp      := add (('<'|'<='|'>'|'>='|'=='|'!=') add)?     // non-associative
//!           | add ('in' | 'not' 'in' | 'contains') add
//! add      := mul (('+'|'-') mul)*
//! mul      := unary (('*'|'/') unary)*
//! unary    := '-' unary | postfix
//! postfix  := primary ('[' expr [':' expr] ']'
//!                     | '.' IDENT | '?.' IDENT | '?.' '[' expr ']'
//!                     | '(' args ')')*
//! primary  := number | string | true | false | nil | '#' | array
//!           | '{' (expr ':' expr),* '}'      // map literal
//!           | '{' expr '}'                   // predicate closure
//!           | IDENT | 'let' … | '(' expr ')'
//! ```

use crate::lexer::{lex, LexError, Tok};

#[derive(Debug, Clone, PartialEq)]
pub enum Ast {
    Num(f64),
    Str(String),
    Bool(bool),
    Array(Vec<Ast>),
    /// A bare name — `finding`, `attributes`, or a `let`-bound local.
    Ident(String),
    /// `base[key]`
    Index(Box<Ast>, Box<Ast>),
    /// `base[lo:hi]` — Go-style slice over a string, by BYTE offsets.
    Slice(Box<Ast>, Box<Ast>, Box<Ast>),
    /// `name(args)` / `ns.name(args)`.
    Call(String, Vec<Ast>),
    Not(Box<Ast>),
    Neg(Box<Ast>),
    And(Box<Ast>, Box<Ast>),
    Or(Box<Ast>, Box<Ast>),
    Cmp(Box<Ast>, CmpOp, Box<Ast>),
    Arith(Box<Ast>, ArithOp, Box<Ast>),
    /// `cond ? then : else`
    Ternary(Box<Ast>, Box<Ast>, Box<Ast>),
    /// `let name = value; body`. `_` discards, keeping the side effect.
    Let {
        name: String,
        value: Box<Ast>,
        body: Box<Ast>,
    },
    /// `nil` — and what `?.` yields on a missing member.
    Nil,
    /// `{ "k": v, … }` — a map literal. Keys are expressions because expr
    /// allows it, though the catalogue only ever uses string literals.
    Map(Vec<(Ast, Ast)>),
    /// `base.name` / `base?.name`. The bool is OPTIONAL chaining: with it, a
    /// missing member (or a nil base) yields nil instead of an error, which is
    /// what makes `r.json?.error ?? "Unauthorized"` work when the response was
    /// not JSON at all — the ordinary case for an invalid credential.
    Member(Box<Ast>, String, bool),
    /// `a ?? b` — `b` only when `a` is nil.
    Coalesce(Box<Ast>, Box<Ast>),
    /// `x in [a, b]` — 152 uses, essentially all of them a status-code set.
    In(Box<Ast>, Box<Ast>),
    /// `haystack contains needle` — expr-lang has this as a BINARY OPERATOR,
    /// which is how `r.body contains "\"features\""` parses.
    Contains(Box<Ast>, Box<Ast>),
    /// `#` — the implicit element inside a predicate closure.
    Pointer,
    /// `base?.[key]` - optional indexing. Yields nil when the base is nil or
    /// the key is absent, rather than erroring.
    OptIndex(Box<Ast>, Box<Ast>),
    /// `{ expr }` in argument position — a predicate closure, whose body is
    /// evaluated once per element with `#` bound to it.
    Closure(Box<Ast>),
}

/// Identifiers that are NAMESPACES rather than variables.
///
/// This list is what separates `http.get(…)` (a function in a namespace) from
/// `finding["secret"].contains(…)` (a builtin called in method position). Both
/// spellings are `X.y(…)`, and expr-lang tells them apart by what `X` resolves
/// to at runtime; the parser cannot, so the roots are named explicitly.
///
/// Being explicit is the safer failure: a namespace missing from this list
/// produces "unknown function", loudly, at config load. Guessing instead — say,
/// "a call after a dot is always a method" — would turn `http.get(url)` into a
/// method call on an undefined variable and fail far from the cause.
pub const NAMESPACE_ROOTS: &[&str] = &[
    "http", "crypto", "base64", "hex", "json", "strings", "time", "env", "filter", "validate",
    "aws", "azure", "gcp",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError(e.0)
    }
}

pub fn parse(src: &str) -> Result<Ast, ParseError> {
    let toks = lex(src)?;
    let mut p = Parser { toks, i: 0 };
    let ast = p.parse_program()?;
    if p.i != p.toks.len() {
        return Err(ParseError(format!("trailing tokens at {:?}", p.peek())));
    }
    Ok(ast)
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, t: &Tok) -> Result<(), ParseError> {
        if self.eat(t) {
            Ok(())
        } else {
            Err(ParseError(format!("expected {t:?}, found {:?}", self.peek())))
        }
    }

    /// `('let' NAME '=' expr ';')* expr`, desugared into nested [`Ast::Let`] so
    /// the evaluator needs no statement concept.
    fn parse_program(&mut self) -> Result<Ast, ParseError> {
        if self.eat(&Tok::Let) {
            let name = match self.peek().cloned() {
                Some(Tok::Ident(n)) => {
                    self.i += 1;
                    n
                }
                other => return Err(ParseError(format!("expected name after 'let', found {other:?}"))),
            };
            self.expect(&Tok::Assign)?;
            let value = self.parse_expr()?;
            self.expect(&Tok::Semi)?;
            let body = self.parse_program()?;
            return Ok(Ast::Let {
                name,
                value: Box::new(value),
                body: Box::new(body),
            });
        }
        self.parse_expr()
    }

    fn parse_expr(&mut self) -> Result<Ast, ParseError> {
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<Ast, ParseError> {
        let cond = self.parse_coalesce()?;
        if self.eat(&Tok::Question) {
            let then = self.parse_expr()?;
            self.expect(&Tok::Colon)?;
            let alt = self.parse_expr()?;
            return Ok(Ast::Ternary(Box::new(cond), Box::new(then), Box::new(alt)));
        }
        Ok(cond)
    }

    /// `??` binds looser than `||` and tighter than the ternary, so
    /// `a ?? b ? x : y` groups as `(a ?? b) ? x : y`.
    fn parse_coalesce(&mut self) -> Result<Ast, ParseError> {
        let mut lhs = self.parse_or()?;
        while self.eat(&Tok::QuestionQuestion) {
            let rhs = self.parse_or()?;
            lhs = Ast::Coalesce(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_or(&mut self) -> Result<Ast, ParseError> {
        let mut lhs = self.parse_and()?;
        while self.eat(&Tok::OrOr) {
            let rhs = self.parse_and()?;
            lhs = Ast::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Ast, ParseError> {
        let mut lhs = self.parse_not()?;
        while self.eat(&Tok::AndAnd) {
            let rhs = self.parse_not()?;
            lhs = Ast::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Ast, ParseError> {
        if self.eat(&Tok::Bang) {
            return Ok(Ast::Not(Box::new(self.parse_not()?)));
        }
        self.parse_cmp()
    }

    /// Non-associative, as in expr: `a < b < c` is a parse error.
    ///
    /// `in` and `contains` sit at this precedence and are recognised by NAME
    /// rather than by a keyword token, because `contains(…)` is ALSO a callable
    /// builtin — lexing it as a keyword would break the call form.
    fn parse_cmp(&mut self) -> Result<Ast, ParseError> {
        let lhs = self.parse_add()?;

        if let Some(Tok::Ident(word)) = self.peek() {
            let word = word.clone();
            let is_call = self.toks.get(self.i + 1) == Some(&Tok::LParen);

            // `not in` — a negated membership, written as two words.
            if !is_call && word == "not" && self.toks.get(self.i + 1) == Some(&Tok::Ident("in".to_string()))
            {
                self.i += 2;
                let rhs = self.parse_add()?;
                return Ok(Ast::Not(Box::new(Ast::In(Box::new(lhs), Box::new(rhs)))));
            }

            if !is_call && (word == "in" || word == "contains") {
                self.i += 1;
                let rhs = self.parse_add()?;
                return Ok(if word == "in" {
                    Ast::In(Box::new(lhs), Box::new(rhs))
                } else {
                    Ast::Contains(Box::new(lhs), Box::new(rhs))
                });
            }
        }

        let op = match self.peek() {
            Some(Tok::Lt) => CmpOp::Lt,
            Some(Tok::Le) => CmpOp::Le,
            Some(Tok::Gt) => CmpOp::Gt,
            Some(Tok::Ge) => CmpOp::Ge,
            Some(Tok::EqEq) => CmpOp::Eq,
            Some(Tok::Ne) => CmpOp::Ne,
            _ => return Ok(lhs),
        };
        self.i += 1;
        let rhs = self.parse_add()?;
        Ok(Ast::Cmp(Box::new(lhs), op, Box::new(rhs)))
    }

    fn parse_add(&mut self) -> Result<Ast, ParseError> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => ArithOp::Add,
                Some(Tok::Minus) => ArithOp::Sub,
                _ => return Ok(lhs),
            };
            self.i += 1;
            let rhs = self.parse_mul()?;
            lhs = Ast::Arith(Box::new(lhs), op, Box::new(rhs));
        }
    }

    fn parse_mul(&mut self) -> Result<Ast, ParseError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => ArithOp::Mul,
                Some(Tok::Slash) => ArithOp::Div,
                _ => return Ok(lhs),
            };
            self.i += 1;
            let rhs = self.parse_unary()?;
            lhs = Ast::Arith(Box::new(lhs), op, Box::new(rhs));
        }
    }

    fn parse_unary(&mut self) -> Result<Ast, ParseError> {
        if self.eat(&Tok::Minus) {
            return Ok(Ast::Neg(Box::new(self.parse_unary()?)));
        }
        self.parse_postfix()
    }

    /// `primary ( '.' IDENT | '?.' IDENT | '[' … ']' | '(' args ')' )*`
    ///
    /// The `path` bookkeeping is what lets `http.get(…)` and `r.status` share
    /// one production. While the chain is still nothing but identifiers joined
    /// by `.`, its dotted spelling is remembered; a `(` at that point is a
    /// NAMESPACED CALL (`http.get`, `crypto.hmacSha256`, `validate.unknown`).
    /// Once anything else intervenes — an index, an optional `?.`, a call — the
    /// path is gone and `.name` is member access on a value.
    ///
    /// That split matters because both spellings are everywhere in the
    /// catalogue and they mean entirely different things: `http.get` is a
    /// function in a namespace, `r.status` is a field of a response.
    fn parse_postfix(&mut self) -> Result<Ast, ParseError> {
        let (mut node, mut path) = self.parse_primary_with_path()?;
        // The base and name of the MOST RECENT `.name`, so a following `(` can
        // be re-read as a method call when the root is not a namespace.
        let mut last_member: Option<(Ast, String)> = None;

        loop {
            if self.eat(&Tok::LBracket) {
                let first = self.parse_expr()?;
                if self.eat(&Tok::Colon) {
                    let hi = self.parse_expr()?;
                    self.expect(&Tok::RBracket)?;
                    node = Ast::Slice(Box::new(node), Box::new(first), Box::new(hi));
                } else {
                    self.expect(&Tok::RBracket)?;
                    node = Ast::Index(Box::new(node), Box::new(first));
                }
                path = None;
                last_member = None;
                continue;
            }

            if self.eat(&Tok::Dot) {
                let name = self.expect_ident("'.'")?;
                last_member = Some((node.clone(), name.clone()));
                if let Some(ref p) = path {
                    // Still a pure identifier chain: keep both readings open
                    // until we see whether a `(` follows.
                    path = Some(format!("{p}.{name}"));
                }
                node = Ast::Member(Box::new(node), name, false);
                continue;
            }

            if self.eat(&Tok::QuestionDot) {
                // `a?.[i]` — optional INDEXING, not member access.
                // `r.json?.data?.[0]?.name` walks a JSON response that may stop
                // being walkable at any step, which is the ordinary shape of a
                // response from a credential that turned out to be invalid.
                if self.eat(&Tok::LBracket) {
                    let key = self.parse_expr()?;
                    self.expect(&Tok::RBracket)?;
                    node = Ast::OptIndex(Box::new(node), Box::new(key));
                    path = None;
                    last_member = None;
                    continue;
                }
                let name = self.expect_ident("'?.'")?;
                node = Ast::Member(Box::new(node), name, true);
                // `a?.b(…)` would be an optional CALL, which expr does not have
                // and the catalogue never writes.
                path = None;
                last_member = None;
                continue;
            }

            if self.peek() == Some(&Tok::LParen) {
                self.i += 1;
                let args = self.parse_call_args()?;

                // Three readings, in order of specificity.
                let is_namespaced = path
                    .as_deref()
                    .and_then(|p| p.split('.').next())
                    .is_some_and(|root| NAMESPACE_ROOTS.contains(&root));

                node = if is_namespaced {
                    // `http.get(…)` — a function inside a namespace.
                    Ast::Call(path.clone().expect("a namespaced path"), args)
                } else if let Some((base, name)) = last_member.take() {
                    // `finding["secret"].contains(…)` / `s.split(":")` — a
                    // builtin called in METHOD position, with the receiver
                    // becoming the first argument. This is how expr-lang reads
                    // it, and the catalogue relies on it.
                    let mut with_receiver = Vec::with_capacity(args.len() + 1);
                    with_receiver.push(base);
                    with_receiver.extend(args);
                    Ast::Call(name, with_receiver)
                } else if let Some(name) = path.clone() {
                    // A plain `f(…)`.
                    Ast::Call(name, args)
                } else {
                    return Err(ParseError(
                        "only a name, a namespaced name, or a method can be called".to_string(),
                    ));
                };
                path = None;
                last_member = None;
                continue;
            }

            return Ok(node);
        }
    }

    fn expect_ident(&mut self, after: &str) -> Result<String, ParseError> {
        match self.peek().cloned() {
            Some(Tok::Ident(name)) => {
                self.i += 1;
                Ok(name)
            }
            // `in` and `contains` lex as identifiers, so they are legal member
            // names too — and a response field could plausibly be called
            // either.
            other => Err(ParseError(format!(
                "expected a name after {after}, found {other:?}"
            ))),
        }
    }

    fn parse_call_args(&mut self) -> Result<Vec<Ast>, ParseError> {
        let mut args = Vec::new();
        if self.eat(&Tok::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr()?);
            if self.eat(&Tok::Comma) {
                // A trailing comma before `)` is legal — the multi-line
                // `http.post(url, {…}, body,)` forms use one.
                if self.eat(&Tok::RParen) {
                    return Ok(args);
                }
                continue;
            }
            self.expect(&Tok::RParen)?;
            return Ok(args);
        }
    }

    fn parse_primary(&mut self) -> Result<Ast, ParseError> {
        match self.peek().cloned() {
            Some(Tok::Num(n)) => {
                self.i += 1;
                Ok(Ast::Num(n))
            }
            Some(Tok::Str(s)) => {
                self.i += 1;
                Ok(Ast::Str(s))
            }
            Some(Tok::True) => {
                self.i += 1;
                Ok(Ast::Bool(true))
            }
            Some(Tok::False) => {
                self.i += 1;
                Ok(Ast::Bool(false))
            }
            Some(Tok::Nil) => {
                self.i += 1;
                Ok(Ast::Nil)
            }
            Some(Tok::Hash) => {
                self.i += 1;
                Ok(Ast::Pointer)
            }
            // A `let` is an EXPRESSION, not only a program prefix: the
            // catalogue writes `let ts = …; (let sig = …; …)`, binding inside
            // parentheses and inside a ternary branch.
            Some(Tok::Let) => self.parse_program(),
            Some(Tok::LParen) => {
                self.i += 1;
                let inner = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                Ok(inner)
            }
            // `{ … }` is TWO constructs sharing a spelling: a map literal
            // (`{"Accept": "application/json"}`) and a predicate closure
            // (`{# not in public_acls}`). They are told apart by what follows
            // the first expression — a `:` means it was a key.
            Some(Tok::LBrace) => {
                self.i += 1;
                let mut entries = Vec::new();
                if self.eat(&Tok::RBrace) {
                    return Ok(Ast::Map(entries));
                }

                let first = self.parse_expr()?;
                if self.eat(&Tok::RBrace) {
                    return Ok(Ast::Closure(Box::new(first)));
                }
                self.expect(&Tok::Colon)?;
                let first_value = self.parse_expr()?;
                entries.push((first, first_value));
                if self.eat(&Tok::RBrace) {
                    return Ok(Ast::Map(entries));
                }
                self.expect(&Tok::Comma)?;
                if self.eat(&Tok::RBrace) {
                    return Ok(Ast::Map(entries));
                }

                loop {
                    let key = self.parse_expr()?;
                    self.expect(&Tok::Colon)?;
                    let value = self.parse_expr()?;
                    entries.push((key, value));
                    if self.eat(&Tok::Comma) {
                        if self.eat(&Tok::RBrace) {
                            break;
                        }
                        continue;
                    }
                    self.expect(&Tok::RBrace)?;
                    break;
                }
                Ok(Ast::Map(entries))
            }
            Some(Tok::LBracket) => {
                self.i += 1;
                let mut items = Vec::new();
                if !self.eat(&Tok::RBracket) {
                    loop {
                        items.push(self.parse_expr()?);
                        if self.eat(&Tok::Comma) {
                            // A trailing comma before `]` is legal — the
                            // catalogue's multi-line arrays use one.
                            if self.eat(&Tok::RBracket) {
                                break;
                            }
                            continue;
                        }
                        self.expect(&Tok::RBracket)?;
                        break;
                    }
                }
                Ok(Ast::Array(items))
            }
            Some(Tok::Ident(first)) => {
                self.i += 1;
                Ok(Ast::Ident(first))
            }
            other => Err(ParseError(format!("unexpected {other:?}"))),
        }
    }

    /// [`parse_primary`], additionally reporting the identifier spelling when
    /// the primary IS a bare identifier — the seed of the dotted-path
    /// bookkeeping in [`parse_postfix`].
    fn parse_primary_with_path(&mut self) -> Result<(Ast, Option<String>), ParseError> {
        if let Some(Tok::Ident(name)) = self.peek().cloned() {
            let node = self.parse_primary()?;
            return Ok((node, Some(name)));
        }
        Ok((self.parse_primary()?, None))
    }
}
