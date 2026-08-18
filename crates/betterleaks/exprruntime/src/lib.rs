//! Port of Go `internal/exprruntime` — the expression language betterleaks
//! filters and validates with, both halves.
//!
//! ## Why this is hand-written rather than a crate
//!
//! Go binds `expr-lang/expr`. No Rust equivalent exists: `cel-rust` is a
//! DIFFERENT language, and `celcompat.go` shows CEL is the *legacy input*
//! betterleaks rewrites INTO expr, not the target. Porting a general-purpose
//! expression language would be enormous — and unnecessary, because the filter
//! surface is tiny.
//!
//! ## The grammar, derived from the whole corpus
//!
//! PORT-PLAN open question 4 required deriving this from all 367
//! filter/prefilter expressions rather than a sample. Doing so found:
//!
//! | Construct | Uses |
//! |---|---|
//! | `finding["secret"]` | 486 |
//! | `entropy(…)` / `filter.entropy(…)` | 211 / 149 |
//! | `filter.tokenRatio(…)` | 121 |
//! | `<` `<=` `>=` comparisons | ~480 |
//! | `\|\|` | 122 |
//! | `matchesAny` / `filter.matchesAny` | 3 / 2 |
//! | `containsAny` | 1 |
//! | `attributes["path"]` | 1 (the global prefilter) |
//!
//! Notably **absent** from the shipped catalogue: `&&`, `!`, `==`, `!=`,
//! ternaries, `let`, `in`, and arithmetic. Those that are part of expr-lang
//! (`&&`, `!`, `==`, `!=`) are implemented anyway — a user config may use them,
//! and rejecting a valid config would be a defect, not restraint.
//!
//! ## The validation half is here too
//!
//! `bindings_validation`, `bindings_cloud` and `validation_limits` carry the
//! other half of the language: the 186 `validate` expressions, their http /
//! crypto / encoding / time / env namespaces, the AWS, Azure and GCP request
//! signers, and the outbound-request governor. All 186 parse and run; the
//! grammar they need was derived the same way the filter grammar was, by
//! compiling every one of them rather than a sample.
//!
//! Validation stays OFF by default, as upstream (`detect.go:39-41`: "Zero value
//! means validation is disabled").

pub mod celcompat;
pub mod obfuscate;
pub mod bindings_cloud;
pub mod bindings_validation;
pub mod validation_limits;
mod bindings_filter;
mod eval;
mod lexer;
mod parser;

pub use bindings_filter::{
    calculate_token_ratio, contains_any, fails_token_efficiency, find_match, matches_any,
    set_confidence, shannon_entropy, Tokenizer,
};
pub use eval::{Context, EvalError, Value};
pub use parser::{Ast, CmpOp, ParseError};

use std::sync::Arc;

/// Go `exprruntime.Program` — a compiled expression.
///
/// Compilation is eager here (the AST is built once), matching Go's
/// `expr.Compile`; only the ENGINE-level regex compilation inside the bindings
/// stays lazy and cached.
#[derive(Debug, Clone)]
pub struct Program {
    src: String,
    ast: Arc<Ast>,
}

impl Program {
    /// The original expression text.
    pub fn source(&self) -> &str {
        &self.src
    }

    pub fn ast(&self) -> &Ast {
        &self.ast
    }
}

/// Go `expr.Compile(src, expr.AsBool())` — parse and pin the boolean contract.
///
/// An empty or whitespace-only expression compiles to `None`, mirroring Go's
/// treatment of an absent filter as "no filter" rather than an error.
pub fn compile(src: &str) -> Result<Option<Program>, ParseError> {
    if src.trim().is_empty() {
        return Ok(None);
    }

    // CEL-shaped configs are rewritten BEFORE parsing, as Go does. The check
    // comes first so an expression already in expr syntax is never touched —
    // a rewrite that runs unnecessarily is a chance to change a meaning.
    let text = if celcompat::needs_cel_compat(src) {
        match celcompat::rewrite_cel_compat(src) {
            Ok(rewritten) => rewritten,
            // A rewrite that fails names itself and the ORIGINAL is parsed
            // anyway: the config may simply contain a `.contains(` this
            // narrow rewriter cannot place, and the parse error that follows
            // is more useful than the rewriter's.
            Err(e) => {
                logging::warn()
                    .str("expression", src)
                    .msg(&format!("CEL compatibility rewrite failed: {e}"));
                src.to_string()
            }
        }
    } else {
        src.to_string()
    };

    let ast = parser::parse(&text).map_err(|e| {
        // Report BOTH spellings when they differ, which is Go's behaviour and
        // the only way an author can see what was actually parsed.
        if text != src {
            ParseError(format!(
                "{}\noriginal expression:\n{src}\ncompat expression:\n{text}",
                e.0
            ))
        } else {
            e
        }
    })?;

    Ok(Some(Program {
        // The ORIGINAL text is kept: it is what the user wrote and what any
        // diagnostic should quote back.
        src: src.to_string(),
        ast: Arc::new(ast),
    }))
}

/// Every function name this engine knows, in either half of the language.
///
/// Used by [`check_functions`] to catch a typo'd or unsupported call at CONFIG
/// CHECK time. The evaluator resolves names when it reaches them, which is fine
/// for a filter — it runs on the first fragment — but useless for a `validate`
/// expression, which must not be executed just to find out whether it is
/// spelled correctly.
pub fn known_function(name: &str) -> bool {
    // `filter.` is an alias prefix for the filter builtins.
    let short = name.strip_prefix("filter.").unwrap_or(name);
    matches!(
        short,
        // expr builtins
        "len" | "min" | "max" | "any" | "all" | "one" | "none"
        // filter namespace
        | "matchesAny" | "containsAny" | "entropy" | "tokenRatio"
        | "failsTokenEfficiency" | "setConfidence" | "findMatch" | "get"
        // validation-only builtins
        | "bytes" | "size" | "replace" | "split" | "substring" | "lastIndexOf"
        | "contains"
    ) || crate::bindings_validation::is_validation_function(short)
        || crate::bindings_cloud::is_cloud_name(short)
}

/// Walk a compiled program and report the first call to a function this engine
/// does not have.
///
/// This is what makes `config check` mean something for a `validate`
/// expression. Without it, a typo in one of the 186 shipped validation
/// expressions — or in a user's own — is invisible until a scan actually
/// reaches that rule with `--validation` on, and then it surfaces as a finding
/// with `status: error` rather than as a config problem.
pub fn check_functions(p: &Program) -> Result<(), String> {
    fn walk(ast: &Ast, out: &mut Option<String>) {
        if out.is_some() {
            return;
        }
        match ast {
            Ast::Call(name, args) => {
                if !known_function(name) {
                    *out = Some(name.clone());
                    return;
                }
                for a in args {
                    walk(a, out);
                }
            }
            Ast::Array(items) => items.iter().for_each(|a| walk(a, out)),
            Ast::Map(entries) => entries.iter().for_each(|(k, v)| {
                walk(k, out);
                walk(v, out);
            }),
            Ast::Index(a, b)
            | Ast::OptIndex(a, b)
            | Ast::And(a, b)
            | Ast::Or(a, b)
            | Ast::Coalesce(a, b)
            | Ast::In(a, b)
            | Ast::Contains(a, b) => {
                walk(a, out);
                walk(b, out);
            }
            Ast::Slice(a, b, c) | Ast::Ternary(a, b, c) => {
                walk(a, out);
                walk(b, out);
                walk(c, out);
            }
            Ast::Cmp(a, _, b) | Ast::Arith(a, _, b) => {
                walk(a, out);
                walk(b, out);
            }
            Ast::Not(a) | Ast::Neg(a) | Ast::Member(a, _, _) | Ast::Closure(a) => walk(a, out),
            Ast::Let { value, body, .. } => {
                walk(value, out);
                walk(body, out);
            }
            Ast::Num(_) | Ast::Str(_) | Ast::Bool(_) | Ast::Ident(_) | Ast::Nil | Ast::Pointer => {}
        }
    }

    let mut unknown = None;
    walk(&p.ast, &mut unknown);
    match unknown {
        Some(name) => Err(format!("unknown name {name}")),
        None => Ok(()),
    }
}

/// Go `EvalValidationWithComponents` — run a `validate` expression and return
/// whatever it produced.
///
/// Unlike a filter, a validation expression does NOT return a bool: it returns
/// a map like `{"result": "valid"}`, which the caller interprets. Forcing a
/// bool here is what would lose the reason.
pub fn eval_validation(p: &Program, ctx: &mut Context) -> Result<eval::Value, EvalError> {
    eval::eval(&p.ast, ctx)
}

/// Evaluate a compiled program to a bool.
///
/// Go's `expr.AsBool()` makes a non-boolean result a compile-time error; this
/// port enforces it at eval time instead (the AST alone cannot know a binding's
/// return type), reporting [`EvalError::NotBoolean`].
pub fn eval_bool(p: &Program, ctx: &mut Context) -> Result<bool, EvalError> {
    match eval::eval(&p.ast, ctx)? {
        Value::Bool(b) => Ok(b),
        other => Err(EvalError::NotBoolean(other.type_name().to_string())),
    }
}

#[cfg(test)]
mod tests;
