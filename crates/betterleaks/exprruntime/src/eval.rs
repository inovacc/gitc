//! The evaluator: walks the AST against a [`Context`] and dispatches the filter
//! namespace plus expr's `len`/`min`/`max` builtins.

use crate::bindings_filter as bf;
use crate::parser::{ArithOp, Ast, CmpOp};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// A runtime value.
///
/// Go's `finding` is `map[string]any`, and the catalogue relies on it: the
/// generic-api-key filter reads `finding["match_start_idx"]` as a NUMBER and
/// `finding["secret"]` as a STRING in the same expression. So this cannot be a
/// string-only map.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<Value>),
    /// Go's `map[string]any`. Added for VALIDATION: request headers, the
    /// response object (`r.status` / `r.body` / `r.headers` / `r.json`), and
    /// the result object every validation expression returns are all maps.
    ///
    /// `BTreeMap` rather than `HashMap` so iteration is ordered — a validation
    /// result becomes finding metadata, and metadata that reorders between runs
    /// makes two identical scans produce different reports.
    Map(BTreeMap<String, Value>),
    /// Go's `[]byte`. The crypto bindings return raw digests and the encoders
    /// consume them, so this cannot be a `String` — an HMAC is binary and
    /// round-tripping it through UTF-8 would corrupt it.
    Bytes(Vec<u8>),
    /// Go's `nil` — what an absent map key yields.
    Nil,
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Num(_) => "number",
            Value::Str(_) => "string",
            Value::List(_) => "list",
            Value::Map(_) => "map",
            Value::Bytes(_) => "bytes",
            Value::Nil => "nil",
        }
    }

    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    fn as_str(&self) -> Result<&str, EvalError> {
        match self {
            Value::Str(s) => Ok(s),
            // A missing key on a Go map[string]string yields "", so nil degrades
            // to the empty string rather than erroring.
            Value::Nil => Ok(""),
            other => Err(EvalError::Type(format!(
                "expected string, found {}",
                other.type_name()
            ))),
        }
    }

    fn as_num(&self) -> Result<f64, EvalError> {
        match self {
            Value::Num(n) => Ok(*n),
            // Go's numeric zero value for an absent key.
            Value::Nil => Ok(0.0),
            other => Err(EvalError::Type(format!(
                "expected number, found {}",
                other.type_name()
            ))),
        }
    }

    fn as_bool(&self) -> Result<bool, EvalError> {
        match self {
            Value::Bool(b) => Ok(*b),
            other => Err(EvalError::Type(format!(
                "expected bool, found {}",
                other.type_name()
            ))),
        }
    }

    /// Mirrors Go's `toStringSlice`, which returns nil for the WHOLE slice when
    /// any element is not a string — the callers then treat that as "no
    /// patterns" and answer false.
    fn as_string_list(&self) -> Vec<String> {
        match self {
            Value::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    match it {
                        Value::Str(s) => out.push(s.clone()),
                        _ => return Vec::new(),
                    }
                }
                out
            }
            Value::Str(s) => vec![s.clone()],
            _ => Vec::new(),
        }
    }
}

/// The evaluation environment.
pub struct Context<'a> {
    /// Go `attributes` — `map[string]string` of source metadata.
    pub attributes: BTreeMap<String, String>,
    /// Go `finding` — `map[string]any`, so values are typed.
    pub finding: BTreeMap<String, Value>,
    /// Go's `tokenizerProvider`, which MAY be nil — then `tokenRatio` is 0 and
    /// `failsTokenEfficiency` is false.
    pub tokenizer: Option<&'a dyn bf::Tokenizer>,
    /// The validation environment — HTTP client, env allowlist, clock. `None`
    /// for a FILTER expression, which is what lets a validation-only function
    /// called from a filter say exactly that rather than fail obscurely.
    pub validation: Option<&'a crate::bindings_validation::ValidationEnv<'a>>,
    /// Go `components` — other rules' matches that contribute to this one.
    pub components: BTreeMap<String, Value>,
    /// Go `captures` — named regex capture groups.
    pub captures: BTreeMap<String, String>,
    /// `let`-bound locals, innermost last.
    scope: Vec<(String, Value)>,
}

impl<'a> Context<'a> {
    pub fn new() -> Context<'a> {
        Context {
            attributes: BTreeMap::new(),
            finding: BTreeMap::new(),
            tokenizer: None,
            validation: None,
            components: BTreeMap::new(),
            captures: BTreeMap::new(),
            scope: Vec::new(),
        }
    }

    /// The overwhelmingly common case: one secret to judge.
    pub fn with_secret(secret: &str) -> Context<'a> {
        let mut c = Context::new();
        c.finding.insert("secret".to_string(), Value::str(secret));
        c
    }

    /// Set a `finding` entry.
    pub fn set_finding(&mut self, key: &str, v: Value) -> &mut Self {
        self.finding.insert(key.to_string(), v);
        self
    }

    fn lookup(&self, name: &str) -> Option<&Value> {
        self.scope.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

impl Default for Context<'_> {
    fn default() -> Self {
        Context::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvalError {
    UnknownIdent(String),
    UnknownFunction(String),
    Arity { name: String, want: usize, got: usize },
    Type(String),
    /// `expr.AsBool()` — the program did not produce a bool.
    NotBoolean(String),
    /// The per-target request budget refused the call. Distinct from every
    /// other error because it means `needs_validation`, not `error`.
    ///
    /// BOXED. EvalError is the error half of every Result the evaluator
    /// returns, and the evaluator is deeply recursive; inlining a 64-byte
    /// payload here widened every frame in that recursion for a case that
    /// happens at most once per finding.
    ValidationLimit(Box<crate::validation_limits::ValidationRequestLimitHit>),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::UnknownIdent(n) => write!(f, "unknown identifier {n:?}"),
            EvalError::UnknownFunction(n) => write!(f, "unknown function {n:?}"),
            EvalError::Arity { name, want, got } => {
                write!(f, "{name}: expected {want} argument(s), got {got}")
            }
            EvalError::Type(m) => write!(f, "{m}"),
            EvalError::NotBoolean(t) => write!(f, "expression must evaluate to bool, got {t}"),
            EvalError::ValidationLimit(h) => write!(f, "{h}"),
        }
    }
}

impl Error for EvalError {}

pub fn eval(ast: &Ast, ctx: &mut Context) -> Result<Value, EvalError> {
    match ast {
        Ast::Num(n) => Ok(Value::Num(*n)),
        Ast::Str(s) => Ok(Value::Str(s.clone())),
        Ast::Bool(b) => Ok(Value::Bool(*b)),

        Ast::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(it, ctx)?);
            }
            Ok(Value::List(out))
        }

        Ast::Let { name, value, body } => {
            let v = eval(value, ctx)?;
            // `let _ = …` keeps the side effect and discards the binding, which
            // is how the catalogue calls filter.setConfidence.
            ctx.scope.push((name.clone(), v));
            let out = eval(body, ctx);
            ctx.scope.pop();
            out
        }

        Ast::Nil => Ok(Value::Nil),

        // `a?.[k]` - nil rather than an error at every step, so a partial
        // JSON response degrades to a default instead of failing the whole
        // validation.
        Ast::OptIndex(base, key) => {
            let b = eval(base, ctx)?;
            let k = eval(key, ctx)?;
            Ok(match b {
                Value::Map(m) => match &k {
                    Value::Str(s) => m.get(s).cloned().unwrap_or(Value::Nil),
                    _ => Value::Nil,
                },
                Value::List(items) => match &k {
                    Value::Num(n) if *n >= 0.0 && (*n as usize) < items.len() => {
                        items[*n as usize].clone()
                    }
                    _ => Value::Nil,
                },
                _ => Value::Nil,
            })
        }

        // `#` resolves to whatever the enclosing predicate bound it to. Outside
        // a closure it is an error rather than nil, because a stray `#` means
        // the expression is not what its author thought.
        Ast::Pointer => match ctx.lookup("#") {
            Some(v) => Ok(v.clone()),
            None => Err(EvalError::UnknownIdent("#".to_string())),
        },

        // A closure is only meaningful as an argument to a predicate builtin,
        // which evaluates its body per element. Reaching here means it was used
        // as an ordinary value.
        Ast::Closure(_) => Err(EvalError::Type(
            "a predicate closure can only be passed to a predicate function".to_string(),
        )),

        Ast::Map(entries) => {
            let mut out = BTreeMap::new();
            for (k, v) in entries {
                let key = eval(k, ctx)?;
                let value = eval(v, ctx)?;
                out.insert(key.as_str()?.to_string(), value);
            }
            Ok(Value::Map(out))
        }

        // `base.name` / `base?.name`.
        //
        // Without the `?`, a missing member is an ERROR: an expression reading
        // `r.stauts` should say so rather than silently comparing nil to 200
        // and reporting every secret as unvalidated.
        Ast::Member(base, name, optional) => {
            let b = eval(base, ctx)?;
            match b {
                Value::Map(m) => match m.get(name) {
                    Some(v) => Ok(v.clone()),
                    None if *optional => Ok(Value::Nil),
                    None => Err(EvalError::Type(format!("no member {name:?} on map"))),
                },
                Value::Nil if *optional => Ok(Value::Nil),
                other => {
                    if *optional {
                        Ok(Value::Nil)
                    } else {
                        Err(EvalError::Type(format!(
                            "cannot read member {name:?} of {}",
                            other.type_name()
                        )))
                    }
                }
            }
        }

        Ast::Coalesce(lhs, rhs) => {
            let l = eval(lhs, ctx)?;
            if l == Value::Nil {
                return eval(rhs, ctx);
            }
            Ok(l)
        }

        // `x in [a, b]`. Also accepts a map (key membership) and a string
        // (substring), which is what expr-lang's `in` does.
        Ast::In(needle, haystack) => {
            let n = eval(needle, ctx)?;
            let h = eval(haystack, ctx)?;
            Ok(Value::Bool(match h {
                Value::List(items) => items.iter().any(|it| *it == n),
                Value::Map(m) => m.contains_key(n.as_str()?),
                Value::Str(s) => s.contains(n.as_str()?),
                Value::Nil => false,
                other => {
                    return Err(EvalError::Type(format!(
                        "cannot use `in` on {}",
                        other.type_name()
                    )))
                }
            }))
        }

        // `haystack contains needle`. A nil haystack is false rather than an
        // error — a response with no body must not blow up the expression.
        Ast::Contains(haystack, needle) => {
            let h = eval(haystack, ctx)?;
            let n = eval(needle, ctx)?;
            Ok(Value::Bool(match h {
                Value::Str(s) => s.contains(n.as_str()?),
                Value::List(items) => items.iter().any(|it| *it == n),
                Value::Nil => false,
                other => {
                    return Err(EvalError::Type(format!(
                        "cannot use `contains` on {}",
                        other.type_name()
                    )))
                }
            }))
        }

        Ast::Ident(name) => match ctx.lookup(name) {
            Some(v) => Ok(v.clone()),
            // A bare `finding`/`attributes` is only meaningful as an index base,
            // which Index/Slice handle directly.
            None => Err(EvalError::UnknownIdent(name.clone())),
        },

        Ast::Index(base, key) => {
            let k = eval(key, ctx)?;
            match base.as_ref() {
                Ast::Ident(n) if n == "finding" && ctx.lookup(n).is_none() => {
                    Ok(ctx.finding.get(k.as_str()?).cloned().unwrap_or(Value::Nil))
                }
                Ast::Ident(n) if n == "attributes" && ctx.lookup(n).is_none() => Ok(ctx
                    .attributes
                    .get(k.as_str()?)
                    .map(|v| Value::Str(v.clone()))
                    .unwrap_or(Value::Nil)),
                // Validation-only bases. A component that did not match yields
                // nil, which `?.secret ?? ""` is written to absorb — the rule
                // still runs, it just builds a URL that will fail honestly.
                Ast::Ident(n) if n == "components" && ctx.lookup(n).is_none() => {
                    Ok(ctx.components.get(k.as_str()?).cloned().unwrap_or(Value::Nil))
                }
                Ast::Ident(n) if n == "captures" && ctx.lookup(n).is_none() => Ok(ctx
                    .captures
                    .get(k.as_str()?)
                    .map(|v| Value::Str(v.clone()))
                    .unwrap_or(Value::Nil)),
                _ => {
                    let b = eval(base, ctx)?;
                    match b {
                        Value::List(items) => {
                            let i = k.as_num()? as isize;
                            if i < 0 || i as usize >= items.len() {
                                return Ok(Value::Nil);
                            }
                            Ok(items[i as usize].clone())
                        }
                        // A missing key yields nil, as it does on a Go map —
                        // NOT an error, because `r.headers["x-foo"]` on a
                        // response without that header is an ordinary case.
                        Value::Map(m) => {
                            Ok(m.get(k.as_str()?).cloned().unwrap_or(Value::Nil))
                        }
                        other => Err(EvalError::Type(format!(
                            "{} is not indexable",
                            other.type_name()
                        ))),
                    }
                }
            }
        }

        Ast::Slice(base, lo, hi) => {
            let b = eval(base, ctx)?;
            let lo = eval(lo, ctx)?.as_num()?;
            let hi = eval(hi, ctx)?.as_num()?;
            let s = b.as_str()?;
            Ok(Value::Str(slice_bytes(s, lo, hi)))
        }

        Ast::Not(inner) => Ok(Value::Bool(!eval(inner, ctx)?.as_bool()?)),
        Ast::Neg(inner) => Ok(Value::Num(-eval(inner, ctx)?.as_num()?)),

        // Short-circuit, as expr does.
        Ast::And(a, b) => {
            if !eval(a, ctx)?.as_bool()? {
                return Ok(Value::Bool(false));
            }
            Ok(Value::Bool(eval(b, ctx)?.as_bool()?))
        }
        Ast::Or(a, b) => {
            if eval(a, ctx)?.as_bool()? {
                return Ok(Value::Bool(true));
            }
            Ok(Value::Bool(eval(b, ctx)?.as_bool()?))
        }

        Ast::Ternary(c, t, e) => {
            if eval(c, ctx)?.as_bool()? {
                eval(t, ctx)
            } else {
                eval(e, ctx)
            }
        }

        Ast::Cmp(a, op, b) => {
            let l = eval(a, ctx)?;
            let r = eval(b, ctx)?;
            let res = match op {
                CmpOp::Eq => values_equal(&l, &r),
                CmpOp::Ne => !values_equal(&l, &r),
                CmpOp::Lt => l.as_num()? < r.as_num()?,
                CmpOp::Le => l.as_num()? <= r.as_num()?,
                CmpOp::Gt => l.as_num()? > r.as_num()?,
                CmpOp::Ge => l.as_num()? >= r.as_num()?,
            };
            Ok(Value::Bool(res))
        }

        Ast::Arith(a, op, b) => {
            let l = eval(a, ctx)?;
            let r = eval(b, ctx)?;
            // expr's `+` concatenates strings as well as adding numbers.
            if matches!(op, ArithOp::Add) {
                if let (Value::Str(x), Value::Str(y)) = (&l, &r) {
                    return Ok(Value::Str(format!("{x}{y}")));
                }
            }
            let (x, y) = (l.as_num()?, r.as_num()?);
            Ok(Value::Num(match op {
                ArithOp::Add => x + y,
                ArithOp::Sub => x - y,
                ArithOp::Mul => x * y,
                ArithOp::Div => x / y,
            }))
        }

        Ast::Call(name, args) => call(name, args, ctx),
    }
}

/// Names owned by the validation half. Listed rather than pattern-matched on a
/// dot, so a typo like `htp.get` still reaches the normal unknown-function
/// error with its own name in it.
fn is_validation_name(name: &str) -> bool {
    crate::bindings_validation::is_validation_function(name)
}

/// `any(list, {predicate})` and friends.
///
/// The second argument is a CLOSURE and must not be evaluated as a value: the
/// body runs once per element with `#` bound to it. Exactly one shipped rule
/// uses this, and without it that rule cannot validate at all.
fn predicate_call(
    short: &str,
    name: &str,
    args: &[Ast],
    ctx: &mut Context,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::Arity {
            name: name.to_string(),
            want: 2,
            got: args.len(),
        });
    }
    let list = match eval(&args[0], ctx)? {
        Value::List(items) => items,
        // A nil list is empty, not an error — `r.json?.acl ?? []` can yield
        // either, and both must behave the same.
        Value::Nil => Vec::new(),
        other => {
            return Err(EvalError::Type(format!(
                "{name}: expected a list, found {}",
                other.type_name()
            )))
        }
    };
    let Ast::Closure(body) = &args[1] else {
        return Err(EvalError::Type(format!(
            "{name}: the second argument must be a predicate closure"
        )));
    };

    let mut hits = 0usize;
    for item in &list {
        ctx.scope.push(("#".to_string(), item.clone()));
        let verdict = eval(body, ctx);
        ctx.scope.pop();
        if verdict?.as_bool()? {
            hits += 1;
            // `any` can stop at the first hit; the others need the full count.
            if short == "any" {
                break;
            }
        }
    }

    Ok(Value::Bool(match short {
        "any" => hits > 0,
        "all" => hits == list.len(),
        "one" => hits == 1,
        "none" => hits == 0,
        _ => unreachable!("guarded by the caller"),
    }))
}

/// Go string slicing is by BYTE offsets and clamps nothing — but a Rust `&str`
/// slice panics on an out-of-range or mid-rune boundary. Clamp, and fall back to
/// a lossy conversion if a boundary splits a character, so a filter can never
/// panic the scanner.
fn slice_bytes(s: &str, lo: f64, hi: f64) -> String {
    let b = s.as_bytes();
    let n = b.len() as f64;
    let lo = lo.max(0.0).min(n) as usize;
    let hi = hi.max(lo as f64).min(n) as usize;
    String::from_utf8_lossy(&b[lo..hi]).into_owned()
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        // A missing key compares equal to "", matching Go's zero value.
        (Value::Nil, Value::Str(s)) | (Value::Str(s), Value::Nil) => s.is_empty(),
        (Value::Nil, Value::Num(n)) | (Value::Num(n), Value::Nil) => *n == 0.0,
        _ => a == b,
    }
}

fn call(name: &str, args: &[Ast], ctx: &mut Context) -> Result<Value, EvalError> {
    // The filter namespace is reachable bare AND under `filter.` — the catalogue
    // uses both spellings for the same function.
    let short = name.strip_prefix("filter.").unwrap_or(name);

    // `any(list, {predicate})` is handled BEFORE the others because its second
    // argument is a closure, which must not be evaluated as a value.
    if short == "any" || short == "all" || short == "one" || short == "none" {
        return predicate_call(short, name, args, ctx);
    }

    // The validation namespaces take EVALUATED arguments, so they are dispatched
    // here rather than inside the big match — which keeps the two halves of the
    // language (filter and validation) from growing into each other.
    if is_validation_name(short) || crate::bindings_cloud::is_cloud_name(short) {
        let mut values = Vec::with_capacity(args.len());
        for a in args {
            values.push(eval(a, ctx)?);
        }
        if let Some(v) = crate::bindings_validation::call_validation(short, &values, ctx.validation)?
        {
            return Ok(v);
        }
        // The cloud signers are separated from the plain bindings because they
        // BUILD a signed request rather than forwarding one, and they pull in
        // the only asymmetric crypto in the workspace.
        if let Some(v) = crate::bindings_cloud::call_cloud(short, &values, ctx.validation)? {
            return Ok(v);
        }
    }

    macro_rules! want {
        ($n:expr) => {
            if args.len() != $n {
                return Err(EvalError::Arity {
                    name: name.to_string(),
                    want: $n,
                    got: args.len(),
                });
            }
        };
    }

    match short {
        // ── validation-only builtins (runtime.go validationBindings) ────────
        //
        // These take ordinary evaluated arguments, so they live with the rest
        // rather than in the namespace dispatch above.
        "bytes" => {
            want!(1);
            let v = eval(&args[0], ctx)?;
            Ok(Value::Bytes(match v {
                Value::Bytes(b) => b,
                other => crate::bindings_validation::display(&other).into_bytes(),
            }))
        }
        // Go `size` — length of a string (BYTES), list or map.
        "size" => {
            want!(1);
            Ok(Value::Num(match eval(&args[0], ctx)? {
                Value::Str(s) => s.len() as f64,
                Value::Bytes(b) => b.len() as f64,
                Value::List(l) => l.len() as f64,
                Value::Map(m) => m.len() as f64,
                Value::Nil => 0.0,
                other => {
                    return Err(EvalError::Type(format!(
                        "size: {} has no size",
                        other.type_name()
                    )))
                }
            }))
        }
        // Go `strings.ReplaceAll` — every occurrence, not the first.
        "replace" => {
            want!(3);
            let s = crate::bindings_validation::display(&eval(&args[0], ctx)?);
            let old = crate::bindings_validation::display(&eval(&args[1], ctx)?);
            let new = crate::bindings_validation::display(&eval(&args[2], ctx)?);
            Ok(Value::Str(s.replace(&old, &new)))
        }
        "split" => {
            want!(2);
            let s = crate::bindings_validation::display(&eval(&args[0], ctx)?);
            let sep = crate::bindings_validation::display(&eval(&args[1], ctx)?);
            Ok(Value::List(
                s.split(&sep as &str).map(Value::str).collect(),
            ))
        }
        // Go `substring(s, start, end)` by BYTE offsets, clamped — the same
        // clamping as the slice operator, and for the same reason: a filter
        // must never panic the scanner.
        "substring" => {
            want!(3);
            let s = crate::bindings_validation::display(&eval(&args[0], ctx)?);
            let lo = eval(&args[1], ctx)?.as_num()?;
            let hi = eval(&args[2], ctx)?.as_num()?;
            Ok(Value::Str(slice_bytes(&s, lo, hi)))
        }
        // Go `strings.LastIndex` — a BYTE offset, and -1 when absent.
        "lastIndexOf" => {
            want!(2);
            let s = crate::bindings_validation::display(&eval(&args[0], ctx)?);
            let sub = crate::bindings_validation::display(&eval(&args[1], ctx)?);
            Ok(Value::Num(match s.rfind(&sub as &str) {
                Some(i) => i as f64,
                None => -1.0,
            }))
        }
        // The CALL form of `contains`, distinct from the operator.
        "contains" => {
            want!(2);
            let hay = eval(&args[0], ctx)?;
            let needle = crate::bindings_validation::display(&eval(&args[1], ctx)?);
            Ok(Value::Bool(match hay {
                Value::Str(s) => s.contains(&needle as &str),
                Value::List(items) => items
                    .iter()
                    .any(|i| crate::bindings_validation::display(i) == needle),
                Value::Nil => false,
                other => {
                    return Err(EvalError::Type(format!(
                        "contains: cannot search {}",
                        other.type_name()
                    )))
                }
            }))
        }

        // ── expr builtins ───────────────────────────────────────────────
        "len" => {
            want!(1);
            let v = eval(&args[0], ctx)?;
            Ok(Value::Num(match v {
                // Go's len() on a string counts BYTES.
                Value::Str(s) => s.len() as f64,
                Value::List(l) => l.len() as f64,
                Value::Nil => 0.0,
                other => {
                    return Err(EvalError::Type(format!("len: {} has no length", other.type_name())))
                }
            }))
        }
        "min" | "max" => {
            if args.is_empty() {
                return Err(EvalError::Arity { name: name.to_string(), want: 1, got: 0 });
            }
            let mut acc = eval(&args[0], ctx)?.as_num()?;
            for a in &args[1..] {
                let v = eval(a, ctx)?.as_num()?;
                acc = if short == "min" { acc.min(v) } else { acc.max(v) };
            }
            Ok(Value::Num(acc))
        }

        // ── filter namespace ────────────────────────────────────────────
        "entropy" => {
            want!(1);
            let v = eval(&args[0], ctx)?;
            Ok(Value::Num(bf::shannon_entropy(v.as_str()?)))
        }
        "matchesAny" => {
            want!(2);
            let s = eval(&args[0], ctx)?;
            let s = s.as_str()?.to_string();
            let pats = eval(&args[1], ctx)?.as_string_list();
            Ok(Value::Bool(bf::matches_any(&s, &pats)))
        }
        "containsAny" => {
            want!(2);
            let s = eval(&args[0], ctx)?;
            let s = s.as_str()?.to_string();
            let terms = eval(&args[1], ctx)?.as_string_list();
            Ok(Value::Bool(bf::contains_any(&s, &terms)))
        }
        "findMatch" => {
            want!(2);
            let s = eval(&args[0], ctx)?;
            let s = s.as_str()?.to_string();
            let p = eval(&args[1], ctx)?;
            let p = p.as_str()?.to_string();
            Ok(Value::Str(bf::find_match(&s, &p)))
        }
        "tokenRatio" => {
            want!(1);
            let v = eval(&args[0], ctx)?;
            let s = v.as_str()?.to_string();
            match ctx.tokenizer {
                None => Ok(Value::Num(0.0)), // Go: nil tokenizer → 0
                Some(tk) => {
                    let (_, ratio, _) = bf::calculate_token_ratio(tk, &s);
                    Ok(Value::Num(ratio))
                }
            }
        }
        "failsTokenEfficiency" => {
            want!(1);
            let v = eval(&args[0], ctx)?;
            let s = v.as_str()?.to_string();
            match ctx.tokenizer {
                None => Ok(Value::Bool(false)), // Go: nil tokenizer → false
                Some(tk) => Ok(Value::Bool(bf::fails_token_efficiency(tk, &s))),
            }
        }
        "setConfidence" => {
            want!(1);
            let v = eval(&args[0], ctx)?;
            let s = v.as_str()?.to_string();
            bf::set_confidence(&mut ctx.attributes, &s)
                .map(Value::Str)
                .map_err(EvalError::Type)
        }
        _ => Err(EvalError::UnknownFunction(name.to_string())),
    }
}
