//! Dump every expression the shipped catalogue contains, so M10's grammar is
//! derived from the WHOLE corpus rather than a sample (PORT-PLAN open question
//! 4 explicitly calls that out).
//!
//! Emits one record per expression, `<kind>\t<rule-id>\t<expr>` with newlines
//! escaped, so the corpus can be tokenised and counted downstream.
//!
//!     cargo run -p config --example dump_exprs > exprs.tsv

fn main() {
    let c = config::default_config().expect("catalogue must parse");

    let mut n = 0usize;
    let mut emit = |kind: &str, id: &str, expr: &str| {
        if expr.trim().is_empty() {
            return;
        }
        println!("{kind}\t{id}\t{}", expr.replace('\n', "\\n"));
    };

    emit("prefilter", "<global>", &c.prefilter);
    emit("filter", "<global>", &c.filter);

    for id in &c.ordered_rules {
        let r = &c.rules[id];
        if !r.filter.trim().is_empty() {
            emit("filter", id, &r.filter);
            n += 1;
        }
        if !r.validate_expr.trim().is_empty() {
            emit("validate", id, &r.validate_expr);
        }
    }

    eprintln!("rule filters: {n}");
}
