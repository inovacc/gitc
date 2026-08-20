//! Every expectation here was PRINTED BY GO, not reasoned out.
//!
//! The generator was a standalone program holding a verbatim copy of
//! `cmd/root.go:669` `FormatDuration` plus `time.Duration.String()`, run once
//! and its table transcribed. Two of these values would have been guessed
//! wrong: `999.999µs` formats as `1ms` (the round crosses the unit boundary),
//! and `1h1m1.5s` formats as `1h1m2s` (three significant digits at the hour
//! scale is whole seconds).

use super::*;

/// Go `time.Duration.String()`, verbatim from the generator's output.
#[test]
fn duration_string_matches_go() {
    let cases: &[(Nanos, &str)] = &[
        (0, "0s"),
        (1, "1ns"),
        (999, "999ns"),
        // The unit is U+00B5 MICRO SIGN, not the Greek letter mu and not "us".
        (1_000, "1µs"),
        (1_500, "1.5µs"),
        (999_999, "999.999µs"),
        (1_000_000, "1ms"),
        (1_500_000, "1.5ms"),
        (368_000_000, "368ms"),
        (368_123_456, "368.123456ms"),
        (999_999_999, "999.999999ms"),
        (1_000_000_000, "1s"),
        (1_500_000_000, "1.5s"),
        (23_600_000_000, "23.6s"),
        (23_604_000_000, "23.604s"),
        // Whole minutes still print the seconds component.
        (60_000_000_000, "1m0s"),
        (61_000_000_000, "1m1s"),
        (90_000_000_000, "1m30s"),
        (3_599_000_000_000, "59m59s"),
        (3_600_000_000_000, "1h0m0s"),
        (3_661_500_000_000, "1h1m1.5s"),
        (-1, "-1ns"),
        (-368_000_000, "-368ms"),
        (-1_500_000_000, "-1.5s"),
        // Go stops at hours because days are not all the same length.
        (i64::MAX, "2562047h47m16.854775807s"),
        // i64::MIN has no positive counterpart; Go negates the UNSIGNED value,
        // which is why this does not overflow.
        (i64::MIN, "-2562047h47m16.854775808s"),
    ];
    for (ns, want) in cases {
        assert_eq!(&duration_string(*ns), want, "duration_string({ns})");
    }
}

/// Go `FormatDuration` — three significant digits, then `String()`.
#[test]
fn format_duration_matches_go() {
    let cases: &[(Nanos, &str)] = &[
        (0, "0s"),
        (1, "1ns"),
        (999, "999ns"),
        (1_000, "1µs"),
        (1_500, "1.5µs"),
        // Rounding crosses the unit boundary: 999.999µs becomes a millisecond.
        (999_999, "1ms"),
        (1_000_000, "1ms"),
        (1_500_000, "1.5ms"),
        (368_000_000, "368ms"),
        // The tail is dropped; this is the whole point of the function.
        (368_123_456, "368ms"),
        (999_999_999, "1s"),
        (1_000_000_000, "1s"),
        (1_500_000_000, "1.5s"),
        (23_600_000_000, "23.6s"),
        (23_604_000_000, "23.6s"),
        (60_000_000_000, "1m0s"),
        (90_000_000_000, "1m30s"),
        (3_600_000_000_000, "1h0m0s"),
        (3_661_500_000_000, "1h1m2s"),
    ];
    for (ns, want) in cases {
        assert_eq!(&format_duration(*ns), want, "format_duration({ns})");
    }
}

/// ⚠ DELIBERATE DIVERGENCE FROM GO — a fix, not a port slip.
///
/// Go's `FormatDuration` is `for scale > d { scale = scale / 10 }`. For a
/// NEGATIVE `d` the condition is always true, `scale` integer-divides down to
/// 0, and `0 / 10` is 0 forever: the function never returns. This is not
/// theoretical — it is what hung the golden-vector generator, which is how it
/// was found.
///
/// It is unreachable in betterleaks because the only caller passes
/// `time.Since(start)`, but a formatting helper that spins the CPU rather than
/// returning is not worth reproducing. The port bails out when the scale
/// reaches 0 and renders the duration unrounded.
#[test]
fn format_duration_terminates_on_a_negative_go_would_hang_on() {
    assert_eq!(format_duration(-1_500_000_000), "-1.5s");
    assert_eq!(format_duration(-368_000_000), "-368ms");
    assert_eq!(format_duration(-1), "-1ns");
}

/// Go's `Duration.Round` rounds half AWAY FROM ZERO, not to even.
#[test]
fn round_matches_go_semantics() {
    assert_eq!(round(1_500, 1_000), 2_000);
    assert_eq!(round(1_499, 1_000), 1_000);
    assert_eq!(round(-1_500, 1_000), -2_000);
    assert_eq!(round(-1_499, 1_000), -1_000);
    // A non-positive multiple is a no-op, which is what makes FormatDuration's
    // `scale / 100 == 0` case safe.
    assert_eq!(round(1_234, 0), 1_234);
    assert_eq!(round(1_234, -5), 1_234);
}

/// A `std::time::Duration` beyond Go's range must not wrap into a negative.
#[test]
fn from_std_saturates_rather_than_wrapping() {
    let huge = std::time::Duration::from_secs(u64::MAX / 2);
    assert_eq!(from_std(huge), i64::MAX);
    assert_eq!(from_std(std::time::Duration::from_millis(368)), 368_000_000);
}

/// The summary line the CLI prints. Rust's `{:.2?}` rendered these as
/// `368.00ms` and `23.60s`; Go renders them as below.
#[test]
fn the_scan_summary_line_reads_as_go_writes_it() {
    assert_eq!(format_std(std::time::Duration::from_millis(368)), "368ms");
    assert_eq!(format_std(std::time::Duration::from_millis(23_604)), "23.6s");
}
