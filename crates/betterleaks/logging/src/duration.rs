//! Go's `time.Duration` formatting — `String()`, `Round()`, and the
//! three-significant-digit `FormatDuration` wrapper from `cmd/root.go:669`.
//!
//! **Why this is a port and not `{:?}`.** Rust's `Debug for Duration` looks
//! similar and is not the same: it renders 23.6 seconds as `23.6s` only if you
//! ask for no precision, `{:.2?}` gives `23.60s`, and 368 ms comes out as
//! `368.00ms`. Go gives `23.6s` and `368ms`. The scan summary prints this on
//! every run, so the difference is visible in the very first line a user reads
//! and in every differential diff.
//!
//! Lives in `logging` because it is a leaf crate with no dependencies, and both
//! the CLI summary and the rule-timing diagnostics need it.
//!
//! Durations are held as **i64 nanoseconds**, which is what Go's
//! `time.Duration` is — including the ability to be negative, which
//! `std::time::Duration` cannot represent.

/// Go `time.Duration` — a signed nanosecond count.
pub type Nanos = i64;

pub const NANOSECOND: Nanos = 1;
pub const MICROSECOND: Nanos = 1_000;
pub const MILLISECOND: Nanos = 1_000_000;
pub const SECOND: Nanos = 1_000_000_000;

/// `std::time::Duration` → Go nanoseconds, saturating rather than wrapping.
///
/// Go's Duration tops out at ~292 years; a `std::time::Duration` can hold more.
/// Saturating keeps a nonsense input from printing as a negative time.
pub fn from_std(d: std::time::Duration) -> Nanos {
    let n = d.as_nanos();
    if n > i64::MAX as u128 {
        i64::MAX
    } else {
        n as i64
    }
}

/// Go `time.Duration.String()`.
///
/// A direct port of `fmtFrac`/`fmtInt` from `time/time.go`, filling a buffer
/// from the right. The odd shape is Go's, kept because the trailing-zero
/// elision rule (`fmtFrac`'s `print` latch) is exactly what makes `1.5s` print
/// as `1.5s` and not `1.500000000s` — reimplementing that "cleanly" is how the
/// formats drift apart.
pub fn duration_string(d: Nanos) -> String {
    // Go: `u = -u` on the unsigned value, so i64::MIN negates correctly.
    let neg = d < 0;
    let mut u = (d as i64).unsigned_abs();

    let mut buf = [0u8; 32];
    let mut w = buf.len();

    if u < SECOND as u64 {
        // Sub-second: pick the unit and a fractional precision to match.
        if u == 0 {
            return "0s".to_string();
        }
        w -= 1;
        buf[w] = b's';
        let prec;
        if u < MICROSECOND as u64 {
            prec = 0;
            w -= 1;
            buf[w] = b'n';
        } else if u < MILLISECOND as u64 {
            prec = 3;
            // U+00B5 MICRO SIGN, two bytes in UTF-8. Go writes the micro sign,
            // NOT the Greek letter mu, and not "us".
            w -= 2;
            buf[w] = 0xC2;
            buf[w + 1] = 0xB5;
        } else {
            prec = 6;
            w -= 1;
            buf[w] = b'm';
        }
        let (nw, nu) = fmt_frac(&mut buf, w, u, prec);
        w = fmt_int(&mut buf, nw, nu);
    } else {
        w -= 1;
        buf[w] = b's';

        let (nw, nu) = fmt_frac(&mut buf, w, u, 9);
        w = nw;
        u = nu;

        // u is now whole seconds.
        w = fmt_int(&mut buf, w, u % 60);
        u /= 60;

        if u > 0 {
            w -= 1;
            buf[w] = b'm';
            w = fmt_int(&mut buf, w, u % 60);
            u /= 60;

            // Go stops at hours: days are not all the same length.
            if u > 0 {
                w -= 1;
                buf[w] = b'h';
                w = fmt_int(&mut buf, w, u);
            }
        }
    }

    if neg {
        w -= 1;
        buf[w] = b'-';
    }

    String::from_utf8_lossy(&buf[w..]).into_owned()
}

/// Go `fmtFrac` — write the fraction, dropping trailing zeros AND the decimal
/// point when nothing was written. Returns the new write index and what is left
/// of the value.
fn fmt_frac(buf: &mut [u8; 32], mut w: usize, mut v: u64, prec: usize) -> (usize, u64) {
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            w -= 1;
            buf[w] = b'0' + digit as u8;
        }
        v /= 10;
    }
    if print {
        w -= 1;
        buf[w] = b'.';
    }
    (w, v)
}

/// Go `fmtInt`.
fn fmt_int(buf: &mut [u8; 32], mut w: usize, mut v: u64) -> usize {
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    w
}

/// Go `time.Duration.Round(m)` — round half AWAY FROM ZERO to a multiple of
/// `m`, saturating instead of overflowing.
pub fn round(d: Nanos, m: Nanos) -> Nanos {
    if m <= 0 {
        return d;
    }
    let mut r = d % m;
    if d < 0 {
        r = -r;
        if less_than_half(r, m) {
            return d + r;
        }
        let d1 = d.wrapping_sub(m).wrapping_add(r);
        if d1 < d {
            return d1;
        }
        return i64::MIN;
    }
    if less_than_half(r, m) {
        return d - r;
    }
    let d1 = d.wrapping_add(m).wrapping_sub(r);
    if d1 > d {
        return d1;
    }
    i64::MAX
}

/// Go `lessThanHalf` — `x+x < y` in UNSIGNED arithmetic, so the doubling
/// cannot overflow into a wrong answer.
fn less_than_half(x: Nanos, y: Nanos) -> bool {
    (x as u64).wrapping_add(x as u64) < y as u64
}

/// Go `cmd/root.go:669` `FormatDuration` — round to roughly three significant
/// digits, then render.
///
/// The loop walks the scale down from 100s until it is no larger than the
/// duration, then rounds to a hundredth of that scale. So 368 ms prints as
/// `368ms` and 23.6 s as `23.6s`, rather than a fixed number of decimals that
/// would be noise on one and lost precision on the other.
pub fn format_duration(d: Nanos) -> String {
    let mut scale = 100 * SECOND;
    while scale > d {
        scale /= 10;
        // Go's loop divides an int64 and would reach 0, at which point Round is
        // a no-op (`m <= 0`). Guard so the division below cannot trap.
        if scale == 0 {
            return duration_string(d);
        }
    }
    duration_string(round(d, scale / 100))
}

/// Convenience for the call sites that hold a `std::time::Duration`.
pub fn format_std(d: std::time::Duration) -> String {
    format_duration(from_std(d))
}

#[cfg(test)]
mod tests;
