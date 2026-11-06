//! Pure-Rust port of libalpm's version comparison (`alpm_pkg_vercmp`),
//! i.e. what `vercmp` and pacman itself use to order `[epoch:]pkgver[-pkgrel]`.

use std::cmp::Ordering;

/// Compare two full pacman versions (`[epoch:]pkgver[-pkgrel]`).
pub fn vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (e1, v1, r1) = parse_evr(a);
    let (e2, v2, r2) = parse_evr(b);

    let mut ret = rpmvercmp(e1, e2);
    if ret == Ordering::Equal {
        ret = rpmvercmp(v1, v2);
        if ret == Ordering::Equal {
            if let (Some(r1), Some(r2)) = (r1, r2) {
                ret = rpmvercmp(r1, r2);
            }
        }
    }
    ret
}

/// Split `[epoch:]version[-release]` exactly like libalpm's `parseEVR`.
fn parse_evr(evr: &str) -> (&str, &str, Option<&str>) {
    let bytes = evr.as_bytes();
    let mut s = 0;
    while s < bytes.len() && bytes[s].is_ascii_digit() {
        s += 1;
    }
    let (epoch, rest_start) = if s < bytes.len() && bytes[s] == b':' {
        let epoch = &evr[..s];
        (if epoch.is_empty() { "0" } else { epoch }, s + 1)
    } else {
        ("0", 0)
    };
    // The release separator is searched only after the epoch digits.
    match evr[s..].rfind('-').map(|i| i + s) {
        Some(dash) if dash >= rest_start => (epoch, &evr[rest_start..dash], Some(&evr[dash + 1..])),
        _ => (epoch, &evr[rest_start..], None),
    }
}

/// Port of rpmvercmp() from libalpm/version.c.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (mut one, mut two) = (0usize, 0usize);
    let (mut ptr1, mut ptr2) = (0usize, 0usize);
    let at = |s: &[u8], i: usize| -> u8 { s.get(i).copied().unwrap_or(0) };

    while at(a, one) != 0 && at(b, two) != 0 {
        while at(a, one) != 0 && !at(a, one).is_ascii_alphanumeric() {
            one += 1;
        }
        while at(b, two) != 0 && !at(b, two).is_ascii_alphanumeric() {
            two += 1;
        }
        // Ran off the end of either string: done with the loop.
        if at(a, one) == 0 || at(b, two) == 0 {
            break;
        }
        // Different separator lengths decide the comparison.
        if one - ptr1 != two - ptr2 {
            return if one - ptr1 < two - ptr2 { Ordering::Less } else { Ordering::Greater };
        }
        ptr1 = one;
        ptr2 = two;

        let isnum = at(a, ptr1).is_ascii_digit();
        if isnum {
            while at(a, ptr1).is_ascii_digit() {
                ptr1 += 1;
            }
            while at(b, ptr2).is_ascii_digit() {
                ptr2 += 1;
            }
        } else {
            while at(a, ptr1).is_ascii_alphabetic() {
                ptr1 += 1;
            }
            while at(b, ptr2).is_ascii_alphabetic() {
                ptr2 += 1;
            }
        }

        if one == ptr1 {
            return Ordering::Less; // cannot happen; arbitrary like upstream
        }
        // Segments of different types: numeric is always newer than alpha.
        if two == ptr2 {
            return if isnum { Ordering::Greater } else { Ordering::Less };
        }

        let mut seg1 = &a[one..ptr1];
        let mut seg2 = &b[two..ptr2];
        if isnum {
            while seg1.first() == Some(&b'0') {
                seg1 = &seg1[1..];
            }
            while seg2.first() == Some(&b'0') {
                seg2 = &seg2[1..];
            }
            match seg1.len().cmp(&seg2.len()) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        match seg1.cmp(seg2) {
            Ordering::Equal => {}
            other => return other,
        }
        one = ptr1;
        two = ptr2;
    }

    let c1 = at(a, one);
    let c2 = at(b, two);
    if c1 == 0 && c2 == 0 {
        return Ordering::Equal;
    }
    // A remaining alpha segment never beats an empty string.
    if (c1 == 0 && !c2.is_ascii_alphabetic()) || c1.is_ascii_alphabetic() {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(a: &str, b: &str, expected: i32) {
        let exp = expected.cmp(&0);
        assert_eq!(vercmp(a, b), exp, "vercmp({a}, {b})");
        assert_eq!(vercmp(b, a), exp.reverse(), "vercmp({b}, {a})");
    }

    /// Test vectors from pacman's test/util/vercmptest.sh.
    #[test]
    fn pacman_vercmp_suite() {
        // all similar length, no pkgrel
        check("1.5.0", "1.5.0", 0);
        check("1.5.1", "1.5.0", 1);
        // mixed length
        check("1.5.1", "1.5", 1);
        // with pkgrel, simple
        check("1.5.0-1", "1.5.0-1", 0);
        check("1.5.0-1", "1.5.0-2", -1);
        check("1.5.0-1", "1.5.1-1", -1);
        check("1.5.0-2", "1.5.1-1", -1);
        // with pkgrel, mixed lengths
        check("1.5-1", "1.5.1-1", -1);
        check("1.5-2", "1.5.1-1", -1);
        check("1.5-2", "1.5.1-2", -1);
        // mixed pkgrel inclusion
        check("1.5", "1.5-1", 0);
        check("1.5-1", "1.5", 0);
        check("1.1-1", "1.1", 0);
        check("1.0-1", "1.1", -1);
        check("1.1-1", "1.0", 1);
        // alphanumeric versions
        check("1.5b-1", "1.5-1", -1);
        check("1.5b", "1.5", -1);
        check("1.5b-1", "1.5", -1);
        check("1.5b", "1.5.1", -1);
        // from the manpage
        check("1.0a", "1.0alpha", -1);
        check("1.0alpha", "1.0b", -1);
        check("1.0b", "1.0beta", -1);
        check("1.0beta", "1.0rc", -1);
        check("1.0rc", "1.0", -1);
        // alpha-dotted versions
        check("1.5.a", "1.5", 1);
        check("1.5.b", "1.5.a", 1);
        check("1.5.1", "1.5.b", 1);
        // alpha dots and dashes
        check("1.5.b-1", "1.5.b", 0);
        check("1.5-1", "1.5.b", -1);
        // same/similar content, differing separators
        check("2.0", "2_0", 0);
        check("2.0_a", "2_0.a", 0);
        check("2.0a", "2.0.a", -1);
        check("2___a", "2_a", 1);
        // epoch included version comparisons
        check("0:1.0", "0:1.0", 0);
        check("0:1.0", "0:1.1", -1);
        check("1:1.0", "0:1.0", 1);
        check("1:1.0", "0:1.1", 1);
        check("1:1.0", "2:1.1", -1);
        // epoch + sometimes present pkgrel
        check("1:1.0", "0:1.0-1", 1);
        check("1:1.0-1", "0:1.1-1", 1);
        // epoch included on one version
        check("0:1.0", "1.0", 0);
        check("0:1.0", "1.1", -1);
        check("0:1.1", "1.0", 1);
        check("1:1.0", "1.0", 1);
        check("1:1.0", "1.1", 1);
        check("1:1.1", "1.1", 1);
    }

    #[test]
    fn cachyos_style_pkgrels() {
        // CachyOS rebuilds often carry a ".N" suffix on the Arch pkgrel.
        check("3.0.8-1.1", "3.0.8-1", 1);
        check("3.0.7-1.1", "3.0.8-1", -1);
        check("1:2.40-3.1", "1:2.40-3", 1);
        check("6.10.2-1", "6.10.10-1", -1);
        check("20240101-1", "20231231-1", 1);
        check("1.2.3-01", "1.2.3-1", 0);
    }
}
