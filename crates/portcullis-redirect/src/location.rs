//! Builds the `Location:` header value for the 302 redirect to the portal
//! (TDD §7.2).
//!
//! Output shape:
//! `https://<portal>/portal?mac=<mac>&nas_id=<store>&ts=<ts>&sig=<sig>`
//!
//! The path (`/portal`) and the `nas_id` query key match the FE captive portal
//! (`app/portal`) + the CP's `/api/captive/auth/instant` contract; the `ts`/`sig`
//! pair is the HMAC the CP verifies before granting (invariant #7).
//!
//! Every query value is percent-encoded so a hostile `store_id` (the only field
//! that isn't already a constrained shape — MAC is `[0-9a-f:]`, ts is digits,
//! sig is hex) cannot inject extra query parameters, fragments, CRLF, or break
//! out of the URL. We encode all four values uniformly rather than trusting any
//! of them.

use portcullis_types::MacAddr;

/// Percent-encode a string for safe inclusion in a URL query *value*, using the
/// conservative "encode everything that isn't an unreserved char" rule
/// (RFC 3986 unreserved set: ALPHA / DIGIT / `-` / `.` / `_` / `~`).
///
/// This is intentionally stricter than necessary — encoding `:` in the MAC, for
/// instance — but a captive-portal splash endpoint accepts the encoded form and
/// strictness here removes any chance of query-injection. Total: handles every
/// byte, including non-ASCII, via its UTF-8 encoding.
fn encode_query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(to_hex_upper(b >> 4));
            out.push(to_hex_upper(b & 0x0f));
        }
    }
    out
}

fn to_hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        // Unreachable: callers pass a single nibble. Map defensively rather
        // than panic so this stays total.
        _ => '0',
    }
}

/// Normalize the portal base so the result is always exactly
/// `<scheme>://<host>[/path]` with no trailing slash, then append `/portal?...`.
///
/// A trailing slash on `portal_base` would otherwise produce `//portal`.
fn normalized_base(portal_base: &str) -> &str {
    portal_base.trim_end_matches('/')
}

/// Build the full redirect `Location` URL.
///
/// `mac` is rendered canonical; the caller supplies the already-computed `sig`
/// (hex from [`crate::sign::sign`]). All values are query-encoded.
pub fn build_location(
    portal_base: &str,
    mac: &MacAddr,
    store_id: &str,
    ts: i64,
    sig: &str,
) -> String {
    format!(
        "{base}/portal?mac={mac}&nas_id={store}&ts={ts}&sig={sig}",
        base = normalized_base(portal_base),
        mac = encode_query_value(&mac.to_canonical()),
        store = encode_query_value(store_id),
        ts = ts, // an i64 renders as `-?[0-9]+`, already URL-safe
        sig = encode_query_value(sig),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> MacAddr {
        "aa:bb:cc:dd:ee:ff".parse().unwrap()
    }

    #[test]
    fn exact_output_shape() {
        let got = build_location(
            "https://portal.wifihub.vn",
            &mac(),
            "store-42",
            1_700_000_000,
            "deadbeef",
        );
        assert_eq!(
            got,
            "https://portal.wifihub.vn/portal?mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&nas_id=store-42&ts=1700000000&sig=deadbeef"
        );
    }

    #[test]
    fn trailing_slash_on_base_is_normalized() {
        let got = build_location("https://portal.example/", &mac(), "s", 0, "ab");
        assert!(got.starts_with("https://portal.example/portal?"));
        assert!(!got.contains("//portal?"));
    }

    #[test]
    fn hostile_store_id_cannot_inject_query_params() {
        // A store id trying to smuggle an extra param / fragment / CRLF.
        let evil = "x&grant=1#frag\r\nSet-Cookie: a=b";
        let got = build_location("https://p", &mac(), evil, 1, "ab");
        // The only literal '&' / '#' / CR / LF in the output must be the ones
        // we placed; the injected ones are percent-encoded.
        assert!(!got.contains("grant=1"));
        assert!(!got.contains('#'));
        assert!(!got.contains('\r'));
        assert!(!got.contains('\n'));
        assert!(got.contains("nas_id=x%26grant%3D1%23frag%0D%0ASet-Cookie%3A%20a%3Db"));
        // Exactly the four params we intend.
        assert_eq!(got.matches("&nas_id=").count(), 1);
        assert_eq!(got.matches("&grant=").count(), 0);
    }

    #[test]
    fn negative_ts_renders_safely() {
        let got = build_location("https://p", &mac(), "s", -5, "ab");
        assert!(got.contains("ts=-5"));
    }

    #[test]
    fn encode_handles_non_ascii_and_spaces() {
        assert_eq!(encode_query_value("a b"), "a%20b");
        assert_eq!(encode_query_value("café"), "caf%C3%A9");
        assert_eq!(encode_query_value("~-._"), "~-._"); // unreserved untouched
        assert_eq!(encode_query_value(""), "");
    }
}
