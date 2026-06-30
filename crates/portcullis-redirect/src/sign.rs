//! HMAC signing of the redirect identity tuple (TDD §7.2, §13).
//!
//! The router signs `"<mac>|<store_id>|<ts>"` with a per-store key that the
//! client never sees. The portal/control plane trust `mac`/`store` *only*
//! because this signature validates — a client cannot forge another MAC into a
//! grant request. Verification uses a **constant-time** comparison (`subtle`)
//! so the tag can't be recovered by timing the response.

use hmac::{Hmac, Mac};
use portcullis_types::MacAddr;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// A tiny fixed-capacity stack string — lets us format a MAC / integer without
/// a heap allocation on the per-redirect signing hot path.
struct StackStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackStr<N> {
    fn new() -> Self {
        StackStr { buf: [0u8; N], len: 0 }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> std::fmt::Write for StackStr<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let b = s.as_bytes();
        let end = self.len + b.len();
        if end > N {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(b);
        self.len = end;
        Ok(())
    }
}

/// Feed the canonical signing message `"<mac>|<store_id>|<ts>"` into the HMAC
/// state without allocating a combined `String`.
///
/// `store_id` is borrowed (no copy); `mac` renders into a 17-byte buffer (its
/// canonical lowercase `aa:bb:..` form is always 17 chars) and `ts` into a
/// 20-byte buffer (an `i64` is at most 19 digits + sign). This is the *only*
/// place the message format is defined, so signer and verifier never drift.
fn update_message(state: &mut HmacSha256, mac: &MacAddr, store_id: &str, ts: i64) {
    use std::fmt::Write as _;
    let mut macbuf = StackStr::<17>::new();
    let _ = write!(macbuf, "{mac}");
    let mut tsbuf = StackStr::<20>::new();
    let _ = write!(tsbuf, "{ts}");

    state.update(macbuf.as_bytes());
    state.update(b"|");
    state.update(store_id.as_bytes());
    state.update(b"|");
    state.update(tsbuf.as_bytes());
}

/// Compute `HMAC-SHA256(key, "<mac>|<store_id>|<ts>")` and return it as
/// lowercase hex.
///
/// HMAC-SHA256 accepts a key of any length (it internally hashes over-long
/// keys and zero-pads short ones), so this is total over every `key` — no panic
/// on an empty or huge key.
pub fn sign(key: &[u8], mac: &MacAddr, store_id: &str, ts: i64) -> String {
    let mut mac_state =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    update_message(&mut mac_state, mac, store_id, ts);
    let tag = mac_state.finalize().into_bytes();
    hex::encode(tag)
}

/// Verify a hex-encoded signature against the tuple using a constant-time
/// comparison. Returns `false` for any malformed hex or length mismatch — never
/// panics, never short-circuits on the first differing byte.
pub fn verify(key: &[u8], mac: &MacAddr, store_id: &str, ts: i64, sig_hex: &str) -> bool {
    // Decode the candidate first. Invalid/odd-length hex is simply "no match".
    let candidate = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac_state = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    update_message(&mut mac_state, mac, store_id, ts);
    let expected = mac_state.finalize().into_bytes();

    // Length guard before the CT compare so the slices line up; the lengths
    // themselves are not secret (always 32 bytes for SHA-256).
    if candidate.len() != expected.len() {
        return false;
    }
    // subtle's ct_eq returns a Choice; folding to bool keeps it data-independent.
    candidate.ct_eq(expected.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"secret-key";
    // Independently computed:
    //   printf 'aa:bb:cc:dd:ee:ff|store-42|1700000000' \
    //     | openssl dgst -sha256 -hmac 'secret-key'
    const KAT: &str = "9cb62e50c60d9a17e6be8c153baf74e7cccefa179a99f7b3972ae635a3299b49";

    fn mac() -> MacAddr {
        "aa:bb:cc:dd:ee:ff".parse().unwrap()
    }

    #[test]
    fn known_answer_vector() {
        assert_eq!(sign(KEY, &mac(), "store-42", 1_700_000_000), KAT);
        // Output is lowercase hex, exactly 64 chars (32 bytes).
        let s = sign(KEY, &mac(), "store-42", 1_700_000_000);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let sig = sign(KEY, &mac(), "store-1", 42);
        assert!(verify(KEY, &mac(), "store-1", 42, &sig));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sig = sign(KEY, &mac(), "store-1", 42);
        // Flip the last hex nibble.
        let mut bytes: Vec<char> = sig.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == '0' { '1' } else { '0' };
        let tampered: String = bytes.into_iter().collect();
        assert_ne!(tampered, sig);
        assert!(!verify(KEY, &mac(), "store-1", 42, &tampered));
    }

    #[test]
    fn verify_rejects_wrong_key_mac_store_or_ts() {
        let sig = sign(KEY, &mac(), "store-1", 42);
        let other_mac: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert!(!verify(b"other-key", &mac(), "store-1", 42, &sig));
        assert!(!verify(KEY, &other_mac, "store-1", 42, &sig));
        assert!(!verify(KEY, &mac(), "store-2", 42, &sig));
        assert!(!verify(KEY, &mac(), "store-1", 43, &sig));
    }

    #[test]
    fn verify_is_total_on_garbage_hex() {
        // Non-hex, odd length, wrong length, empty — all must return false,
        // never panic (constant-time path is only reached on equal lengths).
        assert!(!verify(KEY, &mac(), "store-1", 42, ""));
        assert!(!verify(KEY, &mac(), "store-1", 42, "zz"));
        assert!(!verify(KEY, &mac(), "store-1", 42, "abc")); // odd length
        assert!(!verify(KEY, &mac(), "store-1", 42, "ab")); // valid hex, too short
        let too_long = "ab".repeat(64);
        assert!(!verify(KEY, &mac(), "store-1", 42, &too_long));
        // A 32-byte all-zero candidate (right length, wrong value).
        assert!(!verify(KEY, &mac(), "store-1", 42, &"00".repeat(32)));
    }

    #[test]
    fn sign_is_total_on_empty_and_huge_key() {
        // Empty key must not panic.
        let _ = sign(b"", &mac(), "store", 0);
        // Key longer than the SHA-256 block size (64 bytes) must not panic.
        let big = vec![0xABu8; 1024];
        let s = sign(&big, &mac(), "store", 0);
        assert_eq!(s.len(), 64);
    }
}
