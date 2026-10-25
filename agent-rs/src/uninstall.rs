//! One-time uninstall codes, checked offline (same construction as agent/uninstall.py, pinned by
//! contract/uninstall-vectors.json). HOTP-style: HMAC-SHA256 over a big-endian counter, 50 bits
//! written as 10 Crockford base32 symbols.

use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LENGTH: usize = 10;
/// Counters accepted above the last one used, so unused codes generated in the panel stay valid.
pub const WINDOW: u64 = 20;
const RELEASE_LABEL: &[u8] = b"openems-release-v1";

/// HMAC-SHA256 (RFC 2104) on the existing sha2 dependency.
fn mac(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|value| value ^ byte);
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

/// Display form `XXXXX-XXXXX` for `counter` (positive).
pub fn code(secret: &[u8], counter: u64) -> String {
    let digest = mac(secret, &counter.to_be_bytes());
    let value = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) >> (64 - 5 * CODE_LENGTH);
    let symbols: String = (0..CODE_LENGTH)
        .map(|index| ALPHABET[((value >> (5 * (CODE_LENGTH - 1 - index))) & 31) as usize] as char)
        .collect();
    format!("{}-{}", &symbols[..5], &symbols[5..])
}

/// Code as typed (any case, spaces or dashes, O/I/L lookalikes) to its 10 symbols, or None.
pub fn normalize(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|character| *character != '-' && *character != ' ')
        .map(|character| match character.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    (cleaned.len() == CODE_LENGTH && cleaned.bytes().all(|byte| ALPHABET.contains(&byte))).then_some(cleaned)
}

/// Counter of a valid unused code (last_used < counter <= last_used + WINDOW), or None.
pub fn verify(secret: &[u8], typed: &str, last_used: u64) -> Option<u64> {
    let wanted = normalize(typed)?;
    (last_used + 1..=last_used + WINDOW).find(|&counter| {
        let candidate = code(secret, counter).replace('-', "");
        // Constant-time comparison: every byte is compared whatever the first mismatch.
        candidate.len() == wanted.len()
            && candidate.bytes().zip(wanted.bytes()).fold(0u8, |acc, (left, right)| acc | (left ^ right)) == 0
    })
}

/// Proof that the server released removal without a code for this registration.
pub fn release_token(secret: &[u8]) -> String {
    hex::encode(mac(secret, RELEASE_LABEL))
}
