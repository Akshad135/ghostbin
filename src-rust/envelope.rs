use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub const ENVELOPE_PREFIX: &str = "v1:";
const AES_GCM_OVERHEAD: usize = 12 + 16;

/// Decode canonical base64url without padding.
pub fn decode_b64(value: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return None;
    }
    Some(bytes)
}

pub fn decode_b64_exact(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let bytes = decode_b64(value)?;
    (bytes.len() == expected_len).then_some(bytes)
}

pub fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a `v1:` AES-GCM envelope. The caller supplies the plaintext bound.
pub fn decode_envelope(value: &str, max_plaintext_len: usize) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix(ENVELOPE_PREFIX)?;
    let bytes = decode_b64(encoded)?;
    if bytes.len() < AES_GCM_OVERHEAD || bytes.len() > AES_GCM_OVERHEAD + max_plaintext_len {
        return None;
    }
    Some(bytes)
}

pub fn decode_envelope_exact(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix(ENVELOPE_PREFIX)?;
    decode_b64_exact(encoded, expected_len)
}

pub fn encode_envelope(bytes: &[u8]) -> String {
    format!("{ENVELOPE_PREFIX}{}", encode_b64(bytes))
}
