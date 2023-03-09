use sha2::{ Sha256, Digest };
use base58::ToBase58;

/// Performs a two-fold iterated SHA256 digest of a byte slice
/// and returns the leading four bytes of the resulting blob.
fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let tmp: Vec<u8> = <Sha256 as Digest>::digest(payload).as_slice().to_vec();
    <Sha256 as Digest>::digest(&tmp).as_slice()[0..4].to_vec()
}

/// Returns the Base58Check digest [`String`] of a binary buffer.
fn safe_encode(payload: &[u8]) -> String {
    let mut buf = payload.to_vec();
    let mut check = double_sha256(payload);
    buf.append(&mut check);
    buf.to_base58()
}

/// Returns the Base58Check digest over arbitrary binary-convertible types.
pub fn to_base58check_raw(payload: &impl AsRef<[u8]>) -> String {
    safe_encode(payload.as_ref())
}

/// Performs a Base58Check encode operation on a byte-slice.
///
/// The first argument is a static byte-slice to prepend to the input
/// payload. These prefixes are determined based on the desired string
/// prefix in the Base58Check output string encoding.
pub fn to_base58check(prefix: &'static [u8], payload: &[u8]) -> String {
    let mut tmp = Vec::with_capacity(prefix.len() + payload.len());
    tmp.extend_from_slice(prefix);
    tmp.extend_from_slice(payload);
    safe_encode(&tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base58check_sanity() {
        assert_eq!(to_base58check(&crate::core::PublicKeyHashV0::ED25519_BASE58_PREFIX, &[0u8; 20]), "tz1Ke2h7sDdakHJQh8WX4Z372du1KChsksyU");
    }
}