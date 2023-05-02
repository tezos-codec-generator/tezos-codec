use std::convert::Infallible;

use base58::{FromBase58, FromBase58Error, ToBase58};
use sha2::{Digest, Sha256};

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

#[derive(Debug)]
pub enum FromBase58CheckError<E: 'static = Infallible> {
    Base58(FromBase58Error),
    Other(E),
}

impl<E> From<FromBase58Error> for FromBase58CheckError<E> {
    fn from(value: FromBase58Error) -> Self {
        Self::Base58(value)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for FromBase58CheckError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FromBase58CheckError::Base58(b58_err) => {
                write!(
                    f,
                    "error encountered during base58check decoding: {:?}",
                    b58_err
                )
            }
            FromBase58CheckError::Other(other) => {
                write!(
                    f,
                    "error encountered during base58ccheck decoding: {}",
                    other
                )
            }
        }
    }
}

impl<E: std::error::Error> std::error::Error for FromBase58CheckError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FromBase58CheckError::Base58(_) => None,
            FromBase58CheckError::Other(e) => Some(e),
        }
    }
}

pub fn from_base58check<S, E>(image: S) -> Result<Vec<u8>, FromBase58CheckError<E>>
where
    S: AsRef<str>,
{
    safe_decode(image.as_ref())
}

/// Removes the final four bytes of a slice
///
/// # Examples
/// ```
/// # use tezos_codec::core::base58::drop_four;
/// assert_eq!(drop_four(&[1,2,3,4,5]), &[1]);
/// ```
pub fn drop_four<'a>(bytes: &'a [u8]) -> &'a [u8] {
    let l = bytes.len();
    bytes.split_at(l - 4).0
}

fn safe_decode<E>(image_str: &str) -> Result<Vec<u8>, FromBase58CheckError<E>> {
    let full_plaintext = image_str.from_base58()?;
    Ok(drop_four(&full_plaintext).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58check_sanity_tz1() {
        assert_eq!(
            to_base58check(
                &crate::core::PublicKeyHashV0::ED25519_BASE58_PREFIX,
                &[0u8; 20]
            ),
            "tz1Ke2h7sDdakHJQh8WX4Z372du1KChsksyU"
        );
    }

    #[test]
    fn base58check_sanity_tz2() {
        assert_eq!(
            to_base58check(
                &crate::core::PublicKeyHashV0::SECP256K1_BASE58_PREFIX,
                &[0u8; 20]
            ),
            "tz28KEfLTo3wg2wGyJZMjC1MaDA1q68s6tz5"
        );
    }
}
