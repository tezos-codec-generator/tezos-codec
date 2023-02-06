pub mod base58;

use rust_runtime::FixedBytes;

use crate::traits::{AsPayload, Crypto};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolHash(FixedBytes<32>);

impl ProtocolHash {
    pub const BASE58_PREFIX: [u8; 2] = [2, 170];
}


impl From<[u8; 32]> for ProtocolHash {
    fn from(value: [u8; 32]) -> Self {
        Self(FixedBytes::<32>::from(&value))
    }
}

impl From<FixedBytes<32>> for ProtocolHash {
    fn from(value: FixedBytes<32>) -> Self {
        Self(value)
    }
}

impl crate::traits::AsPayload for ProtocolHash {
    fn as_payload(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl crate::traits::StaticPrefix for ProtocolHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl crate::traits::Crypto for ProtocolHash {}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct SignatureV0(FixedBytes<64>);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PublicKeyHashV0 {
    Ed25519(FixedBytes<20>),
    Secp256k1(FixedBytes<20>),
    P256(FixedBytes<20>),
}

impl PublicKeyHashV0 {
    pub const ED25519_BASE58_PREFIX : [u8; 3] = [6, 161, 159];
    pub const SECP256K1_BASE58_PREFIX : [u8; 3] = [6, 161, 161];
    pub const P256_BASE58_PREFIX : [u8; 3] = [6, 161, 164];

    #[must_use]
    #[inline]
    /// Returns a reference to the
    pub const fn as_fixed_bytes(&self) -> &FixedBytes<20> {
        match self {
            | Self::Ed25519(bytes)
            | Self::Secp256k1(bytes)
            | Self::P256(bytes) => bytes,
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        match self {
            Self::Ed25519(bytes) => bytes.as_slice(),
            Self::Secp256k1(bytes) => bytes.as_slice(),
            Self::P256(bytes) => bytes.as_slice(),
        }
    }
}

impl crate::traits::DynamicPrefix for PublicKeyHashV0 {
    fn get_prefix(&self) -> &'static [u8] {
        match self {
            PublicKeyHashV0::Ed25519(_) => &Self::ED25519_BASE58_PREFIX,
            PublicKeyHashV0::Secp256k1(_) => &Self::SECP256K1_BASE58_PREFIX,
            PublicKeyHashV0::P256(_) => &Self::P256_BASE58_PREFIX,
        }
    }
}

impl AsPayload for PublicKeyHashV0 {
    #[inline(always)]
    fn as_payload(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Crypto for PublicKeyHashV0 { }


#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(i64);

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: implement RFC3339 (chrono) display
        self.0.fmt(f)
    }
}

impl From<Timestamp> for i64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

impl From<i64> for Timestamp {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl AsRef<i64> for Timestamp {
    fn as_ref(&self) -> &i64 {
        &self.0
    }
}

impl std::borrow::Borrow<i64> for Timestamp {
    fn borrow(&self) -> &i64 {
        &self.0
    }
}