pub mod base58;

use tedium::FixedBytes;

use crate::traits::{ AsPayload, Crypto, StaticPrefix, DynamicPrefix, BinaryDataType };

/// Cross-protocol type for representing 32-byte cryptographic
/// digests of arbitrary operation payloads.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationHash(FixedBytes<32>);

impl BinaryDataType<32> for OperationHash {
    fn as_array_ref(&self) -> &[u8; 32] {
        self.0.bytes()
    }

    fn as_fixed_bytes(&self) -> &FixedBytes<32> {
        &self.0
    }
}

impl OperationHash {
    pub const BASE58_PREFIX : [u8; 2] = [5, 116];

    #[inline]
    #[must_use]
    /// Promotes a raw [`FixedBytes<32>`] value into a reified [`OperationHash`].
    pub const fn from_fixed_bytes(fixed_bytes: FixedBytes<32>) -> Self {
        Self(fixed_bytes)
    }

    #[inline]
    #[must_use]
    /// Promotes a raw [`[u8; 32]`] value into a reified [`OperationHash`].
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self(FixedBytes::from_array(bytes))
    }
}

impl AsPayload for OperationHash {
    fn as_payload(&self) -> &[u8] {
        self.0.bytes()
    }
}

impl StaticPrefix for OperationHash {
    const PREFIX : &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for OperationHash {
}

impl AsRef<[u8; 32]> for OperationHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.bytes()
    }
}

impl AsRef<[u8]> for OperationHash {
    fn as_ref(&self) -> &[u8] {
        self.0.bytes()
    }
}

impl AsRef<FixedBytes<32>> for OperationHash {
    fn as_ref(&self) -> &FixedBytes<32> {
        &self.0
    }
}

impl From<[u8; 32]> for OperationHash {
    fn from(value: [u8; 32]) -> Self {
        Self::from_byte_array(value)
    }
}

impl From<&'_ [u8; 32]> for OperationHash {
    fn from(value: &'_ [u8; 32]) -> Self {
        Self::from_byte_array(*value)
    }
}

impl From<FixedBytes<32>> for OperationHash {
    fn from(value: FixedBytes<32>) -> Self {
        Self(value)
    }
}

/// Newtype struct representing a unified (protocol-invariant) chain-identifier,
/// as a 4-byte blob
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainId(FixedBytes<4>);

impl BinaryDataType<4> for ChainId {
    fn as_array_ref(&self) -> &[u8; 4] {
        self.0.bytes()
    }

    fn as_fixed_bytes(&self) -> &FixedBytes<4> {
        &self.0
    }
}

impl ChainId {
    #[must_use]
    #[inline(always)]
    /// Promotes a raw [`FixedBytes<4>`] value into a reified [`ChainId`].
    pub const fn from_fixed_bytes(fixed_bytes: FixedBytes<4>) -> Self {
        Self(fixed_bytes)
    }

    #[must_use]
    #[inline]
    /// Promotes a raw [`[u8; 4]`] value into a reified [`ChainId`].
    pub fn from_byte_array(bytes: [u8; 4]) -> Self {
        Self(bytes.into())
    }
}

impl From<&'_ [u8; 4]> for ChainId {
    fn from(value: &'_ [u8; 4]) -> Self {
        Self(FixedBytes::<4>::from(value))
    }
}

impl From<[u8; 4]> for ChainId {
    fn from(value: [u8; 4]) -> Self {
        Self(FixedBytes::<4>::from(&value))
    }
}

impl From<FixedBytes<4>> for ChainId {
    fn from(value: FixedBytes<4>) -> Self {
        Self(value)
    }
}

impl AsRef<FixedBytes<4>> for ChainId {
    fn as_ref(&self) -> &FixedBytes<4> {
        &self.0
    }
}

impl AsRef<[u8; 4]> for ChainId {
    fn as_ref(&self) -> &[u8; 4] {
        self.0.as_ref()
    }
}

impl AsPayload for ChainId {
    fn as_payload(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Simple struct representing BlockHash types
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHash(FixedBytes<32>);

impl BlockHash {
    /// Reverse-engineered byte-level prefix to ensure Base58Check
    /// output starts with the correct substring
    pub const BASE58_PREFIX: [u8; 2] = [1, 52];
}

impl From<[u8; 32]> for BlockHash {
    fn from(value: [u8; 32]) -> Self {
        Self(FixedBytes::<32>::from(&value))
    }
}

impl From<FixedBytes<32>> for BlockHash {
    fn from(value: FixedBytes<32>) -> Self {
        Self(value)
    }
}

impl crate::traits::AsPayload for BlockHash {
    fn as_payload(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl crate::traits::StaticPrefix for BlockHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl crate::traits::Crypto for BlockHash {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ProtocolHash(FixedBytes<32>);

impl ProtocolHash {
    /// Reverse-engineered byte-level prefix to ensure Base58Check
    /// output starts with the correct substring
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

impl SignatureV0 {
    pub const BASE58_PREFIX: [u8; 3] = [4, 130, 43];

    #[inline]
    #[must_use]
    pub fn from_fixed_bytes(bytes: FixedBytes<64>) -> Self {
        Self(bytes)
    }

    #[inline]
    #[must_use]
    pub fn from_byte_array(bytes: [u8; 64]) -> Self {
        Self(bytes.into())
    }
}

impl From<FixedBytes<64>> for SignatureV0 {
    fn from(value: FixedBytes<64>) -> Self {
        Self(value)
    }
}

impl From<[u8; 64]> for SignatureV0 {
    fn from(value: [u8; 64]) -> Self {
        Self(value.into())
    }
}

impl AsRef<FixedBytes<64>> for SignatureV0 {
    fn as_ref(&self) -> &FixedBytes<64> {
        &self.0
    }
}

impl AsRef<[u8; 64]> for SignatureV0 {
    fn as_ref(&self) -> &[u8; 64] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for SignatureV0 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsPayload for SignatureV0 {
    #[inline]
    fn as_payload(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl StaticPrefix for SignatureV0 {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for SignatureV0 {}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PublicKeyHashV0 {
    Ed25519(FixedBytes<20>),
    Secp256k1(FixedBytes<20>),
    P256(FixedBytes<20>),
}

impl PublicKeyHashV0 {
    pub const ED25519_BASE58_PREFIX: [u8; 3] = [6, 161, 159];
    pub const SECP256K1_BASE58_PREFIX: [u8; 3] = [6, 161, 161];
    pub const P256_BASE58_PREFIX: [u8; 3] = [6, 161, 164];

    #[must_use]
    #[inline]
    /// Returns a reference to the
    pub const fn as_fixed_bytes(&self) -> &FixedBytes<20> {
        match self {
            Self::Ed25519(bytes) | Self::Secp256k1(bytes) | Self::P256(bytes) => bytes,
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        match self {
            Self::Ed25519(bytes) => bytes.bytes(),
            Self::Secp256k1(bytes) => bytes.bytes(),
            Self::P256(bytes) => bytes.bytes(),
        }
    }
}

impl DynamicPrefix for PublicKeyHashV0 {
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

impl Crypto for PublicKeyHashV0 {}

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