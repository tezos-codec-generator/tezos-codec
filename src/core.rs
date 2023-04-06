pub mod ballot;
pub mod base58;
pub mod rpc;

use std::{fmt::Display, hint::unreachable_unchecked};

use num::rational::Ratio;
use tedium::{Decode, FixedBytes};

#[macro_export]
macro_rules! boilerplate {
    (@ refonly $($tname:ident = $n:literal),+ $(,)?) => {
       $(
            impl AsPayload for $tname {
                fn as_payload(&self) -> &[u8] {
                    self.as_array_ref()
                }
            }

            impl AsRef<[u8; $n]> for $tname {
                fn as_ref(&self) -> &[u8; $n] {
                    self.as_array_ref()
                }
            }

            impl AsRef<[u8]> for $tname {
                fn as_ref(&self) -> &[u8] {
                    self.as_array_ref()
                }
            }

            impl AsRef<FixedBytes<$n>> for $tname {
                fn as_ref(&self) -> &FixedBytes<$n> {
                    self.as_fixed_bytes()
                }
            }
        )+
    };
    ($($tname:ident = $n:literal),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, tedium::Decode)]
            pub struct $tname(::tedium::FixedBytes<$n>);

            impl $crate::traits::AsPayload for $tname {
                fn as_payload(&self) -> &[u8] {
                    self.0.bytes()
                }
            }

            impl $crate::traits::BinaryDataType<$n> for $tname {
                fn as_array_ref(&self) -> &[u8; $n] {
                    self.0.bytes()
                }

                fn as_fixed_bytes(&self) -> &::tedium::FixedBytes<$n> {
                    &self.0
                }
            }

            impl $tname {
                pub const fn from_byte_array(b: [u8; $n]) -> Self {
                    Self(::tedium::FixedBytes::<$n>::from_array(b))
                }

                pub const fn from_fixed_bytes(bytes: ::tedium::FixedBytes<$n>) -> Self {
                    Self(bytes)
                }
            }

            impl From<[u8; $n]> for $tname {
                fn from(value: [u8; $n]) -> Self {
                    Self::from_byte_array(value)
                }
            }

            impl From<&'_ [u8; $n]> for $tname {
                fn from(value: &'_ [u8; $n]) -> Self {
                    Self::from_byte_array(*value)
                }
            }

            impl From<::tedium::FixedBytes<$n>> for $tname {
                fn from(value: ::tedium::FixedBytes<$n>) -> Self {
                    Self::from_fixed_bytes(value)
                }
            }

            impl AsRef<[u8; $n]> for $tname {
                fn as_ref(&self) -> &[u8; $n] {
                    self.0.bytes()
                }
            }

            impl AsRef<[u8]> for $tname {
                fn as_ref(&self) -> &[u8] {
                    self.0.bytes()
                }
            }

            impl AsRef<::tedium::FixedBytes<$n>> for $tname {
                fn as_ref(&self) -> &::tedium::FixedBytes<$n> {
                    &self.0
                }
            }

            impl TryFrom<&'_ [u8]> for $tname {
                type Error = std::array::TryFromSliceError;

                fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
                    Ok(Self::from_byte_array(value.try_into()?))
                }
            }
        )+
    };
}

macro_rules! impl_serde_crypto {
    ($($tname:ident),+ $(,)?) => {
        $(
            impl serde::Serialize for $tname {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
                    if serializer.is_human_readable() {
                        let tmp: String = self.to_base58check();
                        serializer.serialize_str(tmp.as_str())
                    } else {
                        serializer.serialize_newtype_struct(stringify!($tname), &self.0)
                    }
                }
            }
        )+
    };
}

use crate::{
    impl_crypto_display,
    traits::{AsPayload, Crypto, DynamicPrefix, StaticPrefix},
};

boilerplate!(OperationHash = 32);
impl_crypto_display!(OperationHash);
impl_serde_crypto!(OperationHash);

impl OperationHash {
    /// Preimage of ciphertext prefix `o`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [5, 116];
}

impl StaticPrefix for OperationHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for OperationHash {}

boilerplate!(ChainId = 4);
impl_crypto_display!(ChainId);
impl_serde_crypto!(ChainId);

impl ChainId {
    /// Preimage of ciphertext prefix `net`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 3] = [87, 82, 0];
}

impl StaticPrefix for ChainId {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for ChainId {}

boilerplate!(BlockHash = 32);
impl_crypto_display!(BlockHash);
impl_serde_crypto!(BlockHash);

impl BlockHash {
    /// Preimage of ciphertext prefix `B`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [1, 52];
}

impl StaticPrefix for BlockHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for BlockHash {}

boilerplate!(ContextHash = 32);
impl_crypto_display!(ContextHash);
impl ContextHash {
    /// Preimage of ciphertext prefix `Co`.
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [79, 199];
}
impl StaticPrefix for ContextHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}
impl Crypto for ContextHash {}

boilerplate!(OperationListListHash = 32);
impl_crypto_display!(OperationListListHash);
impl_serde_crypto!(OperationListListHash);

impl OperationListListHash {
    /// Preimage of ciphertext prefix `LLo`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 3] = [29, 159, 109];
}

impl StaticPrefix for OperationListListHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for OperationListListHash {}

boilerplate!(ProtocolHash = 32);
impl_crypto_display!(ProtocolHash);
impl_serde_crypto!(ProtocolHash);

impl ProtocolHash {
    /// Preimage of ciphertext prefix `P`.
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [2, 170];
}

impl StaticPrefix for ProtocolHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for ProtocolHash {}

boilerplate!(ValueHash = 32);
impl_crypto_display!(ValueHash);

impl ValueHash {
    /// Preimage bytes for ciphertext prefix `vh`.
    pub const BASE58_PREFIX: [u8; 3] = [1, 106, 242];
}

impl crate::traits::StaticPrefix for ValueHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl crate::traits::Crypto for ValueHash {}

crate::boilerplate!(NonceHash = 32);
crate::impl_crypto_display!(NonceHash);

impl NonceHash {
    /// Preimage bytes for ciphertext prefix `nce`.
    pub const BASE58_PREFIX: [u8; 3] = [69, 220, 169];
}

impl StaticPrefix for NonceHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}
impl Crypto for NonceHash {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureV1 {
    SigV0(FixedBytes<64>),
    Bls(FixedBytes<96>),
}

#[derive(Debug)]
pub struct InvalidSignatureV1ByteLengthError(pub(crate) usize);

impl Display for InvalidSignatureV1ByteLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "byte-sequence of length {} cannot be a valid V1 signature (BLS := 96, v0 := 64)",
            self.0
        )
    }
}

impl std::error::Error for InvalidSignatureV1ByteLengthError {}

mod sigv1_impls {
    use super::*;

    impl From<SignatureV0> for SignatureV1 {
        fn from(value: SignatureV0) -> Self {
            Self::SigV0(value.0)
        }
    }

    impl From<FixedBytes<64>> for SignatureV1 {
        fn from(value: FixedBytes<64>) -> Self {
            Self::SigV0(value)
        }
    }

    impl From<FixedBytes<96>> for SignatureV1 {
        fn from(value: FixedBytes<96>) -> Self {
            Self::Bls(value)
        }
    }

    impl TryFrom<Vec<u8>> for SignatureV1 {
        type Error = InvalidSignatureV1ByteLengthError;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            match value.len() {
                96 => unsafe {
                    let bytes: FixedBytes<96> =
                        FixedBytes::try_from_slice(value.as_ref()).unwrap_unchecked();
                    Ok(Self::Bls(bytes))
                },
                64 => unsafe {
                    let bytes: FixedBytes<64> =
                        FixedBytes::try_from_slice(value.as_ref()).unwrap_unchecked();
                    Ok(Self::SigV0(bytes))
                },
                other => Err(InvalidSignatureV1ByteLengthError(other)),
            }
        }
    }

    impl TryFrom<tedium::Bytes> for SignatureV1 {
        type Error = <SignatureV1 as TryFrom<Vec<u8>>>::Error;

        fn try_from(value: tedium::Bytes) -> Result<Self, Self::Error> {
            Self::try_from(value.into_vec())
        }
    }
}

#[derive(Debug)]
pub struct TryIntoSigV0Error;

impl Display for TryIntoSigV0Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot downcast SignatureV0-incompatible SignatureV1")
    }
}

impl std::error::Error for TryIntoSigV0Error {}

impl SignatureV1 {
    pub const fn from_signature_v0(sigv0: SignatureV0) -> Self {
        Self::SigV0(sigv0.0)
    }

    pub const fn is_sigv0_compatible(&self) -> bool {
        matches!(self, &Self::SigV0(_))
    }

    pub const fn is_bls(&self) -> bool {
        matches!(self, &Self::Bls(_))
    }

    pub fn try_into_sigv0(self) -> Result<SignatureV0, TryIntoSigV0Error> {
        match self {
            SignatureV1::SigV0(v0bytes) => Ok(SignatureV0(v0bytes)),
            SignatureV1::Bls(_) => Err(TryIntoSigV0Error),
        }
    }

    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, InvalidSignatureV1ByteLengthError> {
        bytes.try_into()
    }

    pub fn try_from_bytes(bytes: tedium::Bytes) -> Result<Self, InvalidSignatureV1ByteLengthError> {
        Self::try_from_vec(bytes.into_vec())
    }

    pub const fn from_fixed_bls(bls: FixedBytes<96>) -> Self {
        Self::Bls(bls)
    }

    pub const fn from_array_bls(bls: [u8; 96]) -> Self {
        Self::Bls(FixedBytes::from_array(bls))
    }
}

impl SignatureV1 {
    pub const BASE58_PREFIX: [u8; 3] = SignatureV0::BASE58_PREFIX;
}

impl StaticPrefix for SignatureV1 {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl AsPayload for SignatureV1 {
    fn as_payload(&self) -> &[u8] {
        match self {
            SignatureV1::SigV0(pl) => pl.bytes(),
            SignatureV1::Bls(pl) => pl.bytes(),
        }
    }
}

impl Crypto for SignatureV1 {}

boilerplate!(SignatureV0 = 64);
impl_crypto_display!(SignatureV0);
impl_serde_crypto!(SignatureV0);

impl SignatureV0 {
    pub const BASE58_PREFIX: [u8; 3] = [4, 130, 43];
}

impl StaticPrefix for SignatureV0 {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for SignatureV0 {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicKeyHashV0 {
    Ed25519(FixedBytes<20>),
    Secp256k1(FixedBytes<20>),
    P256(FixedBytes<20>),
}

impl PublicKeyHashV0 {
    /// Returns the discriminant value from which a given variant would be deserialized,
    /// regardless of what discriminant value the Rust compiler assigns that variant.
    pub const fn virtual_discriminant(&self) -> u8 {
        match self {
            PublicKeyHashV0::Ed25519(_) => 0,
            PublicKeyHashV0::Secp256k1(_) => 1,
            PublicKeyHashV0::P256(_) => 2,
        }
    }

    /// Returns the full serialization-equivalent value of a [`PublicKeyHashV0`], primarily for
    /// purposes of raw memory comparison operations such as [`tedium::parse::ParserExt::fast_kv_search`].
    pub fn to_discriminated_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(21);
        v.push(self.virtual_discriminant());
        v.extend_from_slice(self.as_array_ref());
        v
    }

    /// Constructs the appropriate variant of [`PublicKeyHashV0`] from a single-byte discriminant value
    /// and the 20-byte content-array.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to call this method with a discriminant-value that is out of the
    /// valid set of:
    ///   * `0` for [`Self::Ed25519`]
    ///   * `1` for [`Self::Secp256k1`]
    ///   * `2` for [`Self::P256`]
    ///
    /// It is the caller's responsibility to ensure that the discriminant value
    /// they pass in can **never** fall outside this range.
    pub unsafe fn from_parts_unchecked(disc: u8, bytes: FixedBytes<20>) -> Self {
        match disc {
            0 => Self::Ed25519(bytes),
            1 => Self::Secp256k1(bytes),
            2 => Self::P256(bytes),
            _ => std::hint::unreachable_unchecked(),
        }
    }
}

impl std::hash::Hash for PublicKeyHashV0 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_discriminated_bytes().hash(state);
    }
}

impl tedium::Decode for PublicKeyHashV0 {
    fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
    where
        Self: Sized,
    {
        let tag = p.take_tagword::<PublicKeyHashV0, u8, _>(&[0, 1, 2])?;
        let payload = FixedBytes::<20>::parse(p)?;
        Ok(unsafe { Self::from_parts_unchecked(tag, payload) })
    }
}

impl PublicKeyHashV0 {
    pub(self) const fn variant_name(&self) -> &'static str {
        match self {
            PublicKeyHashV0::Ed25519(_) => "Ed25519",
            PublicKeyHashV0::Secp256k1(_) => "Secp256k1",
            PublicKeyHashV0::P256(_) => "P256",
        }
    }
}

impl serde::Serialize for PublicKeyHashV0 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let tmp: String = self.to_base58check();
            serializer.serialize_str(tmp.as_str())
        } else {
            serializer.serialize_newtype_variant(
                "PublicKeyHashV0",
                self.virtual_discriminant() as u32,
                self.variant_name(),
                self.as_payload(),
            )
        }
    }
}

boilerplate!(@refonly PublicKeyHashV0 = 20);
impl_crypto_display!(PublicKeyHashV0);

impl PublicKeyHashV0 {
    /// Preimage of ciphertext prefix `tz1`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const ED25519_BASE58_PREFIX: [u8; 3] = [6, 161, 159];

    /// Preimage of ciphertext prefix `tz2`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const SECP256K1_BASE58_PREFIX: [u8; 3] = [6, 161, 161];

    /// Preimage of ciphertext prefix `tz3`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const P256_BASE58_PREFIX: [u8; 3] = [6, 161, 164];

    #[must_use]
    #[inline]
    /// Converts a borrowed [`PublicKeyHashV0`] into a reference to its constituent bytes,
    /// discarding any distinction as to what cryptographic algorithm it corresponds to.
    pub const fn as_fixed_bytes(&self) -> &FixedBytes<20> {
        match self {
            Self::Ed25519(bytes) | Self::Secp256k1(bytes) | Self::P256(bytes) => bytes,
        }
    }

    #[must_use]
    #[inline]
    /// Converts a borrowed [`PublicKeyHashV0`] into a reference to its constituent byte-array,
    /// discarding any distinction as to what cryptographic algorithm it corresponds to.
    pub const fn as_array_ref(&self) -> &[u8; 20] {
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

impl Crypto for PublicKeyHashV0 {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicKeyHashV1 {
    PkhV0(PublicKeyHashV0),
    Bls(FixedBytes<20>),
}

impl From<PublicKeyHashV0> for PublicKeyHashV1 {
    fn from(value: PublicKeyHashV0) -> Self {
        Self::PkhV0(value)
    }
}

#[derive(Debug)]
pub struct UnsupportedAlgorithmError(());

impl std::fmt::Display for UnsupportedAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot downcast: cryptographic algorithm unsupported in target type")
    }
}

impl std::error::Error for UnsupportedAlgorithmError {}

impl TryFrom<PublicKeyHashV1> for PublicKeyHashV0 {
    type Error = UnsupportedAlgorithmError;

    fn try_from(value: PublicKeyHashV1) -> Result<Self, Self::Error> {
        match value {
            PublicKeyHashV1::PkhV0(x) => Ok(x),
            PublicKeyHashV1::Bls(_) => Err(UnsupportedAlgorithmError(())),
        }
    }
}

impl PublicKeyHashV1 {
    pub const fn is_pkh_v0_compatible(&self) -> bool {
        matches!(self, &Self::PkhV0(_))
    }

    pub const fn is_bls(&self) -> bool {
        matches!(self, &Self::Bls(_))
    }

    pub const fn upcast(pkhv0: PublicKeyHashV0) -> Self {
        Self::PkhV0(pkhv0)
    }

    pub const fn try_downcast(self) -> Result<PublicKeyHashV0, UnsupportedAlgorithmError> {
        match self {
            PublicKeyHashV1::PkhV0(pkhv0) => Ok(pkhv0),
            PublicKeyHashV1::Bls(_) => Err(UnsupportedAlgorithmError(())),
        }
    }

    pub unsafe fn downcast_unchecked(self) -> PublicKeyHashV0 {
        let Self::PkhV0(pkhv0) = self else { unreachable_unchecked() };
        pkhv0
    }
}

impl PublicKeyHashV1 {
    /// Returns the discriminant value from which a given variant would be deserialized,
    /// regardless of what discriminant value the Rust compiler assigns that variant.
    pub const fn virtual_discriminant(&self) -> u8 {
        match self {
            Self::PkhV0(pkhv0) => pkhv0.virtual_discriminant(),
            Self::Bls(_) => 3,
        }
    }

    /// Returns the full serialization-equivalent value of a [`PublicKeyHashV0`], primarily for
    /// purposes of raw memory comparison operations such as [`tedium::parse::ParserExt::fast_kv_search`].
    pub fn to_discriminated_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(21);
        v.push(self.virtual_discriminant());
        v.extend_from_slice(self.as_array_ref());
        v
    }

    /// Constructs the appropriate variant of [`PublicKeyHashV1`] from a single-byte discriminant value
    /// and the 20-byte content-array.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to call this method with a discriminant-value that is out of the
    /// valid set of:
    ///   * `0` for [`PublicKeyHashV0::Ed25519`]
    ///   * `1` for [`PublicKeyHashV0::Secp256k1`]
    ///   * `2` for [`PublicKeyHashV0::P256`]
    ///   * `3` for [`Self::Bls`]
    ///
    /// It is the caller's responsibility to ensure that the discriminant value
    /// they pass in can **never** fall outside this range.
    pub unsafe fn from_parts_unchecked(disc: u8, bytes: FixedBytes<20>) -> Self {
        match disc {
            0..=2 => Self::PkhV0(PublicKeyHashV0::from_parts_unchecked(disc, bytes)),
            3 => Self::Bls(bytes),
            _ => std::hint::unreachable_unchecked(),
        }
    }
}

impl std::hash::Hash for PublicKeyHashV1 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_discriminated_bytes().hash(state);
    }
}

impl tedium::Decode for PublicKeyHashV1 {
    fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
    where
        Self: Sized,
    {
        let tag = p.take_tagword::<PublicKeyHashV1, u8, _>(&[0, 1, 2, 3])?;
        let payload = FixedBytes::<20>::parse(p)?;
        Ok(unsafe { Self::from_parts_unchecked(tag, payload) })
    }
}

impl PublicKeyHashV1 {
    pub(self) const fn variant_name(&self) -> &'static str {
        match self {
            Self::Bls(_) => "Bls",
            Self::PkhV0(pkhv0) => pkhv0.variant_name(),
        }
    }
}

impl serde::Serialize for PublicKeyHashV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let tmp: String = self.to_base58check();
            serializer.serialize_str(tmp.as_str())
        } else {
            serializer.serialize_newtype_variant(
                "PublicKeyHashV1",
                self.virtual_discriminant() as u32,
                self.variant_name(),
                self.as_payload(),
            )
        }
    }
}

boilerplate!(@refonly PublicKeyHashV1 = 20);
impl_crypto_display!(PublicKeyHashV1);

impl PublicKeyHashV1 {
    pub const BLS12_381_BASE58_PREFIX: [u8; 3] = [6, 161, 166];

    #[must_use]
    #[inline]
    /// Converts a borrowed [`PublicKeyHashV1`] into a reference to its constituent bytes,
    /// discarding any distinction as to what cryptographic algorithm it corresponds to.
    pub const fn as_fixed_bytes(&self) -> &FixedBytes<20> {
        match self {
            Self::PkhV0(pkhv0) => pkhv0.as_fixed_bytes(),
            Self::Bls(bls) => bls,
        }
    }

    #[must_use]
    #[inline]
    /// Converts a borrowed [`PublicKeyHashV1`] into a reference to its constituent byte-array,
    /// discarding any distinction as to what cryptographic algorithm it corresponds to.
    pub const fn as_array_ref(&self) -> &[u8; 20] {
        match self {
            Self::PkhV0(pkhv0) => pkhv0.as_array_ref(),
            Self::Bls(bls) => bls.bytes(),
        }
    }
}

impl DynamicPrefix for PublicKeyHashV1 {
    fn get_prefix(&self) -> &'static [u8] {
        match self {
            PublicKeyHashV1::PkhV0(pkhv0) => pkhv0.get_prefix(),
            PublicKeyHashV1::Bls(_) => &Self::BLS12_381_BASE58_PREFIX,
        }
    }
}

impl Crypto for PublicKeyHashV1 {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(i64);

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: implement RFC3339 (chrono) display
        self.0.fmt(f)
    }
}

impl Timestamp {
    #[inline]
    #[must_use]
    /// Upcasts an [`i64`] to a representationally equivalent [`Timestamp`].
    pub const fn from_i64(i: i64) -> Self {
        Self(i)
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

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Mutez(i64);

impl Decode for Mutez {
    fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(i64::parse(p)?.into())
    }
}

impl tedium::conv::len::FixedLength for Mutez {
    const LEN: usize = <i64 as tedium::conv::len::FixedLength>::LEN;
}

impl Mutez {
    pub const PRECISION: u64 = 1_000_000;

    pub const fn to_i64(&self) -> i64 {
        self.0
    }

    pub const fn from_i64(mutez: i64) -> Self {
        Self(mutez)
    }

    /// Partitions a [`Mutez`] around the logical decimal point in its xtz value,
    /// returning the signed number of tez followed by the unsigned mantissa.
    pub const fn to_parts(&self) -> (i64, u64) {
        let abs = self.0.unsigned_abs();
        let mantissa = abs.rem_euclid(Self::PRECISION);
        let radix = self.0.wrapping_div(Self::PRECISION as i64);
        (radix, mantissa)
    }

    /// Returns a string representation of the decimal value of this [`Mutez`] instance,
    /// with an implicit unit of `tez`.
    ///
    /// The numeric formatting is done using the standard Display for integers, and so it will
    /// not include any separators between digits. For more readable or otherwise more customizable
    /// formatting, see [`format_parts`].
    pub fn to_xtz_string(&self) -> String {
        let (radix, mantissa) = self.to_parts();
        format!("{radix}.{mantissa}")
    }

    /// Calls an arbitrary function that maps the radix and mantissa of a [`Mutez`] instance
    /// into a formatted string.
    ///
    /// This function is provided as a convenience for end-users who want more control over
    /// the display format of [`Mutez`] values than provided by the [`std::fmt::Debug`] and [`std::fmt::Display`]
    /// traits implementations, or the [`to_xtz_string`] associated method.
    pub fn format_parts<F>(&self, f: F) -> String
    where
        F: FnOnce(i64, u64) -> String,
    {
        let (radix, mantissa) = self.to_parts();
        f(radix, mantissa)
    }

    pub fn to_tez_lossy(&self) -> f64 {
        let val = self.0 as f64;
        val / (Self::PRECISION as f64)
    }
}

impl From<i64> for Mutez {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl std::ops::Add for Mutez {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for Mutez {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl std::ops::Add<i64> for Mutez {
    type Output = Self;

    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl Display for Mutez {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} μtz", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Hash)]
/// Representation of a rational number as a numerator-denominator pair, both of which
/// are [`u16`]. The actual implementation is based on the generic [`num::rational::Ratio`] type.
pub struct RatioU16(Ratio<u16>);

impl RatioU16 {
    pub fn new(numer: u16, denom: u16) -> Self {
        Self(Ratio::new(numer, denom))
    }
}

impl std::ops::Deref for RatioU16 {
    type Target = Ratio<u16>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Ratio<u16>> for RatioU16 {
    fn from(value: Ratio<u16>) -> Self {
        Self(value)
    }
}

impl From<RatioU16> for Ratio<u16> {
    fn from(value: RatioU16) -> Self {
        value.0
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum VotingPeriodKind {
    Proposal = 0,
    Exploration = 1,
    Cooldown = 2,
    Promotion = 3,
    Adoption = 4,
}

impl std::fmt::Display for VotingPeriodKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VotingPeriodKind::Proposal => write!(f, "Proposal"),
            VotingPeriodKind::Exploration => write!(f, "Exploration"),
            VotingPeriodKind::Cooldown => write!(f, "Cooldown"),
            VotingPeriodKind::Promotion => write!(f, "Promotion"),
            VotingPeriodKind::Adoption => write!(f, "Adoption"),
        }
    }
}

impl VotingPeriodKind {
    pub const unsafe fn from_u8_unchecked(raw: u8) -> Self {
        std::mem::transmute::<u8, Self>(raw)
    }

    pub fn from_u8(raw: u8) -> Self {
        assert!(
            raw < 5,
            "Invalid raw u8 value for VotingPeriodKind: {raw} not in range [0..=4]"
        );
        unsafe { Self::from_u8_unchecked(raw) }
    }

    pub fn next(self) -> Self {
        let raw = self as u8;
        let next_raw = (raw + 1) % 5;
        unsafe { Self::from_u8_unchecked(next_raw) }
    }

    pub fn prev(self) -> Self {
        let raw = self as u8;
        let prev_raw = (raw + 4) % 5;
        unsafe { Self::from_u8_unchecked(prev_raw) }
    }
}
