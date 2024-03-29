pub mod ballot;
pub mod base58;
pub mod rpc;
pub mod transaction;

use chrono::{DateTime, NaiveDateTime, Utc};
use std::{array::TryFromSliceError, fmt::Display, hint::unreachable_unchecked};

use num::rational::Ratio;
use tedium::FixedBytes;

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
    ($($(@ attr $m:meta for)? $tname:ident = $n:literal),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, tedium::Decode)]
            $( #[$m] )?
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

            impl TryFrom<Vec<u8>> for $tname {
                type Error = std::array::TryFromSliceError;

                fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                    Ok(Self::from_byte_array(value.as_slice().try_into()?))
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
    traits::{AsPayload, BinaryDataType, Crypto, CryptoExt, DynamicPrefix, StaticPrefix},
};

pub mod etc;
pub use etc::*;

boilerplate!(@attr derive(PartialOrd,Ord) for ContractHash = 20);

impl ContractHash {
    /// Preimage of ciphertext prefix `KT1`
    ///
    /// ```
    /// # use tezos_codec::{traits::Crypto, core::ContractHash};
    /// assert_eq!(ContractHash::from_byte_array([0u8; 20]).to_base58check().chars().take(3).collect::<String>(), "KT1");
    /// ```
    pub const BASE58_PREFIX: [u8; 3] = [2, 90, 121];
}

impl StaticPrefix for ContractHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for ContractHash {}

impl CryptoExt for ContractHash {
    type Error = CryptoDecodeError;

    fn reconstruct(preimage: Vec<u8>) -> Result<Self, Self::Error> {
        let (_pref, bytes) = preimage.split_at(Self::BASE58_PREFIX.len());
        if _pref == Self::BASE58_PREFIX {
            Ok(Self(bytes.try_into()?))
        } else {
            Err(CryptoDecodeError::UnexpectedPrefix {
                prefix_bytes: _pref.to_vec(),
            })
        }
    }
}

impl_crypto_display!(ContractHash);
impl_serde_crypto!(ContractHash);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ContractId<Pkh> {
    Implicit(Pkh),
    Originated(ContractHash),
}

impl<Pkh> ContractId<Pkh> {
    /// Returns the raw `[u8; 20]` payload of a [`ContractId<Pkh>`], ignoring any
    /// distinctions between implicit/originated accounts, and the cryptographic
    /// algorithm associated with the `Pkh` type (if applicable).
    pub fn as_array_ref(&self) -> &[u8; 20]
    where
        Pkh: AsRef<[u8; 20]>,
    {
        match self {
            ContractId::Implicit(pkh) => pkh.as_ref(),
            ContractId::Originated(ch) => ch.as_array_ref(),
        }
    }

    pub fn as_fixed_bytes(&self) -> &FixedBytes<20>
    where
        Pkh: AsRef<FixedBytes<20>>,
    {
        match self {
            ContractId::Implicit(pkh) => pkh.as_ref(),
            ContractId::Originated(ch) => ch.as_fixed_bytes(),
        }
    }
}

mod contract_id_impls {
    use super::{sealed::PKHType, *};
    use crate::traits::AsPayload;

    impl<Pkh: PKHType> AsPayload for ContractId<Pkh> {
        fn as_payload(&self) -> &[u8] {
            self.as_array_ref()
        }
    }

    impl<Pkh: PKHType> AsRef<[u8; 20]> for ContractId<Pkh> {
        fn as_ref(&self) -> &[u8; 20] {
            self.as_array_ref()
        }
    }

    impl<Pkh: PKHType> AsRef<[u8]> for ContractId<Pkh> {
        fn as_ref(&self) -> &[u8] {
            self.as_array_ref()
        }
    }

    impl<Pkh: PKHType> AsRef<FixedBytes<20>> for ContractId<Pkh> {
        fn as_ref(&self) -> &FixedBytes<20> {
            self.as_fixed_bytes()
        }
    }
}

mod sealed {
    pub trait PKHType:
        crate::traits::Crypto
        + AsRef<[u8; 20]>
        + AsRef<tedium::FixedBytes<20>>
        + crate::traits::CryptoExt<Error = super::CryptoDecodeError>
    {
    }

    impl PKHType for super::PublicKeyHashV0 {}
    impl PKHType for super::PublicKeyHashV1 {}
}

impl<Pkh: sealed::PKHType> From<Pkh> for ContractId<Pkh> {
    fn from(value: Pkh) -> Self {
        Self::Implicit(value)
    }
}

impl<Pkh: sealed::PKHType> From<ContractHash> for ContractId<Pkh> {
    fn from(value: ContractHash) -> Self {
        Self::Originated(value)
    }
}

impl<Pkh: Crypto> ContractId<Pkh> {
    /// Returns `true` if the contract id is [`Implicit`].
    ///
    /// [`Implicit`]: LimaContractId::Implicit
    #[must_use]
    pub fn is_implicit(&self) -> bool {
        matches!(self, Self::Implicit(..))
    }

    /// Returns `true` if the lima contract id is [`Originated`].
    ///
    /// [`Originated`]: LimaContractId::Originated
    #[must_use]
    pub fn is_originated(&self) -> bool {
        matches!(self, Self::Originated(..))
    }

    pub fn as_implicit(&self) -> Option<&Pkh> {
        if let Self::Implicit(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn as_originated(&self) -> Option<&ContractHash> {
        if let Self::Originated(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

impl<Pkh: sealed::PKHType> std::fmt::Display for ContractId<Pkh> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Crypto>::base58check_fmt(&self, f)
    }
}

impl<Pkh: DynamicPrefix> DynamicPrefix for ContractId<Pkh> {
    fn get_prefix(&self) -> &'static [u8] {
        match self {
            ContractId::Implicit(pkh) => pkh.get_prefix(),
            ContractId::Originated(ch) => ch.get_prefix(),
        }
    }
}

impl<Pkh: sealed::PKHType> Crypto for ContractId<Pkh> {}

impl<Pkh: sealed::PKHType> CryptoExt for ContractId<Pkh> {
    type Error = CryptoDecodeError;

    fn reconstruct(preimage: Vec<u8>) -> Result<Self, Self::Error> {
        if &preimage[..3] == ContractHash::BASE58_PREFIX {
            Ok(Self::Originated(ContractHash::reconstruct(preimage)?))
        } else {
            Ok(Self::Implicit(Pkh::reconstruct(preimage)?))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureV1 {
    SigV0(FixedBytes<64>),
    Bls(FixedBytes<96>),
}

#[derive(Debug)]
pub struct InvalidSignatureV1ByteLengthError(pub(crate) usize);

impl From<InvalidSignatureV1ByteLengthError> for tedium::parse::error::ExternalError {
    fn from(value: InvalidSignatureV1ByteLengthError) -> Self {
        Self::WidthViolation(tedium::error::WidthError::InvalidWidth {
            valid: &[64, 96usize],
            actual: value.0,
        })
    }
}

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

boilerplate!(BlindedPublicKeyHash = 20);

impl BlindedPublicKeyHash {
    /// Preimage of ciphertext preimage "btz1"
    ///
    /// ```
    /// # use tezos_codec::core::BlindedPublicKeyHash;
    /// # use tezos_codec::traits::Crypto;
    /// let bpkh = BlindedPublicKeyHash::from_byte_array([0u8; 20]);
    /// let image : String = bpkh.to_base58check();
    /// assert_eq!(&image[0..4], "btz1")
    /// ```
    pub const BASE58_PREFIX: [u8; 4] = [1, 2, 49, 223];
}

impl crate::traits::StaticPrefix for BlindedPublicKeyHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for BlindedPublicKeyHash {}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PublicKeyHashV0 {
    Ed25519(FixedBytes<20>),
    Secp256k1(FixedBytes<20>),
    P256(FixedBytes<20>),
}

pub mod pkh_macros {
    #[macro_export]
    macro_rules! pkh {
        (tz1: $x:expr) => {
            tz1!($x)
        };
        (tz2: $x:expr) => {
            tz2!($x)
        };
        (tz3: $x:expr) => {
            tz3!($x)
        };
        (tz4: $x:expr) => {
            tz4!($x)
        };
    }

    #[macro_export]
    macro_rules! kt1 {
        ($x:expr) => {
            $crate::core::ContractId::Originated($crate::core::ContractHash(
                $crate::FixedBytes::from($x),
            ))
        };
    }

    #[macro_export]
    macro_rules! tz1 {
        (@ v0 $x:expr) => {
            $crate::core::PublicKeyHashV0::Ed25519($crate::FixedBytes::from($x))
        };
        ($x:expr) => {
            $crate::core::PublicKeyHashV1::upcast($crate::tz1!(@v0 $x))
        };
    }

    #[macro_export]
    macro_rules! tz2 {
        (@ v0 $x:expr) => {
            $crate::core::PublicKeyHashV0::Secp256k1($crate::FixedBytes::from($x))
        };
        ($x:expr) => {
            $crate::core::PublicKeyHashV1::upcast($crate::tz2!(@v0 $x))
        };
    }

    #[macro_export]
    macro_rules! tz3 {
        (@ v0 $x:expr) => {
            $crate::core::PublicKeyHashV0::P256($crate::FixedBytes::from($x))
        };
        ($x:expr) => {
            $crate::core::PublicKeyHashV1::upcast($crate::tz3!(@v0 $x))
        };
    }

    #[macro_export]
    macro_rules! tz4 {
        ($x:expr) => {
            $crate::core::PublicKeyHashV1::Bls($crate::FixedBytes::from($x))
        };
    }
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

#[derive(Debug)]
pub enum CryptoDecodeError {
    FromSlice(std::array::TryFromSliceError),
    UnexpectedPrefix { prefix_bytes: Vec<u8> },
}

impl std::fmt::Display for CryptoDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoDecodeError::FromSlice(s_err) => write!(f, "CryptoExt decoding error: {}", s_err),
            CryptoDecodeError::UnexpectedPrefix { prefix_bytes } => {
                write!(f, "unexpected base58check prefix `{:#?}`", prefix_bytes)
            }
        }
    }
}

impl std::error::Error for CryptoDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoDecodeError::FromSlice(s) => Some(s),
            CryptoDecodeError::UnexpectedPrefix { .. } => None,
        }
    }
}

impl From<TryFromSliceError> for CryptoDecodeError {
    fn from(value: TryFromSliceError) -> Self {
        Self::FromSlice(value)
    }
}

impl Crypto for PublicKeyHashV0 {}

impl CryptoExt for PublicKeyHashV0 {
    type Error = CryptoDecodeError;

    fn reconstruct(preimage: Vec<u8>) -> Result<Self, Self::Error> {
        let (pref, bytes) = preimage.split_at(3);
        match pref {
            _ if pref == Self::ED25519_BASE58_PREFIX => Ok(Self::Ed25519(bytes.try_into()?)),
            _ if pref == Self::SECP256K1_BASE58_PREFIX => Ok(Self::Secp256k1(bytes.try_into()?)),
            _ if pref == Self::P256_BASE58_PREFIX => Ok(Self::P256(bytes.try_into()?)),
            _ => Err(CryptoDecodeError::UnexpectedPrefix {
                prefix_bytes: pref.to_vec(),
            }),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
        write!(
            f,
            "cannot downcast: cryptographic algorithm unsupported in target type"
        )
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

impl CryptoExt for PublicKeyHashV1 {
    type Error = CryptoDecodeError;

    fn reconstruct(preimage: Vec<u8>) -> Result<Self, Self::Error> {
        let (pref, bytes) = preimage.split_at(3);
        match pref {
            _ if pref == Self::BLS12_381_BASE58_PREFIX => Ok(Self::Bls(bytes.try_into()?)),
            _ => Ok(Self::PkhV0(PublicKeyHashV0::reconstruct(preimage)?)),
        }
    }
}

#[derive(Debug)]
pub struct AnachronisticTimestampError(i64);

impl std::fmt::Display for AnachronisticTimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "epoch offset `{}` outside of conceivable time-range",
            self.0
        )
    }
}

impl std::error::Error for AnachronisticTimestampError {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(i64);

impl TryFrom<Timestamp> for DateTime<Utc> {
    type Error = AnachronisticTimestampError;

    fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
        let secs = value.0;
        if let Some(datetime) = NaiveDateTime::from_timestamp_opt(secs, 0) {
            Ok(DateTime::<Utc>::from_utc(datetime, Utc))
        } else {
            Err(AnachronisticTimestampError(secs))
        }
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self(i64::deserialize(deserializer)?))
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if let Ok(utc) = <Timestamp as TryInto<DateTime<Utc>>>::try_into(*self) {
            utc.serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(utc_date) = DateTime::<Utc>::try_from(*self) {
            write!(f, "{}", utc_date.to_rfc3339())
        } else {
            write!(f, "{:?}", self)
        }
    }
}

impl Timestamp {
    #[inline]
    #[must_use]
    /// Upcasts an [`i64`] to a representationally equivalent [`Timestamp`].
    pub const fn from_i64(i: i64) -> Self {
        Self(i)
    }

    /// Converts this [`Timestamp`] to the corresponding [`DateTime<Utc>`] value
    ///
    /// # Panics
    ///
    /// Panics if the timestamp is fundamentally too large to convert to a [`DateTime<Utc>`].
    #[must_use]
    pub fn to_utc(&self) -> DateTime<Utc> {
        let ret = (*self).try_into().unwrap_or_else(|err| panic!("{err}"));
        ret
    }

    #[inline]
    pub fn try_to_utc(&self) -> Result<DateTime<Utc>, AnachronisticTimestampError> {
        (*self).try_into()
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

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn epoch_test() {
        let utc: DateTime<Utc> = DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .into();
        assert_eq!(Timestamp::from_i64(0).to_utc(), utc);
    }
}

pub mod mutez {
    use std::fmt::Display;

    use num::{Integer, ToPrimitive};
    use num_bigint::BigUint;
    use tedium::Decode;

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
    pub struct Mutez(i64);

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

    #[repr(transparent)]
    #[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct MutezPlus(BigUint);

    impl From<BigUint> for MutezPlus {
        fn from(value: BigUint) -> Self {
            Self(value)
        }
    }

    mod _impls {
        use num_bigint::BigUint;

        macro_rules! impl_from_integral {
            (@ from $($t:ident),+ $(,)?) => {
                $(
                    impl From<$t> for $crate::core::mutez::MutezPlus {
                        fn from(value: $t) -> Self {
                            Self::from_biguint(BigUint::from(value))
                        }
                    }
                )+
            };
            (@ tryfrom $($t:ident),+ $(,)?) => {
               $(
                    impl TryFrom<$t> for $crate::core::mutez::MutezPlus {
                        type Error = <BigUint as TryFrom<$t>>::Error;

                        fn try_from(value: $t) -> Result<Self, Self::Error> {
                            Ok(Self::from_biguint(BigUint::try_from(value)?))
                        }
                    }
                )+
            };
        }

        impl_from_integral!(@from u8, u16, u32, u64, u128);
        impl_from_integral!(@tryfrom i8, i16, i32, i64, i128);
    }

    impl std::ops::Add for MutezPlus {
        type Output = MutezPlus;

        fn add(self, rhs: Self) -> Self::Output {
            MutezPlus(self.0 + rhs.0)
        }
    }

    impl serde::Serialize for MutezPlus {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let tmp = format!("{self}");
            serializer.serialize_str(&tmp)
        }
    }

    impl MutezPlus {
        pub const PRECISION: u64 = 1_000_000;

        pub const fn from_biguint(mutez: BigUint) -> Self {
            Self(mutez)
        }

        pub const fn as_biguint(&self) -> &BigUint {
            &self.0
        }

        pub fn into_biguint(self) -> BigUint {
            self.0
        }

        pub fn to_parts(&self) -> (BigUint, u64) {
            let (radix, big_mantissa) = self.0.div_rem(&BigUint::from(Self::PRECISION));
            let mantissa: u64 = big_mantissa
                .to_u64()
                .unwrap_or_else(||
                    unreachable!(
                        "Impossible: Remainder of division by 1e6 failed to be converted to u64(!?) [value: {big_mantissa}]"
                    )
                );
            (radix, mantissa)
        }

        /// Returns a string representation of the decimal value of this [`MutezPlus`] instance,
        /// with an implicit unit of `tez`.
        ///
        /// The numeric formatting is done using the standard Display for integers, and so it will
        /// not include any separators between digits. For more readable or otherwise more customizable
        /// formatting, see [`format_parts`].
        pub fn to_xtz_string(&self) -> String {
            let (radix, mantissa) = self.to_parts();
            format!("{radix}.{mantissa}")
        }

        /// Calls an arbitrary function that maps the radix and mantissa of a [`MutezPlus`] instance
        /// into a formatted string.
        ///
        /// This function is provided as a convenience for end-users who want more control over
        /// the display format of [`MutezPlus`] values than provided by the [`std::fmt::Debug`] and [`std::fmt::Display`]
        /// traits implementations, or the [`to_xtz_string`] associated method.
        pub fn format_parts<F>(&self, f: F) -> String
        where
            F: FnOnce(BigUint, u64) -> String,
        {
            let (radix, mantissa) = self.to_parts();
            f(radix, mantissa)
        }

        pub fn to_tez_lossy(&self) -> f64 {
            let (radix, mantissa) = self.to_parts();
            if let Some(f_radix) = radix.to_f64() {
                f_radix + (mantissa as f64) / (Self::PRECISION as f64)
            } else {
                unreachable!("f64 should encompass BigUint radixes")
            }
        }
    }

    impl TryFrom<Mutez> for MutezPlus {
        type Error = <BigUint as TryFrom<i64>>::Error;

        fn try_from(value: Mutez) -> Result<Self, Self::Error> {
            let amount = value.0.try_into()?;
            Ok(Self::from_biguint(amount))
        }
    }

    impl TryFrom<MutezPlus> for Mutez {
        type Error = <i64 as TryFrom<BigUint>>::Error;

        fn try_from(value: MutezPlus) -> Result<Self, Self::Error> {
            let amount = value.0.try_into()?;
            Ok(Self::from_i64(amount))
        }
    }

    impl std::fmt::Display for MutezPlus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{} μtz", self.0)
        }
    }

    #[macro_export]
    macro_rules! mtz {
        ($amount:expr) => {
            $crate::core::mutez::Mutez::from_i64($amount)
        };
        (@ n $amount:expr) => {
            $crate::core::mutez::MutezPlus::from($amount)
        };
    }

    #[cfg(test)]
    mod mtz_macro_test {
        use super::*;
        use crate::mtz;

        #[test]
        fn mtz_macro_numlit() {
            let hundred = mtz!(100);
            assert_eq!(hundred, Mutez::from(100));
        }

        #[test]
        fn mtz_macro_underscore() {
            let million = mtz!(1_000_000);
            assert_eq!(million, Mutez::from(1_000_000));
        }

        #[test]
        fn mtz_macro_arithmetic() {
            let fortytwo = mtz!(40 + 2);
            assert_eq!(fortytwo, Mutez::from_i64(42));
        }

        #[test]
        fn mtz_macro_lvalue() {
            let x: i64 = 1234;
            let x_mtz = mtz!(x);
            assert_eq!(x_mtz, Mutez::from_i64(x));
        }
    }
}

pub use mutez::{Mutez, MutezPlus};

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

pub struct InvalidDiscriminantError<T> {
    raw: u8,
    _proxy: std::marker::PhantomData<T>,
}

impl<T> InvalidDiscriminantError<T> {
    pub(self) fn from_raw(raw: u8) -> Self
    where
        T: std::any::Any,
    {
        Self {
            raw,
            _proxy: std::marker::PhantomData::<T>,
        }
    }
}

impl<T: std::any::Any> std::fmt::Debug for InvalidDiscriminantError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvalidDiscriminantError")
            .field("raw", &self.raw)
            .finish()
    }
}

impl<T: std::any::Any> std::fmt::Display for InvalidDiscriminantError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "value {} is invalid as a discriminant byte for type {}",
            self.raw,
            std::any::type_name::<T>()
        )
    }
}

impl<T: std::any::Any> std::error::Error for InvalidDiscriminantError<T> {}

impl VotingPeriodKind {
    pub const unsafe fn from_u8_unchecked(raw: u8) -> Self {
        std::mem::transmute::<u8, Self>(raw)
    }

    /// Attempts to convert a raw `u8`-encoded voting period discriminant (as obtained by parsing the raw binary)
    /// into a valid variant of [`VotingPeriodKind`].
    ///
    /// # Panics
    ///
    /// Will panic if `raw` is invalid as a discriminant of this type (i.e. `raw > 4`).
    pub fn from_u8(raw: u8) -> Self {
        assert!(
            raw < 5,
            "Invalid raw u8 value for VotingPeriodKind: {raw} not in range [0..=4]"
        );
        unsafe { Self::from_u8_unchecked(raw) }
    }

    pub fn try_from_u8(raw: u8) -> Result<Self, InvalidDiscriminantError<Self>> {
        match raw {
            0..=4 => unsafe { Ok(Self::from_u8_unchecked(raw)) },
            _ => Err(InvalidDiscriminantError::<Self>::from_raw(raw)),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn tz1_roundtrip_pkhv0(raw: [u8; 20]) {
            let input = crate::tz1!(@v0 raw);
            let oput = input.to_base58check();
            match PublicKeyHashV0::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn tz1_roundtrip_pkhv1(raw: [u8; 20]) {
            let input = crate::tz1!(raw);
            let oput = input.to_base58check();
            match PublicKeyHashV1::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn tz2_roundtrip_pkhv0(raw: [u8; 20]) {
            let input = crate::tz2!(@v0 raw);
            let oput = input.to_base58check();
            match PublicKeyHashV0::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn tz2_roundtrip_pkhv1(raw: [u8; 20]) {
            let input = crate::tz2!(raw);
            let oput = input.to_base58check();
            match PublicKeyHashV1::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn tz3_roundtrip_pkhv0(raw: [u8; 20]) {
            let input = crate::tz3!(@v0 raw);
            let oput = input.to_base58check();
            match PublicKeyHashV0::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn tz3_roundtrip_pkhv1(raw: [u8; 20]) {
            let input = crate::tz3!(raw);
            let oput = input.to_base58check();
            match PublicKeyHashV1::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn tz4_roundtrip(raw: [u8; 20]) {
            let input = crate::tz4!(raw);
            let oput = input.to_base58check();
            match PublicKeyHashV1::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }

        #[test]
        fn kt1_roundtrip(raw: [u8; 20]) {
            let input = crate::kt1!(raw);
            let oput = input.to_base58check();
            match ContractId::<PublicKeyHashV1>::parse_base58check(&oput) {
                Ok(rt) => assert_eq!(input, rt),
                Err(e) => panic!("Failure in case `{oput}`: {e}"),
            }
        }
    }
}
