use tezos_codegen::proto014_ptkathma::{block_info};


// TODO: implement minimal facade for Kathmandu

macro_rules! from_pkh {
    ($($id:ident),+ $(,)?) => {
        $(
            impl From<$crate::core::PublicKeyHashV0> for $id::PublicKeyHash {
                fn from(value: $crate::core::PublicKeyHashV0) -> Self {
                    use $id::publickeyhash::{ Ed25519, Secp256k1, P256 };
                    match value {
                        $crate::core::PublicKeyHashV0::Ed25519(ed25519_public_key_hash) => Self::Ed25519(Ed25519 { ed25519_public_key_hash }),
                        $crate::core::PublicKeyHashV0::Secp256k1(secp256k1_public_key_hash) => Self::Secp256k1(Secp256k1 { secp256k1_public_key_hash }),
                        $crate::core::PublicKeyHashV0::P256(p256_public_key_hash) => Self::P256(P256 { p256_public_key_hash }),
                    }
                }
            }

            impl From<&'_ $id::PublicKeyHash> for $crate::core::PublicKeyHashV0 {
                fn from(value: &'_ $id::PublicKeyHash) -> Self {
                    use $id::{ PublicKeyHash, publickeyhash::{ Ed25519, Secp256k1, P256 } };
                    match value {
                        PublicKeyHash::Ed25519(Ed25519 { ed25519_public_key_hash }) => Self::Ed25519(*ed25519_public_key_hash),
                        PublicKeyHash::Secp256k1(Secp256k1 { secp256k1_public_key_hash }) => Self::Secp256k1(*secp256k1_public_key_hash),
                        PublicKeyHash::P256(P256 { p256_public_key_hash }) => Self::P256(*p256_public_key_hash),
                    }
                }
            }

            impl From<$id::PublicKeyHash> for $crate::core::PublicKeyHashV0 {
                fn from(value: $id::PublicKeyHash) -> Self {
                    use $id::{ PublicKeyHash, publickeyhash::{ Ed25519, Secp256k1, P256 } };
                    match value {
                        PublicKeyHash::Ed25519(Ed25519 { ed25519_public_key_hash }) => Self::Ed25519(ed25519_public_key_hash),
                        PublicKeyHash::Secp256k1(Secp256k1 { secp256k1_public_key_hash }) => Self::Secp256k1(secp256k1_public_key_hash),
                        PublicKeyHash::P256(P256 { p256_public_key_hash }) => Self::P256(p256_public_key_hash),
                    }
                }
            }
        )+
    };
}

from_pkh!(block_info);

pub mod raw {
    pub use tezos_codegen::proto014_ptkathma::block_info;

    pub(crate) use block_info::{ Operation, RawBlockHeader, BlockHeaderMetadata };

    pub type BlockInfo = block_info::Proto014PtKathmaBlockInfo;
}