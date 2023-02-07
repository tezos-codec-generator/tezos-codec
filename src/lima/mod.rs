use rustgen::proto015_ptlimapt::{ block_info, baking_rights, constants };

macro_rules! from_pkh {
    ($($id:ident),+ $(,)?) => {
        $(
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

from_pkh!(baking_rights, constants, block_info);

pub mod raw {
    pub use rustgen::proto015_ptlimapt::level::{ self as level };
    pub use rustgen::proto015_ptlimapt::constants::{ self as constants };
    pub use rustgen::proto015_ptlimapt::block_info::{ self as block_info };
    pub use rustgen::proto015_ptlimapt::baking_rights::{ self as baking_rights };

    pub(crate) use block_info::{ ChainId, Operation, Hash, RawBlockHeader, BlockHeaderMetadata };

    pub type BlockInfo = block_info::Proto015PtLimaPtBlockInfo;
    pub type OperationResult =
        block_info::Proto015PtLimaPtOperationAlphaSuccessfulManagerOperationResult;
    pub type BalanceUpdate = block_info::Proto015PtLimaPtOperationMetadataAlphaBalance;
    pub type MichelsonExpression = block_info::MichelineProto015PtLimaPtMichelsonV1Expression;
}

pub mod api {
    use rust_runtime::Dynamic;
    use rust_runtime::Sequence;
    use rust_runtime::u30;
    use super::raw::block_info::OperationDenestDyn;
    use super::raw::block_info::Proto015PtLimaPtOperationAlphaOperationWithMetadata;
    use super::raw::block_info::operationdenestdyn;
    use super::raw::block_info::proto015ptlimaptoperationalphaoperationwithmetadata;

    use crate::core::ProtocolHash;
    use crate::core::PublicKeyHashV0;
    use crate::traits::ContainsBallots;
    use crate::traits::Crypto;

    use super::block_info::Proto015PtLimaPtOperationAlphaContents;
    use super::raw;

    pub type LimaChainId = raw::ChainId;
    pub type LimaBlockHash = raw::Hash;
    pub type LimaBlockHeader = raw::RawBlockHeader;
    pub type LimaMetadata = raw::BlockHeaderMetadata;
    pub type LimaOperation = raw::Operation;

    #[repr(i8)]
    #[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub enum Ballot {
        Yay = 0,
        Nay = 1,
        Pass = 2,
    }

    impl Ballot {
        #[inline]
        /// Converts an [i8] to the corresponding Ballot value without
        /// checking that it is a valid element of the enumeration.
        ///
        /// # Safety
        ///
        /// This function performs an unchecked [std::mem::transmute] call
        /// which will produce undefined behavior if the value is not valid
        /// in the result type. This should only be called on values that are
        /// either statically known to fall in the correct range, or in code-paths
        /// that have filtered out all possible invalid values.
        pub const unsafe fn from_i8_unchecked(raw: i8) -> Self {
            std::mem::transmute::<i8, Ballot>(raw)
        }

        pub fn from_i8_checked(raw: i8) -> Self {
            assert!(matches!(raw, 0..=2));
            unsafe { Self::from_i8_unchecked(raw) }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct InvalidBallotError(i8);

    impl std::fmt::Display for InvalidBallotError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Invalid ballot: {} is not in the enum range (0..=2)", self.0)
        }
    }

    impl std::error::Error for InvalidBallotError {}

    impl TryFrom<i8> for Ballot {
        type Error = InvalidBallotError;

        fn try_from(value: i8) -> Result<Self, Self::Error> {
            match value {
                0..=2 => Ok(unsafe { Ballot::from_i8_unchecked(value) }),
                _ => Err(InvalidBallotError(value)),
            }
        }
    }

    impl std::fmt::Display for Ballot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Yay => write!(f, "yay"),
                Self::Nay => write!(f, "nay"),
                Self::Pass => write!(f, "pass"),
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct LimaBallot {
        source: PublicKeyHashV0,
        period: i32,
        proposal: ProtocolHash,
        ballot: Ballot,
    }

    impl std::fmt::Display for LimaBallot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Ballot {{ source: {}, period: {}, proposal: {}, ballot: {} }}",
                self.source.to_base58check(),
                self.period,
                self.proposal.to_base58check(),
                self.ballot
            )
        }
    }

    impl ContainsBallots for Proto015PtLimaPtOperationAlphaContents {
        type BallotType = LimaBallot;

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                Proto015PtLimaPtOperationAlphaContents::Ballot(ballot) => {
                    let source: PublicKeyHashV0 =
                        (&ballot.source.signature_v0_public_key_hash).into();
                    let period = ballot.period;
                    let proposal: crate::core::ProtocolHash = ballot.proposal.protocol_hash.into();
                    let ballot: Ballot = Ballot::from_i8_checked(ballot.ballot);
                    vec![LimaBallot { source, period, proposal, ballot }]
                }
                _ => vec![],
            }
        }
    }

    impl ContainsBallots
    for
    rustgen::proto015_ptlimapt::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResult {
        type BallotType = LimaBallot;

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                rustgen::proto015_ptlimapt::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResult::Ballot(
                    ballot,
                ) => {
                    let source: PublicKeyHashV0 =
                        (&ballot.source.signature_v0_public_key_hash).into();
                    let period = ballot.period;
                    let proposal = ProtocolHash::from(ballot.proposal.protocol_hash);
                    let ballot: Ballot = Ballot::from_i8_checked(ballot.ballot);
                    vec![LimaBallot { source, period, proposal, ballot }]
                }
                _ => vec![],
            }
        }
    }

    impl ContainsBallots for LimaOperation {
        type BallotType = LimaBallot;

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self.operation_rhs.1.as_ref() {
                OperationDenestDyn::Operation_with_too_large_metadata(
                    operationdenestdyn::Operation_with_too_large_metadata { contents, .. },
                ) =>
                    contents
                        .iter()
                        .flat_map(|op| op.get_ballots())
                        .collect(),
                OperationDenestDyn::Operation_without_metadata(
                    operationdenestdyn::Operation_without_metadata { contents, .. },
                ) =>
                    contents
                        .iter()
                        .flat_map(|op| op.get_ballots())
                        .collect(),
                OperationDenestDyn::Operation_with_metadata(
                    operationdenestdyn::Operation_with_metadata(op),
                ) =>
                    match op {
                        Proto015PtLimaPtOperationAlphaOperationWithMetadata::Operation_with_metadata(
                            proto015ptlimaptoperationalphaoperationwithmetadata::Operation_with_metadata {
                                contents,
                                ..
                            },
                        ) => {
                            contents
                                .as_ref()
                                .iter()
                                .flat_map(|op| op.get_ballots())
                                .collect()
                        }
                        Proto015PtLimaPtOperationAlphaOperationWithMetadata::Operation_without_metadata(
                            proto015ptlimaptoperationalphaoperationwithmetadata::Operation_without_metadata {
                                contents,
                                ..
                            },
                        ) =>
                            contents
                                .as_ref()
                                .iter()
                                .flat_map(|op| op.get_ballots())
                                .collect(),
                    }
            }
        }
    }

    /// Cross-module canonical type for Lima `block_info` values
    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct LimaBlockInfo {
        chain_id: LimaChainId,
        hash: LimaBlockHash,
        header: LimaBlockHeader,
        metadata: Option<LimaMetadata>,
        operations: Vec<Vec<LimaOperation>>,
    }

    fn unpack_operations(
        operations: Dynamic<u30, Sequence<Dynamic<u30, Dynamic<u30, Sequence<raw::Operation>>>>>
    ) -> Vec<Vec<raw::Operation>> {
        operations
            .into_inner()
            .into_iter()
            .map(|ddx| ddx.into_inner().into_inner().into_inner())
            .collect()
    }

    impl From<raw::BlockInfo> for LimaBlockInfo {
        fn from(value: raw::BlockInfo) -> Self {
            Self {
                chain_id: LimaChainId::from(value.chain_id),
                hash: LimaBlockHash::from(value.hash),
                header: LimaBlockHeader::from(value.header.into_inner()),
                metadata: value.metadata.map(|x| LimaMetadata::from(x.into_inner())),
                operations: unpack_operations(value.operations),
            }
        }
    }

    impl LimaBlockInfo {
        pub fn get_all_ballots(&self) -> Vec<LimaBallot> {
            self.operations
                .iter()
                .flat_map(|v| v.iter().flat_map(|op| op.get_ballots()))
                .collect()
        }
    }
}