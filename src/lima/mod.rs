use rustgen::proto015_ptlimapt::{ block_info, baking_rights, constants };

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

from_pkh!(baking_rights, constants, block_info);

pub mod raw {
    pub use rustgen::proto015_ptlimapt::level::{ self as level };
    pub use rustgen::proto015_ptlimapt::constants::{ self as constants };
    pub use rustgen::proto015_ptlimapt::block_info::{ self as block_info };
    pub use rustgen::proto015_ptlimapt::baking_rights::{ self as baking_rights };

    pub(crate) use block_info::{
        Operation,
        OperationHash,
        RawBlockHeader,
        BlockHeaderMetadata,
    };

    pub type BlockInfo = block_info::Proto015PtLimaPtBlockInfo;
    pub type OperationResult =
        block_info::Proto015PtLimaPtOperationAlphaSuccessfulManagerOperationResult;
    pub type BalanceUpdate = block_info::Proto015PtLimaPtOperationMetadataAlphaBalance;
    pub type MichelsonExpression = block_info::MichelineProto015PtLimaPtMichelsonV1Expression;

    macro_rules! impl_crypto {
        ($($tname:path),+ $(,)?) => {
        $( impl $crate::traits::AsPayload for $tname {
            fn as_payload(&self) -> &[u8] {
                match &self.signature_v0_public_key_hash {
                    baking_rights::PublicKeyHash::Ed25519(x) => x.ed25519_public_key_hash.as_slice(),
                    baking_rights::PublicKeyHash::Secp256k1(x) => x.secp256k1_public_key_hash.as_slice(),
                    baking_rights::PublicKeyHash::P256(x) => x.p256_public_key_hash.as_slice(),
                }
            }
        }

        impl $crate::traits::DynamicPrefix for $tname {
            fn get_prefix(&self) -> &'static [u8] {
                match &self.signature_v0_public_key_hash {
                    baking_rights::PublicKeyHash::Ed25519(_) => &$crate::core::PublicKeyHashV0::ED25519_BASE58_PREFIX,
                    baking_rights::PublicKeyHash::Secp256k1(_) => &$crate::core::PublicKeyHashV0::SECP256K1_BASE58_PREFIX,
                    baking_rights::PublicKeyHash::P256(_) => &$crate::core::PublicKeyHashV0::P256_BASE58_PREFIX,
                }
            }
        }

        impl $crate::traits::Crypto for $tname {}
        )+
        };
    }

    impl_crypto!(baking_rights::Delegate, baking_rights::ConsensusKey);
}

pub mod api {
    use rust_runtime::{ Dynamic, Sequence, u30 };
    use super::raw::{
        self,
        block_info::{
            Proto015PtLimaPtOperationAlphaOperationContentsAndResult,
            OperationDenestDyn,
            Proto015PtLimaPtOperationAlphaOperationWithMetadata,
        },
    };

    use crate::{ core::{ ProtocolHash, PublicKeyHashV0 }, traits::{ ContainsBallots, Crypto } };

    use super::block_info::Proto015PtLimaPtOperationAlphaContents;

    pub type LimaBlockHeader = raw::RawBlockHeader;
    pub type LimaMetadata = raw::BlockHeaderMetadata;
    pub type LimaOperationHash = raw::OperationHash;
    pub type LimaOperationShellHeader = raw::block_info::OperationShellHeader;

    /// Cross-module canonical type for Lima `block_info` values
    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct LimaBlockInfo {
        chain_id: crate::core::ChainId,
        hash: crate::core::BlockHash,
        header: LimaBlockHeader,
        metadata: Option<LimaMetadata>,
        operations: Vec<Vec<LimaOperation>>,
    }

    fn unpack_block_operations(
        operations: Dynamic<u30, Sequence<Dynamic<u30, Dynamic<u30, Sequence<raw::Operation>>>>>
    ) -> Vec<Vec<LimaOperation>> {
        operations
            .into_inner()
            .into_iter()
            .map(|ddx|
                ddx
                    .into_inner()
                    .into_inner()

                    .into_iter()
                    .map(|op| op.into())
                    .collect::<Vec<_>>()
            )
            .collect()
    }

    impl From<raw::BlockInfo> for LimaBlockInfo {
        fn from(value: raw::BlockInfo) -> Self {
            Self {
                chain_id: crate::core::ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: crate::core::BlockHash::from(value.hash.block_hash),
                header: LimaBlockHeader::from(value.header.into_inner()),
                metadata: value.metadata.map(|x| LimaMetadata::from(x.into_inner())),
                operations: unpack_block_operations(value.operations),
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

        pub fn metadata(&self) -> &Option<LimaMetadata> {
            &self.metadata
        }

        pub fn metadata_mut(&mut self) -> &mut Option<LimaMetadata> {
            &mut self.metadata
        }

        pub fn operations(&self) -> &Vec<Vec<LimaOperation>> {
            &self.operations
        }

        pub fn operations_mut(&mut self) -> &mut Vec<Vec<LimaOperation>> {
            &mut self.operations
        }

        pub fn chain_id(&self) -> &crate::core::ChainId {
            &self.chain_id
        }

        pub fn hash(&self) -> &crate::core::BlockHash {
            &self.hash
        }

        pub fn header(&self) -> &LimaBlockHeader {
            &self.header
        }
    }
    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct LimaOperationPayload {
        shell_header: LimaOperationShellHeader,
        operation: LimaOperationContainer,
    }

    impl ContainsBallots for LimaOperationPayload {
        type BallotType = LimaBallot;

        fn has_ballots(&self) -> bool {
            self.operation.has_ballots()
        }

        fn count_ballots(&self) -> usize {
            self.operation.count_ballots()
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            self.operation.get_ballots()
        }
    }

    impl From<super::raw::block_info::OperationRhs> for LimaOperationPayload {
        fn from(value: super::raw::block_info::OperationRhs) -> Self {
            Self {
                shell_header: value.0.into_inner(),
                operation: LimaOperationContainer::from(value.1.into_inner()),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub enum LimaOperationContainer {
        WithMetadata {
            contents: Vec<LimaOperationContentsAndResult>,
            signature: Option<crate::core::SignatureV0>,
        },
        WithoutMetadata {
            contents: Vec<LimaOperationContents>,
            signature: Option<crate::core::SignatureV0>,
        },
    }

    impl ContainsBallots for LimaOperationContainer {
        type BallotType = LimaBallot;

        fn has_ballots(&self) -> bool {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().any(ContainsBallots::has_ballots),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().any(ContainsBallots::has_ballots),
            }
        }

        fn count_ballots(&self) -> usize {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().map(ContainsBallots::count_ballots).sum(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().map(ContainsBallots::count_ballots).sum(),
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().flat_map(ContainsBallots::get_ballots).collect(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().flat_map(ContainsBallots::get_ballots).collect(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    #[non_exhaustive]
    pub enum LimaOperationContents {
        Ballot(LimaBallot),
        Raw(super::raw::block_info::Proto015PtLimaPtOperationAlphaContents),
    }

    impl From<RawOpContents> for LimaOperationContents {
        fn from(value: RawOpContents) -> Self {
            match value {
                Proto015PtLimaPtOperationAlphaContents::Ballot(ballot) => {
                    Self::Ballot(
                        LimaBallot::try_from(ballot).unwrap_or_else(|err|
                            panic!("Error converting ballot: {}", err)
                        )
                    )
                }
                _other => Self::Raw(_other),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    #[non_exhaustive]
    pub enum LimaOperationContentsAndResult {
        Ballot(LimaBallot),
        Raw(super::raw::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResult),
    }

    impl From<RawOpContentsAndResult> for LimaOperationContentsAndResult {
        fn from(value: RawOpContentsAndResult) -> Self {
            match value {
                Proto015PtLimaPtOperationAlphaOperationContentsAndResult::Ballot(ballot) => {
                    Self::Ballot(
                        LimaBallot::try_from(ballot).unwrap_or_else(|err|
                            panic!("Error converting ballot: {}", err)
                        )
                    )
                }
                other => Self::Raw(other),
            }
        }
    }

    impl ContainsBallots for LimaOperationContentsAndResult {
        type BallotType = LimaBallot;

        fn has_ballots(&self) -> bool {
            matches!(self, &LimaOperationContentsAndResult::Ballot(_))
        }

        fn count_ballots(&self) -> usize {
            match self {
                LimaOperationContentsAndResult::Ballot(_) => 1,
                LimaOperationContentsAndResult::Raw(_) => 0,
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                &LimaOperationContentsAndResult::Ballot(ret) => vec![ret],
                LimaOperationContentsAndResult::Raw(_) => Vec::new(),
            }
        }
    }

    type RawOpContents = Proto015PtLimaPtOperationAlphaContents;
    type RawOpContentsAndResult = Proto015PtLimaPtOperationAlphaOperationContentsAndResult;

    fn unpack_operation_contents(contents: Sequence<RawOpContents>) -> Vec<LimaOperationContents> {
        contents
            .into_iter()
            .map(|raw_op| LimaOperationContents::from(raw_op))
            .collect()
    }

    fn unpack_operation_contents_and_result(
        contents: Sequence<RawOpContentsAndResult>
    ) -> Vec<LimaOperationContentsAndResult> {
        contents
            .into_iter()
            .map(|raw_op_and_result| LimaOperationContentsAndResult::from(raw_op_and_result))
            .collect()
    }

    impl From<super::raw::block_info::OperationDenestDyn> for LimaOperationContainer {
        fn from(value: super::raw::block_info::OperationDenestDyn) -> Self {
            match value {
                OperationDenestDyn::Operation_with_too_large_metadata(
                    super::raw::block_info::operationdenestdyn::Operation_with_too_large_metadata {
                        contents,
                        signature,
                    },
                ) =>
                    Self::WithoutMetadata {
                        contents: unpack_operation_contents(contents),
                        signature: Some(crate::core::SignatureV0::from(signature.signature_v0)),
                    },
                OperationDenestDyn::Operation_without_metadata(
                    super::raw::block_info::operationdenestdyn::Operation_without_metadata {
                        contents,
                        signature,
                    },
                ) =>
                    Self::WithoutMetadata {
                        contents: unpack_operation_contents(contents),
                        signature: Some(crate::core::SignatureV0::from(signature.signature_v0)),
                    },
                OperationDenestDyn::Operation_with_metadata(
                    super::raw::block_info::operationdenestdyn::Operation_with_metadata(inner),
                ) => {
                    use super::raw::block_info::{
                        proto015ptlimaptoperationalphaoperationwithmetadata::{
                            Operation_with_metadata,
                            Operation_without_metadata,
                        },
                    };
                    match inner {
                        Proto015PtLimaPtOperationAlphaOperationWithMetadata::Operation_with_metadata(
                            Operation_with_metadata { contents, signature },
                        ) => {
                            Self::WithMetadata {
                                contents: unpack_operation_contents_and_result(
                                    contents.into_inner()
                                ),
                                signature: signature.map(|sig| sig.signature_v0.into()),
                            }
                        }
                        Proto015PtLimaPtOperationAlphaOperationWithMetadata::Operation_without_metadata(
                            Operation_without_metadata { contents, signature },
                        ) => {
                            Self::WithoutMetadata {
                                contents: unpack_operation_contents(contents.into_inner()),
                                signature: signature.map(|sig| sig.signature_v0.into()),
                            }
                        }
                    }
                }
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct LimaOperation {
        chain_id: crate::core::ChainId,
        hash: LimaOperationHash,
        operation: LimaOperationPayload,
    }

    impl From<super::raw::block_info::Operation> for LimaOperation {
        fn from(value: super::raw::block_info::Operation) -> Self {
            Self {
                chain_id: crate::core::ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: value.hash,
                operation: LimaOperationPayload::from(value.operation_rhs),
            }
        }
    }

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

    impl LimaBallot {
        pub fn new(
            source: PublicKeyHashV0,
            period: i32,
            proposal: ProtocolHash,
            ballot: Ballot
        ) -> Self {
            Self { source, period, proposal, ballot }
        }

        pub fn source(&self) -> PublicKeyHashV0 {
            self.source
        }

        pub fn period(&self) -> i32 {
            self.period
        }

        pub fn proposal(&self) -> ProtocolHash {
            self.proposal
        }

        pub fn ballot(&self) -> Ballot {
            self.ballot
        }
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

    impl TryFrom<super::raw::block_info::proto015ptlimaptoperationalphacontents::Ballot>
    for LimaBallot {
        type Error = InvalidBallotError;

        fn try_from(
            value: super::raw::block_info::proto015ptlimaptoperationalphacontents::Ballot
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                source: crate::core::PublicKeyHashV0::from(
                    value.source.signature_v0_public_key_hash
                ),
                period: value.period,
                proposal: crate::core::ProtocolHash::from(value.proposal.protocol_hash),
                ballot: value.ballot.try_into()?,
            })
        }
    }

    impl TryFrom<super::raw::block_info::proto015ptlimaptoperationalphaoperationcontentsandresult::Ballot>
    for LimaBallot {
        type Error = InvalidBallotError;

        fn try_from(
            value: super::raw::block_info::proto015ptlimaptoperationalphaoperationcontentsandresult::Ballot
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                source: crate::core::PublicKeyHashV0::from(
                    value.source.signature_v0_public_key_hash
                ),
                period: value.period,
                proposal: crate::core::ProtocolHash::from(value.proposal.protocol_hash),
                ballot: value.ballot.try_into()?,
            })
        }
    }

    impl ContainsBallots
    for
    rustgen::proto015_ptlimapt::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResult {
        type BallotType = LimaBallot;

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                Self::Ballot(ballot) => {
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

        fn has_ballots(&self) -> bool {
            matches!(self, &Self::Ballot(_))
        }

        fn count_ballots(&self) -> usize {
            match self {
                Self::Ballot(_) => 1,
                _ => 0,
            }
        }
    }

    impl ContainsBallots for LimaOperationContents {
        type BallotType = LimaBallot;

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                &LimaOperationContents::Ballot(ballot) => vec![ballot],
                LimaOperationContents::Raw(_) => Vec::new(),
            }
        }

        fn has_ballots(&self) -> bool {
            matches!(self, &LimaOperationContents::Ballot(_))
        }

        fn count_ballots(&self) -> usize {
            match self {
                LimaOperationContents::Ballot(_) => 1,
                LimaOperationContents::Raw(_) => 0,
            }
        }
    }

    impl ContainsBallots for LimaOperation {
        type BallotType = LimaBallot;

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match &self.operation.operation {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents
                        .iter()
                        .flat_map(|op| op.get_ballots())
                        .collect(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents
                        .iter()
                        .flat_map(|op| op.get_ballots())
                        .collect(),
            }
        }

        fn has_ballots(&self) -> bool {
            match &self.operation.operation {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().any(|op| op.has_ballots()),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().any(|op| op.has_ballots()),
            }
        }

        fn count_ballots(&self) -> usize {
            match &self.operation.operation {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents
                        .iter()
                        .map(|op| op.count_ballots())
                        .sum(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents
                        .iter()
                        .map(|op| op.count_ballots())
                        .sum(),
            }
        }
    }
}