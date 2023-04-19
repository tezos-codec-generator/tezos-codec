use tezos_codegen::proto015_ptlimapt::{ baking_rights, block_info, constants };

pub mod error {
    use std::convert::Infallible;

    use crate::core::{ ballot::InvalidBallotError, InvalidDiscriminantError, VotingPeriodKind };

    #[derive(Debug)]
    pub enum LimaConversionError {
        Ballot(InvalidBallotError),
        VPKDisc(InvalidDiscriminantError<VotingPeriodKind>),
    }

    impl std::fmt::Display for LimaConversionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                LimaConversionError::Ballot(b_err) => write!(f, "{b_err}"),
                LimaConversionError::VPKDisc(vpk_err) => write!(f, "{vpk_err}"),
            }
        }
    }

    impl std::error::Error for LimaConversionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                LimaConversionError::Ballot(b_err) => Some(b_err),
                LimaConversionError::VPKDisc(vpk_err) => Some(vpk_err),
            }
        }
    }

    impl From<InvalidBallotError> for LimaConversionError {
        fn from(value: InvalidBallotError) -> Self {
            Self::Ballot(value)
        }
    }

    impl From<InvalidDiscriminantError<VotingPeriodKind>> for LimaConversionError {
        fn from(value: InvalidDiscriminantError<VotingPeriodKind>) -> Self {
            Self::VPKDisc(value)
        }
    }

    impl From<Infallible> for LimaConversionError {
        fn from(value: Infallible) -> Self {
            match value {
            }
        }
    }
}

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
    pub use tezos_codegen::proto015_ptlimapt::baking_rights;
    pub use tezos_codegen::proto015_ptlimapt::block_info;
    pub use tezos_codegen::proto015_ptlimapt::constants;
    pub use tezos_codegen::proto015_ptlimapt::level;

    pub(crate) use block_info::{ BlockHeaderMetadata, Operation, RawBlockHeader };

    pub type BlockInfo = block_info::Proto015PtLimaPtBlockInfo;
    pub type OperationResult =
        block_info::Proto015PtLimaPtOperationAlphaSuccessfulManagerOperationResult;
    pub type BalanceUpdate = block_info::Proto015PtLimaPtOperationMetadataAlphaBalance;
    pub type MichelsonExpression = block_info::MichelineProto015PtLimaPtMichelsonV1Expression;
    pub type Constants = constants::Proto015PtLimaPtConstants;

    macro_rules! impl_crypto {
        ($($tname:path),+ $(,)?) => {
        $( impl $crate::traits::AsPayload for $tname {
            fn as_payload(&self) -> &[u8] {
                match &self.signature_v0_public_key_hash {
                    baking_rights::PublicKeyHash::Ed25519(x) => x.ed25519_public_key_hash.bytes(),
                    baking_rights::PublicKeyHash::Secp256k1(x) => x.secp256k1_public_key_hash.bytes(),
                    baking_rights::PublicKeyHash::P256(x) => x.p256_public_key_hash.bytes(),
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
    use super::{
        error::LimaConversionError,
        raw::{
            self,
            block_info::{
                proto015ptlimaptcontractid::Originated,
                OperationDenestDyn,
                Proto015PtLimaPtBlockHeaderAlphaMetadataNonceHash,
                Proto015PtLimaPtOperationAlphaContents,
                Proto015PtLimaPtOperationAlphaOperationContentsAndResult,
                Proto015PtLimaPtOperationAlphaOperationWithMetadata,
            },
        },
    };
    use num_bigint::{ BigInt, BigUint };
    use tedium::{ u30, Dynamic, Sequence };
    use tezos_codegen::proto015_ptlimapt::{
        block_info::{
            proto015ptlimaptcontractid::Implicit,
            Proto015PtLimaPtContractId,
            Proto015PtLimaPtEntrypoint,
        },
        constants::{
            Proto015PtLimaPtConstantsMinimalParticipationRatio,
            Proto015PtLimaPtConstantsRatioOfFrozenDepositsSlashedPerDoubleEndorsement,
        },
    };

    use crate::{
        core::{
            ballot::{ self, Ballot, InvalidBallotError },
            mutez::MutezPlus,
            BlockHash,
            ChainId,
            ContractHash,
            InvalidDiscriminantError,
            NonceHash,
            ProtocolHash,
            PublicKeyHashV0,
            RatioU16,
            VotingPeriodKind,
            ContractId,
            // Mutez,
            transaction::Entrypoint,
        },
        traits::{ ContainsBallots, ContainsProposals, Crypto, ContainsTransactions },
        util::abstract_unpack_dynseq,
    };

    /// Cross-module canonical type for Lima `block_info` values
    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct LimaBlockInfo {
        chain_id: ChainId,
        hash: BlockHash,
        header: LimaBlockHeader,
        metadata: Option<LimaMetadata>,
        operations: Vec<Vec<LimaOperation>>,
    }

    impl tedium::Decode for LimaBlockInfo {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
            let raw: raw::BlockInfo = raw::BlockInfo::parse(p)?;
            Ok(raw.try_into().map_err(tedium::ParseError::reify)?)
        }
    }

    fn unpack_block_operations(
        operations: Dynamic<u30, Sequence<Dynamic<u30, Dynamic<u30, Sequence<raw::Operation>>>>>
    ) -> Result<Vec<Vec<LimaOperation>>, LimaConversionError> {
        operations
            .into_inner()
            .into_iter()
            .map(|ddx| {
                ddx.into_inner()
                    .into_inner()
                    .into_iter()
                    .map(|op| op.try_into())
                    .collect::<Result<Vec<LimaOperation>, LimaConversionError>>()
            })
            .collect()
    }

    impl TryFrom<raw::BlockInfo> for LimaBlockInfo {
        type Error = LimaConversionError;

        fn try_from(value: raw::BlockInfo) -> Result<Self, Self::Error> {
            Ok(Self {
                chain_id: ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: BlockHash::from(value.hash.block_hash),
                header: LimaBlockHeader::from(value.header.into_inner()),
                metadata: value.metadata
                    .map(|x| LimaMetadata::try_from(x.into_inner()))
                    .transpose()?,
                operations: unpack_block_operations(value.operations)?,
            })
        }
    }

    impl ContainsProposals for LimaBlockInfo {
        type ProposalsType = LimaProposals;

        fn has_proposals(&self) -> bool {
            self.operations.iter().any(|ops| ops.iter().any(|op| op.has_proposals()))
        }

        fn count_proposals(&self) -> usize {
            todo!()
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            todo!()
        }
    }

    impl ContainsBallots for LimaBlockInfo {
        type BallotType = LimaBallot;

        fn has_ballots(&self) -> bool {
            self.operations.iter().any(|ops| ops.iter().any(|op| op.has_ballots()))
        }

        fn count_ballots(&self) -> usize {
            self.operations
                .iter()
                .fold(0usize, |major, ops| {
                    ops.iter().fold(major, |minor, op| minor + op.count_ballots())
                })
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            self.operations
                .iter()
                .flat_map(|v| v.iter().flat_map(|op| op.get_ballots()))
                .collect()
        }
    }

    impl ContainsTransactions for LimaBlockInfo {
        type TransactionType = LimaTransaction;

        fn has_transactions(&self) -> bool {
            self.operations.iter().any(|ops| ops.iter().any(|op| op.has_transactions()))
        }

        fn count_transactions(&self) -> usize {
            self.operations
                .iter()
                .fold(0usize, |major, ops| {
                    ops.iter().fold(major, |minor, op| minor + op.count_transactions())
                })
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            self.operations
                .iter()
                .flat_map(|v| v.iter().flat_map(|op| op.get_transactions()))
                .collect()
        }
    }

    impl LimaBlockInfo {
        /// Returns a [Vec] containing every [LimaBallot] operation included in this [LimaBlockInfo].
        pub fn get_all_ballots(&self) -> Vec<LimaBallot> {
            self.operations
                .iter()
                .flat_map(|v| v.iter().flat_map(|op| op.get_ballots()))
                .collect()
        }

        /// Returns a [Vec] containing every [LimaProposals] operation included in this [LimaBlockInfo].
        pub fn get_all_proposals(&self) -> Vec<LimaProposals> {
            self.operations
                .iter()
                .flat_map(|v| v.iter().flat_map(|op| op.get_proposals()))
                .collect()
        }

        pub fn get_all_transactions(&self) -> Vec<LimaTransaction> {
            self.operations
                .iter()
                .flat_map(|v| v.iter().flat_map(|op| op.get_transactions()))
                .collect()
        }
    }

    impl LimaBlockInfo {
        /// Returns the (optional) `metadata` field associated with this [`LimaBlockInfo`].
        pub fn metadata(&self) -> &Option<LimaMetadata> {
            &self.metadata
        }

        /// Returns a mutable reference to the `metadata` field of this [`LimaBlockInfo`].
        pub fn metadata_mut(&mut self) -> &mut Option<LimaMetadata> {
            &mut self.metadata
        }

        /// Returns a reference to the `operations` field of this [`LimaBlockInfo`].
        pub fn operations(&self) -> &Vec<Vec<LimaOperation>> {
            &self.operations
        }

        /// Returns a mutable reference to the `operations` field of this [`LimaBlockInfo`].
        pub fn operations_mut(&mut self) -> &mut Vec<Vec<LimaOperation>> {
            &mut self.operations
        }

        /// Returns a reference to the [ChainId] associated with this [`LimaBlockInfo`].
        pub fn chain_id(&self) -> &ChainId {
            &self.chain_id
        }

        /// Returns a reference to the [BlockHash] associated with this [`LimaBlockInfo`].
        pub fn hash(&self) -> &BlockHash {
            &self.hash
        }

        /// Returns a reference to the `header` field of this [`LimaBlockInfo`]
        pub fn header(&self) -> &LimaBlockHeader {
            &self.header
        }
    }

    crate::boilerplate!(LimaProofOfWorkNonce = 8);

    // pub type LimaBlockHeader = raw::RawBlockHeader;

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct LimaBlockHeader {
        level: i32,
        proto: u8,
        predecessor: BlockHash,
        timestamp: crate::core::Timestamp,
        validation_pass: u8,
        operations_hash: crate::core::OperationListListHash,
        fitness: Vec<tedium::Bytes>,
        context: crate::core::ContextHash,
        payload_hash: crate::core::ValueHash,
        payload_round: i32,
        proof_of_work_nonce: LimaProofOfWorkNonce,
        seed_nonce_hash: Option<NonceHash>,
        liquidity_baking_toggle_vote: i8,
        signature: crate::core::SignatureV0,
    }

    impl LimaBlockHeader {
        #[inline(always)]
        /// Returns the block-level stored in this [`LimaBlockHeader`].
        pub const fn level(&self) -> i32 {
            self.level
        }
    }

    impl From<raw::RawBlockHeader> for LimaBlockHeader {
        fn from(value: raw::RawBlockHeader) -> Self {
            Self {
                level: value.level,
                proto: value.proto,
                predecessor: BlockHash::from_fixed_bytes(value.predecessor.block_hash),
                timestamp: crate::core::Timestamp::from_i64(value.timestamp),
                validation_pass: value.validation_pass,
                operations_hash: crate::core::OperationListListHash::from_fixed_bytes(
                    value.operations_hash.operation_list_list_hash
                ),
                fitness: value.fitness
                    .into_inner()
                    .into_iter()
                    .map(|elt| elt.into_inner())
                    .collect(),
                context: crate::core::ContextHash::from_fixed_bytes(value.context.context_hash),
                payload_hash: crate::core::ValueHash::from_fixed_bytes(
                    value.payload_hash.value_hash
                ),
                payload_round: value.payload_round,
                proof_of_work_nonce: LimaProofOfWorkNonce::from_fixed_bytes(
                    value.proof_of_work_nonce
                ),
                seed_nonce_hash: value.seed_nonce_hash.map(|nonce|
                    crate::core::NonceHash::from_fixed_bytes(nonce.cycle_nonce)
                ),
                liquidity_baking_toggle_vote: value.liquidity_baking_toggle_vote,
                signature: crate::core::SignatureV0::from_fixed_bytes(value.signature.signature_v0),
            }
        }
    }

    pub type LimaLevelInfo = raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataLevelInfo;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LimaVotingPeriodInfo {
        voting_period: LimaVotingPeriod,
        position: i32,
        remaining: i32,
    }

    impl tedium::Decode for LimaVotingPeriodInfo {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
            let raw =
                raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataVotingPeriodInfo::parse(
                    p
                )?;
            Ok(raw.try_into().map_err(tedium::ParseError::reify)?)
        }
    }

    impl LimaVotingPeriodInfo {
        pub fn voting_period(&self) -> LimaVotingPeriod {
            self.voting_period
        }

        pub fn position(&self) -> i32 {
            self.position
        }

        pub fn remaining(&self) -> i32 {
            self.remaining
        }
    }

    impl TryFrom<raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataVotingPeriodInfo>
    for LimaVotingPeriodInfo {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(
            value: raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataVotingPeriodInfo
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                voting_period: value.voting_period.try_into()?,
                position: value.position,
                remaining: value.remaining,
            })
        }
    }

    impl std::fmt::Display for LimaVotingPeriodInfo {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{{ voting_period: {}, position: {}, remaining: {} }}",
                self.voting_period,
                self.position,
                self.remaining
            )
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LimaVotingPeriod {
        index: i32,
        kind: VotingPeriodKind,
        start_position: i32,
    }

    impl LimaVotingPeriod {
        pub fn index(&self) -> i32 {
            self.index
        }

        pub fn kind(&self) -> VotingPeriodKind {
            self.kind
        }

        pub fn start_position(&self) -> i32 {
            self.start_position
        }
    }

    impl std::fmt::Display for LimaVotingPeriod {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{{ index: {}, kind: {}, start_position: {} }}",
                self.index,
                self.kind,
                self.start_position
            )
        }
    }

    pub type RawVotingPeriodKind =
        raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriodKind;

    impl TryFrom<RawVotingPeriodKind> for crate::core::VotingPeriodKind {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(value: RawVotingPeriodKind) -> Result<Self, Self::Error> {
            let raw = value.get_tagval();
            Self::try_from_u8(raw)
        }
    }

    impl TryFrom<raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriod>
    for LimaVotingPeriod {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(
            value: raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriod
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                index: value.index,
                kind: value.kind.try_into()?,
                start_position: value.start_position,
            })
        }
    }

    pub type LimaTestChainStatus = raw::block_info::TestChainStatus;

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct LimaMetadata {
        test_chain_status: LimaTestChainStatus,
        max_operations_ttl: i32,
        max_operation_data_length: i32,
        max_block_header_length: i32,
        max_operation_list_length: Vec<raw::block_info::BlockHeaderMetadataMaxOperationListLengthDenestDynDenestDynDenestSeq>,
        proposer: PublicKeyHashV0,
        baker: PublicKeyHashV0,
        level_info: LimaLevelInfo,
        voting_period_info: LimaVotingPeriodInfo,
        nonce_hash: Option<NonceHash>,
        deactivated: Vec<raw::block_info::Proto015PtLimaPtBlockHeaderAlphaMetadataDeactivatedDenestDynDenestSeq>,
        balance_updates: Vec<raw::block_info::Proto015PtLimaPtOperationMetadataAlphaBalance>,
        liquidity_baking_toggle_ema: i32,
        implicit_operations_results: Vec<raw::block_info::Proto015PtLimaPtOperationAlphaSuccessfulManagerOperationResult>,
        proposer_consensus_key: PublicKeyHashV0,
        baker_consensus_key: PublicKeyHashV0,
        consumed_milligas: BigUint,
        dal_slot_availability: Option<BigInt>,
    }

    impl LimaMetadata {
        pub fn voting_period_info(&self) -> &LimaVotingPeriodInfo {
            &self.voting_period_info
        }
    }

    impl TryFrom<raw::BlockHeaderMetadata> for LimaMetadata {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(value: raw::BlockHeaderMetadata) -> Result<Self, Self::Error> {
            Ok(Self {
                test_chain_status: value.test_chain_status,
                max_operations_ttl: value.max_operations_ttl.to_i32(),
                max_operation_data_length: value.max_operation_data_length.to_i32(),
                max_block_header_length: value.max_block_header_length.to_i32(),
                max_operation_list_length: Sequence::into_inner(
                    value.max_operation_list_length.into_inner().into_inner()
                ),
                proposer: value.proposer.signature_v0_public_key_hash.into(),
                baker: value.baker.signature_v0_public_key_hash.into(),
                level_info: value.level_info.into(),
                voting_period_info: value.voting_period_info.try_into()?,
                nonce_hash: unpack_metadata_nonce_hash(value.nonce_hash),
                deactivated: value.deactivated.into_inner().into_inner(),
                balance_updates: value.balance_updates.into_inner().into_inner(),
                liquidity_baking_toggle_ema: value.liquidity_baking_toggle_ema,
                implicit_operations_results: value.implicit_operations_results
                    .into_inner()
                    .into_inner(),
                proposer_consensus_key: value.proposer_consensus_key.signature_v0_public_key_hash.into(),
                baker_consensus_key: value.baker_consensus_key.signature_v0_public_key_hash.into(),
                consumed_milligas: value.consumed_milligas.into_inner(),
                dal_slot_availability: value.dal_slot_availability
                    .into_inner()
                    .map(tedium::Z::into_inner),
            })
        }
    }

    fn unpack_metadata_nonce_hash(
        value: Proto015PtLimaPtBlockHeaderAlphaMetadataNonceHash
    ) -> Option<NonceHash> {
        match value {
            Proto015PtLimaPtBlockHeaderAlphaMetadataNonceHash::None(_) => None,
            Proto015PtLimaPtBlockHeaderAlphaMetadataNonceHash::Some(
                raw::block_info::proto015ptlimaptblockheaderalphametadatanoncehash::Some {
                    cycle_nonce,
                },
            ) => Some(cycle_nonce.into()),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LimaOperationShellHeader {
        branch: BlockHash,
    }

    impl From<super::raw::block_info::OperationShellHeader> for LimaOperationShellHeader {
        fn from(value: super::raw::block_info::OperationShellHeader) -> Self {
            Self {
                branch: BlockHash::from_fixed_bytes(value.branch.block_hash),
            }
        }
    }

    impl LimaOperationShellHeader {
        pub const fn branch(&self) -> &BlockHash {
            &self.branch
        }

        pub const fn into_branch(self) -> BlockHash {
            self.branch
        }
    }
    /// Outermost type used to represent operation-data within a [`LimaBlockInfo`] object.
    ///
    /// Primarily contains a value of type [`LimaOperationPayload`], along with a [`ChainId`]
    /// and [`OperationHash`]
    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct LimaOperation {
        chain_id: ChainId,
        hash: crate::core::OperationHash,
        operation: LimaOperationPayload,
    }

    impl TryFrom<super::raw::block_info::Operation> for LimaOperation {
        type Error = LimaConversionError;

        fn try_from(value: super::raw::block_info::Operation) -> Result<Self, Self::Error> {
            Ok(Self {
                chain_id: ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: crate::core::OperationHash::from_fixed_bytes(value.hash.operation_hash),
                operation: LimaOperationPayload::try_from(value.operation_rhs)?,
            })
        }
    }

    impl ContainsBallots for LimaOperation {
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

    impl ContainsTransactions for LimaOperation {
        type TransactionType = LimaTransaction;

        fn has_transactions(&self) -> bool {
            self.operation.has_transactions()
        }

        fn count_transactions(&self) -> usize {
            self.operation.count_transactions()
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            self.operation.get_transactions()
        }
    }

    impl ContainsProposals for LimaOperation {
        type ProposalsType = LimaProposals;

        fn has_proposals(&self) -> bool {
            self.operation.has_proposals()
        }

        fn count_proposals(&self) -> usize {
            self.operation.count_proposals()
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            self.operation.get_proposals()
        }
    }

    #[cfg(test)]
    fn mock_operation(contents: LimaOperationContents) -> LimaOperation {
        LimaOperation {
            chain_id: ChainId::from([0, 0, 0, 0]),
            hash: crate::core::OperationHash::from(tedium::FixedBytes::<32>::from_array([0u8; 32])),
            operation: LimaOperationPayload {
                shell_header: LimaOperationShellHeader {
                    branch: BlockHash::from_byte_array([0u8; 32]),
                },
                operation: LimaOperationContainer::WithoutMetadata {
                    contents: vec![contents],
                    signature: None,
                },
            },
        }
    }

    #[cfg(test)]
    mod limaoperation_containsproposals_tests {
        use tedium::FixedBytes;

        use super::*;

        #[test]
        fn test_has_proposals() {
            let should_have = mock_operation(
                LimaOperationContents::Proposals(LimaProposals {
                    source: PublicKeyHashV0::Ed25519(FixedBytes::from_array([0u8; 20])),
                    period: 12,
                    proposals: vec![crate::core::ProtocolHash::from_byte_array([0u8; 32])],
                })
            );
            assert!(should_have.has_proposals());
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

    impl ContainsTransactions for LimaOperationPayload {
        type TransactionType = LimaTransaction;

        fn has_transactions(&self) -> bool {
            self.operation.has_transactions()
        }

        fn count_transactions(&self) -> usize {
            self.operation.count_transactions()
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            self.operation.get_transactions()
        }
    }

    impl ContainsProposals for LimaOperationPayload {
        type ProposalsType = LimaProposals;

        fn has_proposals(&self) -> bool {
            self.operation.has_proposals()
        }

        fn count_proposals(&self) -> usize {
            self.operation.count_proposals()
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            self.operation.get_proposals()
        }
    }

    impl TryFrom<super::raw::block_info::OperationRhs> for LimaOperationPayload {
        type Error = InvalidBallotError;

        fn try_from(value: super::raw::block_info::OperationRhs) -> Result<Self, Self::Error> {
            Ok(Self {
                shell_header: LimaOperationShellHeader::from(value.0.into_inner()),
                operation: LimaOperationContainer::try_from(value.1.into_inner())?,
            })
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
                LimaOperationContainer::WithMetadata { contents, .. } => {
                    contents.iter().any(ContainsBallots::has_ballots)
                }
                LimaOperationContainer::WithoutMetadata { contents, .. } => {
                    contents.iter().any(ContainsBallots::has_ballots)
                }
            }
        }

        fn count_ballots(&self) -> usize {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } => {
                    contents.iter().map(ContainsBallots::count_ballots).sum()
                }
                LimaOperationContainer::WithoutMetadata { contents, .. } => {
                    contents.iter().map(ContainsBallots::count_ballots).sum()
                }
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

    impl ContainsTransactions for LimaOperationContainer {
        type TransactionType = LimaTransaction;

        fn has_transactions(&self) -> bool {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } => {
                    contents.iter().any(ContainsTransactions::has_transactions)
                }
                LimaOperationContainer::WithoutMetadata { contents, .. } => {
                    contents.iter().any(ContainsTransactions::has_transactions)
                }
            }
        }

        fn count_transactions(&self) -> usize {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } => {
                    contents.iter().map(ContainsTransactions::count_transactions).sum()
                }
                LimaOperationContainer::WithoutMetadata { contents, .. } => {
                    contents.iter().map(ContainsTransactions::count_transactions).sum()
                }
            }
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().flat_map(ContainsTransactions::get_transactions).collect(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().flat_map(ContainsTransactions::get_transactions).collect(),
            }
        }
    }

    impl ContainsProposals for LimaOperationContainer {
        type ProposalsType = LimaProposals;

        fn has_proposals(&self) -> bool {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } => {
                    contents.iter().any(ContainsProposals::has_proposals)
                }
                LimaOperationContainer::WithoutMetadata { contents, .. } => {
                    contents.iter().any(ContainsProposals::has_proposals)
                }
            }
        }

        fn count_proposals(&self) -> usize {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().map(ContainsProposals::count_proposals).sum(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().map(ContainsProposals::count_proposals).sum(),
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                LimaOperationContainer::WithMetadata { contents, .. } =>
                    contents.iter().flat_map(ContainsProposals::get_proposals).collect(),
                LimaOperationContainer::WithoutMetadata { contents, .. } =>
                    contents.iter().flat_map(ContainsProposals::get_proposals).collect(),
            }
        }
    }

    pub type LimaRawProposals =
        super::raw::block_info::proto015ptlimaptoperationalphacontents::Proposals;

    pub type LimaRawProposalsAndResult =
        super::raw::block_info::proto015ptlimaptoperationalphaoperationcontentsandresult::Proposals;

    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct LimaProposals {
        source: crate::core::PublicKeyHashV0,
        period: i32,
        proposals: Vec<ProtocolHash>,
    }

    impl std::fmt::Display for LimaProposals {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Account `")?;
            self.source.base58check_fmt(f)?;
            writeln!(f, "` proposed the following protocols during period {}:", self.period)?;
            for proposal in self.proposals.iter() {
                writeln!(f, "\t")?;
                proposal.base58check_fmt(f)?;
            }
            Ok(())
        }
    }

    impl LimaProposals {
        pub fn source(&self) -> PublicKeyHashV0 {
            self.source
        }

        pub fn period(&self) -> i32 {
            self.period
        }

        pub fn proposals(&self) -> &[ProtocolHash] {
            self.proposals.as_ref()
        }
    }

    impl From<LimaRawProposals> for LimaProposals {
        fn from(value: LimaRawProposals) -> Self {
            Self {
                source: value.source.signature_v0_public_key_hash.into(),
                period: value.period,
                proposals: value.proposals
                    .into_inner()
                    .into_iter()
                    .map(|proposal| proposal.protocol_hash.into())
                    .collect(),
            }
        }
    }

    impl From<LimaRawProposalsAndResult> for LimaProposals {
        fn from(value: LimaRawProposalsAndResult) -> Self {
            Self {
                source: value.source.signature_v0_public_key_hash.into(),
                period: value.period,
                proposals: value.proposals
                    .into_inner()
                    .into_iter()
                    .map(|proposal| proposal.protocol_hash.into())
                    .collect(),
            }
        }
    }

    pub type LimaContractId = crate::core::ContractId<PublicKeyHashV0>;

    impl From<Proto015PtLimaPtContractId> for LimaContractId {
        fn from(value: Proto015PtLimaPtContractId) -> Self {
            match value {
                Proto015PtLimaPtContractId::Implicit(Implicit { signature_v0_public_key_hash }) =>
                    Self::Implicit(PublicKeyHashV0::from(signature_v0_public_key_hash)),
                Proto015PtLimaPtContractId::Originated(Originated(ct_padded)) => {
                    Self::Originated(ContractHash::from(ct_padded.into_inner().contract_hash))
                }
            }
        }
    }

    impl serde::Serialize for LimaContractId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_base58check())
            } else {
                match self {
                    LimaContractId::Implicit(pkh) => {
                        serializer.serialize_newtype_variant("ContractId", 0, "Implicit", pkh)
                    }
                    LimaContractId::Originated(ch) => {
                        serializer.serialize_newtype_variant("ContractId", 1, "Originated", ch)
                    }
                }
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash, Serialize)]
    pub struct LimaTransaction {
        source: PublicKeyHashV0,
        fee: MutezPlus,
        counter: BigUint,
        gas_limit: BigUint,
        storage_limit: BigUint,
        amount: MutezPlus,
        destination: LimaContractId,
        parameters: Option<LimaTransactionParameters>,
        #[serde(skip_serializing)] // FIXME[epic=serde]
        metadata: Option<LimaTransactionMetadata>,
    }



    impl From<raw::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResultTransactionMetadata>
    for LimaTransactionMetadata {
        fn from(
            value: raw::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResultTransactionMetadata
        ) -> Self {
            Self {
                balance_updates: abstract_unpack_dynseq(value.balance_updates),
                operation_result: value.operation_result.into(),
                internal_operation_results: abstract_unpack_dynseq(
                    value.internal_operation_results
                ),
            }
        }
    }

    // #[repr(u8)]
    // #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
    // pub(crate) enum UpdateOrigin  {
    //     BlockApplication = 0,
    //     ProtocolMigration = 1,
    //     Subsidy = 2,
    //     Simulation = 3,
    // }

    // // TODO[epic=facade]
    // #[derive(Clone, Debug, PartialEq, Hash, Serialize)]
    // pub enum LimaBalanceUpdate {
    //    Contract  { contract: LimaContractId, change: Mutez, origin: UpdateOrigin },
    //    BlockFees  { change: Mutez, origin: UpdateOrigin },
    //    Deposits  { delegate: PublicKeyHashV0, change: Mutez, origin: UpdateOrigin },
    //    NonceRevelationRewards  { change: Mutez, origin: UpdateOrigin },
    //    DoubleSigningEvidenceRewards { change: Mutez, origin: UpdateOrigin },
    //    EndorsingRewards { change: Mutez, origin: UpdateOrigin },
    //    BakingRewards  { change: Mutez, origin: UpdateOrigin },
    //    BakingBonuses  { change: Mutez, origin: UpdateOrigin },
    //    StorageFees  { change: Mutez, origin: UpdateOrigin },
    //    DoubleSigningPunishments  { change: Mutez, origin: UpdateOrigin },
    //    LostEndorsingRewards  { delegate: PublicKeyHashV0, participation: bool, revelation: bool, change: Mutez, origin: UpdateOrigin },
    //    LiquidityBakingSubsidies  { change: Mutez, origin: UpdateOrigin },
    //    Burned  { change: Mutez, origin: UpdateOrigin },
    //    Commitments  { committer: Proto015PtLimaPtOperationMetadataAlphaBalanceCommitmentsCommitter, pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    Bootstrap  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    Invoice  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    InitialCommitments  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    Minted  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    Frozen_bonds  { pub contract: Proto015PtLimaPtContractId, pub bond_id: Proto015PtLimaPtBondId, pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    TxRollupRejectionRewards  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    TxRollupRejectionPunishments  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    ScRollupRefutationPunishments  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    //    ScRollupRefutationRewards  { pub change: i64, pub origin: Proto015PtLimaPtOperationMetadataAlphaUpdateOriginOrigin },
    // }

    type RawBalanceUpdate = raw::block_info::Proto015PtLimaPtOperationMetadataAlphaBalance;
    // TODO[epic=facade] - pick up facading of LimaBalanceUpdate/
    pub type LimaBalanceUpdate = RawBalanceUpdate;

    // TODO[epic=facade]
    pub type LimaTransactionResult =
        raw::block_info::Proto015PtLimaPtOperationAlphaOperationResultTransaction;

    // TODO[epic=facade]
    pub type LimaInternalOperationResult =
        raw::block_info::Proto015PtLimaPtApplyInternalResultsAlphaOperationResult;

    #[derive(Clone, Debug, PartialEq, Hash)]
    #[cfg_attr(never, derive(Serialize))]
    pub struct LimaTransactionMetadata {
        balance_updates: Vec<LimaBalanceUpdate>,
        operation_result: LimaTransactionResult,
        internal_operation_results: Vec<LimaInternalOperationResult>,
    }

    impl LimaTransactionMetadata {
        pub fn balance_updates(&self) -> &[LimaBalanceUpdate] {
            self.balance_updates.as_ref()
        }

        pub fn operation_result(&self) -> &LimaTransactionResult {
            &self.operation_result
        }

        pub fn internal_operation_results(&self) -> &[LimaInternalOperationResult] {
            self.internal_operation_results.as_ref()
        }
    }

    pub type RawLimaTransaction =
        raw::block_info::proto015ptlimaptoperationalphacontents::Transaction;

    impl tedium::Decode for LimaTransaction {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
            let raw = RawLimaTransaction::parse(p)?;
            Ok(raw.into())
        }
    }

    impl LimaTransaction {
        pub fn source(&self) -> PublicKeyHashV0 {
            self.source
        }

        pub fn fee(&self) -> &MutezPlus {
            &self.fee
        }

        pub fn amount(&self) -> &MutezPlus {
            &self.amount
        }

        pub fn destination(&self) -> LimaContractId {
            self.destination
        }

        pub fn parameters(&self) -> Option<&LimaTransactionParameters> {
            self.parameters.as_ref()
        }

        pub fn counter(&self) -> &BigUint {
            &self.counter
        }

        pub fn storage_limit(&self) -> &BigUint {
            &self.storage_limit
        }

        pub fn gas_limit(&self) -> &BigUint {
            &self.gas_limit
        }
    }

    impl From<raw::block_info::proto015ptlimaptoperationalphacontents::Transaction>
    for LimaTransaction {
        fn from(
            value: raw::block_info::proto015ptlimaptoperationalphacontents::Transaction
        ) -> Self {
            Self {
                source: PublicKeyHashV0::from(value.source.signature_v0_public_key_hash),
                fee: MutezPlus::from_biguint(value.fee.into_inner()),
                counter: value.counter.into_inner(),
                gas_limit: value.gas_limit.into_inner(),
                storage_limit: value.storage_limit.into_inner(),
                amount: MutezPlus::from_biguint(value.amount.into_inner()),
                destination: ContractId::from(value.destination),
                parameters: value.parameters.map(|params| params.into()),
                metadata: None,
            }
        }
    }

    impl From<raw::block_info::proto015ptlimaptoperationalphaoperationcontentsandresult::Transaction>
    for LimaTransaction {
        fn from(
            value: raw::block_info::proto015ptlimaptoperationalphaoperationcontentsandresult::Transaction
        ) -> Self {
            Self {
                source: PublicKeyHashV0::from(value.source.signature_v0_public_key_hash),
                fee: MutezPlus::from_biguint(value.fee.into_inner()),
                counter: value.counter.into_inner(),
                gas_limit: value.gas_limit.into_inner(),
                storage_limit: value.storage_limit.into_inner(),
                amount: MutezPlus::from_biguint(value.amount.into_inner()),
                destination: ContractId::from(value.destination),
                parameters: value.parameters.map(|params| params.into()),
                metadata: Some(value.metadata.into()),
            }
        }
    }

    impl From<Proto015PtLimaPtEntrypoint> for Entrypoint {
        fn from(value: Proto015PtLimaPtEntrypoint) -> Self {
            match value {
                Proto015PtLimaPtEntrypoint::default(_) => Self::Default,
                Proto015PtLimaPtEntrypoint::root(_) => Self::Root,
                Proto015PtLimaPtEntrypoint::r#do(_) => Self::Do,
                Proto015PtLimaPtEntrypoint::set_delegate(_) => Self::SetDelegate,
                Proto015PtLimaPtEntrypoint::remove_delegate(_) => Self::RemoveDelegate,
                Proto015PtLimaPtEntrypoint::deposit(_) => Self::Deposit,
                Proto015PtLimaPtEntrypoint::named(s) => Self::Named(s.0.into_inner()),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash, Serialize)]
    pub struct LimaTransactionParameters {
        entrypoint: Entrypoint,
        value: tedium::Bytes,
    }

    impl From<raw::block_info::Proto015PtLimaPtOperationAlphaContentsTransactionParameters>
    for LimaTransactionParameters {
        fn from(
            value: raw::block_info::Proto015PtLimaPtOperationAlphaContentsTransactionParameters
        ) -> Self {
            Self {
                entrypoint: value.entrypoint.into(),
                value: value.value.into_inner(),
            }
        }
    }

    impl From<raw::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResultTransactionParameters>
    for LimaTransactionParameters {
        fn from(
            value: raw::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResultTransactionParameters
        ) -> Self {
            Self {
                entrypoint: value.entrypoint.into(),
                value: value.value.into_inner(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    #[non_exhaustive]
    pub enum LimaOperationContents {
        Ballot(LimaBallot),
        Proposals(LimaProposals),
        Transaction(LimaTransaction),
        Raw(super::raw::block_info::Proto015PtLimaPtOperationAlphaContents),
    }

    impl TryFrom<RawOpContents> for LimaOperationContents {
        type Error = InvalidBallotError;

        fn try_from(value: RawOpContents) -> Result<Self, Self::Error> {
            match value {
                Proto015PtLimaPtOperationAlphaContents::Ballot(ballot) => {
                    Ok(Self::Ballot(LimaBallot::try_from(ballot)?))
                }
                Proto015PtLimaPtOperationAlphaContents::Proposals(proposals) => {
                    Ok(Self::Proposals(LimaProposals::from(proposals)))
                }
                Proto015PtLimaPtOperationAlphaContents::Transaction(transaction) => {
                    Ok(Self::Transaction(LimaTransaction::from(transaction)))
                }
                _other => Ok(Self::Raw(_other)),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    #[non_exhaustive]
    pub enum LimaOperationContentsAndResult {
        Ballot(LimaBallot),
        Proposals(LimaProposals),
        Transaction(LimaTransaction),
        Raw(super::raw::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResult),
    }

    impl TryFrom<RawOpContentsAndResult> for LimaOperationContentsAndResult {
        type Error = InvalidBallotError;

        fn try_from(value: RawOpContentsAndResult) -> Result<Self, Self::Error> {
            match value {
                Proto015PtLimaPtOperationAlphaOperationContentsAndResult::Ballot(ballot) => {
                    Ok(Self::Ballot(LimaBallot::try_from(ballot)?))
                }
                Proto015PtLimaPtOperationAlphaOperationContentsAndResult::Proposals(proposals) => {
                    Ok(Self::Proposals(LimaProposals::from(proposals)))
                }
                Proto015PtLimaPtOperationAlphaOperationContentsAndResult::Transaction(
                    transaction,
                ) => Ok(Self::Transaction(LimaTransaction::from(transaction))),
                other => Ok(Self::Raw(other)),
            }
        }
    }

    impl ContainsTransactions for LimaOperationContentsAndResult {
        type TransactionType = LimaTransaction;

        fn has_transactions(&self) -> bool {
            matches!(self, &Self::Transaction(..))
        }

        fn count_transactions(&self) -> usize {
            match self {
                LimaOperationContentsAndResult::Transaction(_) => 1,
                _ => 0,
            }
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            match self {
                Self::Transaction(t) => vec![t.clone()],
                _ => Vec::new(),
            }
        }
    }

    impl ContainsProposals for LimaOperationContentsAndResult {
        type ProposalsType = LimaProposals;

        fn has_proposals(&self) -> bool {
            matches!(self, &LimaOperationContentsAndResult::Proposals(_))
        }

        fn count_proposals(&self) -> usize {
            match self {
                LimaOperationContentsAndResult::Proposals(_) => 1,
                _ => 0,
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                LimaOperationContentsAndResult::Proposals(ret) => vec![ret.clone()],
                _ => Vec::new(),
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
                _ => 0,
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                &LimaOperationContentsAndResult::Ballot(ret) => vec![ret],
                _ => Vec::new(),
            }
        }
    }

    type RawOpContents = Proto015PtLimaPtOperationAlphaContents;
    type RawOpContentsAndResult = Proto015PtLimaPtOperationAlphaOperationContentsAndResult;

    fn unpack_operation_contents(
        contents: Sequence<RawOpContents>
    ) -> Result<Vec<LimaOperationContents>, InvalidBallotError> {
        contents
            .into_iter()
            .map(|raw_op| LimaOperationContents::try_from(raw_op))
            .collect()
    }

    fn unpack_operation_contents_and_result(
        contents: Sequence<RawOpContentsAndResult>
    ) -> Result<Vec<LimaOperationContentsAndResult>, InvalidBallotError> {
        contents
            .into_iter()
            .map(|raw_op_and_result| LimaOperationContentsAndResult::try_from(raw_op_and_result))
            .collect()
    }

    impl TryFrom<super::raw::block_info::OperationDenestDyn> for LimaOperationContainer {
        type Error = InvalidBallotError;

        fn try_from(
            value: super::raw::block_info::OperationDenestDyn
        ) -> Result<Self, Self::Error> {
            match value {
                OperationDenestDyn::Operation_with_too_large_metadata(
                    super::raw::block_info::operationdenestdyn::Operation_with_too_large_metadata {
                        contents,
                        signature,
                    },
                ) =>
                    Ok(Self::WithoutMetadata {
                        contents: unpack_operation_contents(contents)?,
                        signature: Some(crate::core::SignatureV0::from(signature.signature_v0)),
                    }),
                OperationDenestDyn::Operation_without_metadata(
                    super::raw::block_info::operationdenestdyn::Operation_without_metadata {
                        contents,
                        signature,
                    },
                ) =>
                    Ok(Self::WithoutMetadata {
                        contents: unpack_operation_contents(contents)?,
                        signature: Some(crate::core::SignatureV0::from(signature.signature_v0)),
                    }),
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
                            Ok(Self::WithMetadata {
                                contents: unpack_operation_contents_and_result(
                                    contents.into_inner()
                                )?,
                                signature: signature.map(|sig| sig.signature_v0.into()),
                            })
                        }
                        Proto015PtLimaPtOperationAlphaOperationWithMetadata::Operation_without_metadata(
                            Operation_without_metadata { contents, signature },
                        ) => {
                            Ok(Self::WithoutMetadata {
                                contents: unpack_operation_contents(contents.into_inner())?,
                                signature: signature.map(|sig| sig.signature_v0.into()),
                            })
                        }
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
    pub struct LimaBallot {
        source: PublicKeyHashV0,
        period: i32,
        proposal: ProtocolHash,
        ballot: Ballot,
    }

    impl crate::traits::BallotLike for LimaBallot {
        fn to_tally(&self) -> crate::util::VoteStatistics {
            self.ballot.to_tally()
        }
    }

    impl LimaBallot {
        #[inline(always)]
        #[must_use]
        /// Creates a new [`LimaBallot`] with the given parameters as its respective fields.
        pub fn new(
            source: PublicKeyHashV0,
            period: i32,
            proposal: ProtocolHash,
            ballot: Ballot
        ) -> Self {
            Self {
                source,
                period,
                proposal,
                ballot,
            }
        }

        #[inline(always)]
        #[must_use]
        /// Returns the public-key hash (v0) of this [`LimaBallot`]'s source address.
        pub fn source(&self) -> PublicKeyHashV0 {
            self.source
        }

        #[inline(always)]
        #[must_use]
        /// Returns the voting period associated with this [`LimaBallot`].
        pub const fn period(&self) -> i32 {
            self.period
        }

        #[inline(always)]
        #[must_use]
        /// Returns the protocol hash this [`LimaBallot`] is voting with reference to.
        pub fn proposal(&self) -> ProtocolHash {
            self.proposal
        }

        #[inline(always)]
        #[must_use]
        /// Returns the type of vote this [`LimaBallot`] represents (i.e. `Ballot::Yay`, `Ballot::Nay`, or `Ballot::Pass`).
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
        type Error = ballot::InvalidBallotError;

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
        type Error = ballot::InvalidBallotError;

        fn try_from(
            value: super::raw::block_info::proto015ptlimaptoperationalphaoperationcontentsandresult::Ballot
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                source: crate::core::PublicKeyHashV0::from(
                    value.source.signature_v0_public_key_hash
                ),
                period: value.period,
                proposal: value.proposal.protocol_hash.into(),
                ballot: value.ballot.try_into()?,
            })
        }
    }

    impl ContainsBallots
    for
    tezos_codegen::proto015_ptlimapt::block_info::Proto015PtLimaPtOperationAlphaOperationContentsAndResult {
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
                _ => Vec::new(),
            }
        }

        fn has_ballots(&self) -> bool {
            matches!(self, &LimaOperationContents::Ballot(_))
        }

        fn count_ballots(&self) -> usize {
            match self {
                LimaOperationContents::Ballot(_) => 1,
                _ => 0,
            }
        }
    }

    impl ContainsTransactions for LimaOperationContents {
        type TransactionType = LimaTransaction;

        fn has_transactions(&self) -> bool {
            matches!(self, &Self::Transaction(..))
        }

        fn count_transactions(&self) -> usize {
            match self {
                Self::Transaction(_) => 1,
                _ => 0,
            }
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            match self {
                Self::Transaction(t) => vec![t.clone()],
                _ => Vec::new(),
            }
        }
    }

    impl ContainsProposals for LimaOperationContents {
        type ProposalsType = LimaProposals;

        fn has_proposals(&self) -> bool {
            matches!(self, Self::Proposals(_))
        }

        fn count_proposals(&self) -> usize {
            match self {
                LimaOperationContents::Proposals(_) => 1,
                _ => 0,
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                LimaOperationContents::Proposals(ret) => vec![ret.clone()],
                _ => Vec::new(),
            }
        }
    }


    // pub type LimaConstants = super::raw::constants::Proto015PtLimaPtConstants;

    crate::boilerplate!(Seed32 = 32);

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct LimaConstants {
        proof_of_work_nonce_size: u8,
        nonce_length: u8,
        max_anon_ops_per_block: u8,
        max_operation_data_length: i32, // originally i31
        max_proposals_per_delegate: u8,
        max_micheline_node_count: i32, // originally i31
        max_micheline_bytes_limit: i32, // originally i31
        max_allowed_global_constants_depth: i32, // originally i31
        cache_layout_size: u8,
        michelson_maximum_type_size: u16,
        sc_max_wrapped_proof_binary_size: i32, // originally ::tedium::i31,
        sc_rollup_message_size_limit: i32, // originally ::tedium::i31,
        preserved_cycles: u8,
        blocks_per_cycle: i32,
        blocks_per_commitment: i32,
        nonce_revelation_threshold: i32,
        blocks_per_stake_snapshot: i32,
        cycles_per_voting_period: i32,
        hard_gas_limit_per_operation: BigInt, // originally ::tedium::Z,
        hard_gas_limit_per_block: BigInt, // originally ::tedium::Z,
        proof_of_work_threshold: i64,
        minimal_stake: BigUint, // originally ::tedium::N,
        vdf_difficulty: i64,
        seed_nonce_revelation_tip: BigUint, // originally ::tedium::N,
        origination_size: i32,
        baking_reward_fixed_portion: BigUint, // originally ::tedium::N,
        baking_reward_bonus_per_slot: BigUint, // originally ::tedium::N,
        endorsing_reward_per_slot: BigUint, // originally ::tedium::N,
        cost_per_byte: BigUint, // originally ::tedium::N,
        hard_storage_limit_per_operation: BigInt, // originally ::tedium::Z,
        quorum_min: i32,
        quorum_max: i32,
        min_proposal_quorum: i32,
        liquidity_baking_subsidy: BigUint, // originally ::tedium::N
        liquidity_baking_toggle_ema_threshold: i32,
        max_operations_time_to_live: i16,
        minimal_block_delay: i64,
        delay_increment_per_round: i64,
        consensus_committee_size: i32, // originally ::tedium::i31
        consensus_threshold: i32, // originally ::tedium::i31
        minimal_participation_ratio: RatioU16,
        max_slashing_period: i32, // originally ::tedium::i31
        frozen_deposits_percentage: i32, // originally ::tedium::i31
        double_baking_punishment: BigUint, // originally ::tedium::N
        ratio_of_frozen_deposits_slashed_per_double_endorsement: RatioU16,
        testnet_dictator: Option<PublicKeyHashV0>,
        initial_seed: Option<Seed32>,
        cache_script_size: i32, // originally ::tedium::i31
        cache_stake_distribution_cycles: i8,
        cache_sampler_state_cycles: i8,
        tx_rollup_enable: bool,
        tx_rollup_origination_size: i32,
        tx_rollup_hard_size_limit_per_inbox: i32,
        tx_rollup_hard_size_limit_per_message: i32,
        tx_rollup_max_withdrawals_per_batch: i32,
        tx_rollup_commitment_bond: BigUint,
        tx_rollup_finality_period: i32,
        tx_rollup_withdraw_period: i32,
        tx_rollup_max_inboxes_count: i32,
        tx_rollup_max_messages_per_inbox: i32,
        tx_rollup_max_commitments_count: i32,
        tx_rollup_cost_per_byte_ema_factor: i32,
        tx_rollup_max_ticket_payload_size: i32,
        tx_rollup_rejection_max_proof_size: i32,
        tx_rollup_sunset_level: i32,
        dal_parametric: LimaConstantsDalParametric,
        sc_rollup_enable: bool,
        sc_rollup_origination_size: i32,
        sc_rollup_challenge_window_in_blocks: i32,
        sc_rollup_max_number_of_messages_per_commitment_period: i32,
        sc_rollup_stake_amount: BigUint,
        sc_rollup_commitment_period_in_blocks: i32,
        sc_rollup_max_lookahead_in_blocks: i32,
        sc_rollup_max_active_outbox_levels: i32,
        sc_rollup_max_outbox_messages_per_level: i32,
        sc_rollup_number_of_sections_in_dissection: u8,
        sc_rollup_timeout_period_in_blocks: i32,
        sc_rollup_max_number_of_cemented_commitments: i32,
        zk_rollup_enable: bool,
        zk_rollup_origination_size: i32,
        zk_rollup_min_pending_to_process: i32,
    }

    #[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
    pub struct LimaConstantsDalParametric {
        feature_enable: bool,
        number_of_slots: i16,
        number_of_shards: i16,
        endorsement_lag: i16,
        availability_threshold: i16,
        slot_size: i32,
        redundancy_factor: u8,
        page_size: u16,
    }

    pub type RawDalParametric = super::raw::constants::Proto015PtLimaPtConstantsDalParametric;

    impl From<RawDalParametric> for LimaConstantsDalParametric {
        fn from(value: RawDalParametric) -> Self {
            Self {
                feature_enable: value.feature_enable,
                number_of_slots: value.number_of_slots,
                number_of_shards: value.number_of_shards,
                endorsement_lag: value.endorsement_lag,
                availability_threshold: value.availability_threshold,
                slot_size: value.slot_size.to_i32(),
                redundancy_factor: value.redundancy_factor,
                page_size: value.page_size,
            }
        }
    }

    impl LimaConstants {
        /// Returns the raw `i64` value of the `minimal_block_delay` field of this [`LimaConstants`] object.
        ///
        /// The value in question represents a number of seconds (for Protocol version Lima).
        pub fn minimal_block_delay(&self) -> i64 {
            self.minimal_block_delay
        }

        pub fn dal_parametric(&self) -> LimaConstantsDalParametric {
            self.dal_parametric
        }
    }

    impl tedium::Decode for LimaConstants {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
            Ok(<super::raw::Constants as tedium::Decode>::parse(p)?.into())
        }
    }

    pub type RawParticipationRatio = Proto015PtLimaPtConstantsMinimalParticipationRatio;

    impl From<RawParticipationRatio> for crate::core::RatioU16 {
        fn from(value: RawParticipationRatio) -> Self {
            crate::core::RatioU16::new(value.numerator, value.denominator)
        }
    }

    pub type RawSlashingRatio =
        Proto015PtLimaPtConstantsRatioOfFrozenDepositsSlashedPerDoubleEndorsement;

    impl From<RawSlashingRatio> for crate::core::RatioU16 {
        fn from(value: RawSlashingRatio) -> Self {
            crate::core::RatioU16::new(value.numerator, value.denominator)
        }
    }

    impl From<super::raw::Constants> for LimaConstants {
        fn from(value: super::raw::Constants) -> Self {
            Self {
                proof_of_work_nonce_size: value.proof_of_work_nonce_size,
                nonce_length: value.nonce_length,
                max_anon_ops_per_block: value.max_anon_ops_per_block,
                max_operation_data_length: value.max_operation_data_length.to_i32(),
                max_proposals_per_delegate: value.max_proposals_per_delegate,
                max_micheline_node_count: value.max_micheline_node_count.to_i32(),
                max_micheline_bytes_limit: value.max_micheline_bytes_limit.to_i32(),
                max_allowed_global_constants_depth: value.max_allowed_global_constants_depth.to_i32(),
                cache_layout_size: value.cache_layout_size,
                michelson_maximum_type_size: value.michelson_maximum_type_size,
                sc_max_wrapped_proof_binary_size: value.sc_max_wrapped_proof_binary_size.to_i32(),
                sc_rollup_message_size_limit: value.sc_rollup_message_size_limit.to_i32(),
                preserved_cycles: value.preserved_cycles,
                blocks_per_cycle: value.blocks_per_cycle,
                blocks_per_commitment: value.blocks_per_commitment,
                nonce_revelation_threshold: value.nonce_revelation_threshold,
                blocks_per_stake_snapshot: value.blocks_per_stake_snapshot,
                cycles_per_voting_period: value.cycles_per_voting_period,
                hard_gas_limit_per_operation: value.hard_gas_limit_per_operation.into_inner(),
                hard_gas_limit_per_block: value.hard_gas_limit_per_block.into_inner(),
                proof_of_work_threshold: value.proof_of_work_threshold,
                minimal_stake: value.minimal_stake.into_inner(),
                vdf_difficulty: value.vdf_difficulty,
                seed_nonce_revelation_tip: value.seed_nonce_revelation_tip.into_inner(),
                origination_size: value.origination_size.to_i32(),
                baking_reward_fixed_portion: value.baking_reward_fixed_portion.into_inner(),
                baking_reward_bonus_per_slot: value.baking_reward_bonus_per_slot.into_inner(),
                endorsing_reward_per_slot: value.endorsing_reward_per_slot.into_inner(),
                cost_per_byte: value.cost_per_byte.into_inner(),
                hard_storage_limit_per_operation: value.hard_storage_limit_per_operation.into_inner(),
                quorum_min: value.quorum_min,
                quorum_max: value.quorum_max,
                min_proposal_quorum: value.min_proposal_quorum,
                liquidity_baking_subsidy: value.liquidity_baking_subsidy.into_inner(),
                liquidity_baking_toggle_ema_threshold: value.liquidity_baking_toggle_ema_threshold,
                max_operations_time_to_live: value.max_operations_time_to_live,
                minimal_block_delay: value.minimal_block_delay,
                delay_increment_per_round: value.delay_increment_per_round,
                consensus_committee_size: value.consensus_committee_size.to_i32(),
                consensus_threshold: value.consensus_threshold.to_i32(),
                minimal_participation_ratio: value.minimal_participation_ratio.into(),
                max_slashing_period: value.max_slashing_period.to_i32(),
                frozen_deposits_percentage: value.frozen_deposits_percentage.to_i32(),
                double_baking_punishment: value.double_baking_punishment.into_inner(),
                ratio_of_frozen_deposits_slashed_per_double_endorsement: value.ratio_of_frozen_deposits_slashed_per_double_endorsement.into(),
                testnet_dictator: value.testnet_dictator.map(|x|
                    x.signature_v0_public_key_hash.into()
                ),
                initial_seed: value.initial_seed.map(|x| x.random.into()),
                cache_script_size: value.cache_script_size.to_i32(),
                cache_stake_distribution_cycles: value.cache_stake_distribution_cycles,
                cache_sampler_state_cycles: value.cache_sampler_state_cycles,
                tx_rollup_enable: value.tx_rollup_enable,
                tx_rollup_origination_size: value.tx_rollup_origination_size.to_i32(),
                tx_rollup_hard_size_limit_per_inbox: value.tx_rollup_hard_size_limit_per_inbox.to_i32(),
                tx_rollup_hard_size_limit_per_message: value.tx_rollup_hard_size_limit_per_message.to_i32(),
                tx_rollup_max_withdrawals_per_batch: value.tx_rollup_max_withdrawals_per_batch.to_i32(),
                tx_rollup_commitment_bond: value.tx_rollup_commitment_bond.into_inner(),
                tx_rollup_finality_period: value.tx_rollup_finality_period.to_i32(),
                tx_rollup_withdraw_period: value.tx_rollup_withdraw_period.to_i32(),
                tx_rollup_max_inboxes_count: value.tx_rollup_max_inboxes_count.to_i32(),
                tx_rollup_max_messages_per_inbox: value.tx_rollup_max_messages_per_inbox.to_i32(),
                tx_rollup_max_commitments_count: value.tx_rollup_max_commitments_count.to_i32(),
                tx_rollup_cost_per_byte_ema_factor: value.tx_rollup_cost_per_byte_ema_factor.to_i32(),
                tx_rollup_max_ticket_payload_size: value.tx_rollup_max_ticket_payload_size.to_i32(),
                tx_rollup_rejection_max_proof_size: value.tx_rollup_rejection_max_proof_size.to_i32(),
                tx_rollup_sunset_level: value.tx_rollup_sunset_level,
                dal_parametric: value.dal_parametric.into(), // TODO: stent this as a scaffolding alias
                sc_rollup_enable: value.sc_rollup_enable,
                sc_rollup_origination_size: value.sc_rollup_origination_size.to_i32(),
                sc_rollup_challenge_window_in_blocks: value.sc_rollup_challenge_window_in_blocks.to_i32(),
                sc_rollup_max_number_of_messages_per_commitment_period: value.sc_rollup_max_number_of_messages_per_commitment_period.to_i32(),
                sc_rollup_stake_amount: value.sc_rollup_stake_amount.into_inner(),
                sc_rollup_commitment_period_in_blocks: value.sc_rollup_commitment_period_in_blocks.to_i32(),
                sc_rollup_max_lookahead_in_blocks: value.sc_rollup_max_lookahead_in_blocks,
                sc_rollup_max_active_outbox_levels: value.sc_rollup_max_active_outbox_levels,
                sc_rollup_max_outbox_messages_per_level: value.sc_rollup_max_outbox_messages_per_level.to_i32(),
                sc_rollup_number_of_sections_in_dissection: value.sc_rollup_number_of_sections_in_dissection,
                sc_rollup_timeout_period_in_blocks: value.sc_rollup_timeout_period_in_blocks.to_i32(),
                sc_rollup_max_number_of_cemented_commitments: value.sc_rollup_max_number_of_cemented_commitments.to_i32(),
                zk_rollup_enable: value.zk_rollup_enable,
                zk_rollup_origination_size: value.zk_rollup_origination_size.to_i32(),
                zk_rollup_min_pending_to_process: value.zk_rollup_min_pending_to_process.to_i32(),
            }
        }
    }
}