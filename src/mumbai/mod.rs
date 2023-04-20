use tezos_codegen::proto016_ptmumbai::{ block_info, constants };

pub mod error {
    use std::convert::Infallible;

    use crate::core::{
        ballot::InvalidBallotError,
        InvalidDiscriminantError,
        InvalidSignatureV1ByteLengthError,
        VotingPeriodKind,
    };

    #[derive(Debug)]
    pub enum MumbaiConversionError {
        Ballot(InvalidBallotError),
        VPKDisc(InvalidDiscriminantError<VotingPeriodKind>),
        Signature(InvalidSignatureV1ByteLengthError),
        SignaturePrefix(UnexpectedSignaturePrefixError),
    }

    impl std::fmt::Display for MumbaiConversionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                MumbaiConversionError::Ballot(b) => b.fmt(f),
                MumbaiConversionError::VPKDisc(vpk) => vpk.fmt(f),
                MumbaiConversionError::Signature(s) => s.fmt(f),
                MumbaiConversionError::SignaturePrefix(sp) => sp.fmt(f),
            }
        }
    }

    impl From<InvalidBallotError> for MumbaiConversionError {
        fn from(value: InvalidBallotError) -> Self {
            Self::Ballot(value)
        }
    }

    impl From<InvalidSignatureV1ByteLengthError> for MumbaiConversionError {
        fn from(value: InvalidSignatureV1ByteLengthError) -> Self {
            Self::Signature(value)
        }
    }

    impl From<UnexpectedSignaturePrefixError> for MumbaiConversionError {
        fn from(value: UnexpectedSignaturePrefixError) -> Self {
            Self::SignaturePrefix(value)
        }
    }

    impl From<InvalidDiscriminantError<VotingPeriodKind>> for MumbaiConversionError {
        fn from(value: InvalidDiscriminantError<VotingPeriodKind>) -> Self {
            Self::VPKDisc(value)
        }
    }

    impl From<Infallible> for MumbaiConversionError {
        fn from(value: Infallible) -> Self {
            match value {
            }
        }
    }

    impl std::error::Error for MumbaiConversionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                MumbaiConversionError::Ballot(b) => Some(b),
                MumbaiConversionError::VPKDisc(vpk) => Some(vpk),
                MumbaiConversionError::Signature(s) => Some(s),
                MumbaiConversionError::SignaturePrefix(sp) => Some(sp),
            }
        }
    }

    #[derive(Debug)]
    pub struct UnexpectedSignaturePrefixError;

    impl std::fmt::Display for UnexpectedSignaturePrefixError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "found unexpected signature prefix in non-final position of contents-list")
        }
    }

    impl std::error::Error for UnexpectedSignaturePrefixError {}
}

macro_rules! from_pkh {
    ($($id:ident),+ $(,)?) => {
        $(
            impl From<$crate::core::PublicKeyHashV1> for $id::PublicKeyHash {
                fn from(value: $crate::core::PublicKeyHashV1) -> Self {
                    use $id::publickeyhash::{ Ed25519, Secp256k1, P256, Bls };
                    match value {
                        $crate::core::PublicKeyHashV1::PkhV0(pkhv0) => match pkhv0 {
                            $crate::core::PublicKeyHashV0::Ed25519(ed25519_public_key_hash) => Self::Ed25519(Ed25519 { ed25519_public_key_hash }),
                            $crate::core::PublicKeyHashV0::Secp256k1(secp256k1_public_key_hash) => Self::Secp256k1(Secp256k1 { secp256k1_public_key_hash }),
                            $crate::core::PublicKeyHashV0::P256(p256_public_key_hash) => Self::P256(P256 { p256_public_key_hash }),
                        },
                        $crate::core::PublicKeyHashV1::Bls(bls12_381_public_key_hash) => Self::Bls(Bls { bls12_381_public_key_hash })
                    }
                }
            }

            impl From<&'_ $id::PublicKeyHash> for $crate::core::PublicKeyHashV1 {
                fn from(value: &'_ $id::PublicKeyHash) -> Self {
                    use $id::{ PublicKeyHash, publickeyhash::{ Ed25519, Secp256k1, P256, Bls } };
                    match value {
                        PublicKeyHash::Ed25519(Ed25519 { ed25519_public_key_hash }) => Self::PkhV0($crate::core::PublicKeyHashV0::Ed25519(*ed25519_public_key_hash)),
                        PublicKeyHash::Secp256k1(Secp256k1 { secp256k1_public_key_hash }) => Self::PkhV0($crate::core::PublicKeyHashV0::Secp256k1(*secp256k1_public_key_hash)),
                        PublicKeyHash::P256(P256 { p256_public_key_hash }) => Self::PkhV0($crate::core::PublicKeyHashV0::P256(*p256_public_key_hash)),
                        PublicKeyHash::Bls(Bls { bls12_381_public_key_hash }) => Self::Bls(*bls12_381_public_key_hash),
                    }
                }
            }

            impl From<$id::PublicKeyHash> for $crate::core::PublicKeyHashV1 {
                fn from(value: $id::PublicKeyHash) -> Self {
                    use $id::{ PublicKeyHash, publickeyhash::{ Ed25519, Secp256k1, P256, Bls } };
                    match value {
                        PublicKeyHash::Ed25519(Ed25519 { ed25519_public_key_hash }) => Self::PkhV0($crate::core::PublicKeyHashV0::Ed25519(ed25519_public_key_hash)),
                        PublicKeyHash::Secp256k1(Secp256k1 { secp256k1_public_key_hash }) => Self::PkhV0($crate::core::PublicKeyHashV0::Secp256k1(secp256k1_public_key_hash)),
                        PublicKeyHash::P256(P256 { p256_public_key_hash }) => Self::PkhV0($crate::core::PublicKeyHashV0::P256(p256_public_key_hash)),
                        PublicKeyHash::Bls(Bls { bls12_381_public_key_hash }) => Self::Bls(bls12_381_public_key_hash),
                    }
                }
            }
        )+
    };
}

from_pkh!(block_info, constants);

pub mod raw {
    pub use tezos_codegen::proto016_ptmumbai::block_info;
    pub use tezos_codegen::proto016_ptmumbai::constants;

    pub(crate) use block_info::Operation;

    pub type BlockInfo = block_info::Proto016PtMumbaiBlockInfo;
    pub type OperationResult =
        block_info::Proto016PtMumbaiOperationAlphaSuccessfulManagerOperationResult;
    pub type BalanceUpdate = block_info::Proto016PtMumbaiOperationMetadataAlphaBalance;
    pub type MichelsonExpression = block_info::MichelineProto016PtMumbaiMichelsonV1Expression;
    pub type Constants = constants::Proto016PtMumbaiConstants;
}

pub mod api {
    use super::raw::{ self, block_info };
    use num::{ BigInt, BigUint };
    use tedium::{ u30, Dynamic, Sequence };
    use tezos_codegen::{
        proto016_ptmumbai::block_info::{
            Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo,
            Proto016PtMumbaiEntrypoint,
            Proto016PtMumbaiOperationAlphaContentsTransactionParameters,
            Proto016PtMumbaiContractId,
            proto016ptmumbaicontractid::Implicit,
            Proto016PtMumbaiOperationAlphaOperationContentsAndResultTransactionParameters,
        },
    };

    use crate::{
        core::{
            ballot::InvalidBallotError,
            BlockHash,
            ChainId,
            InvalidDiscriminantError,
            NonceHash,
            OperationHash,
            ProtocolHash,
            PublicKeyHashV1,
            RatioU16,
            SignatureV1,
            VotingPeriodKind,
            mutez::MutezPlus,
            transaction::Entrypoint,
            ContractHash,
            ContractId,
        },
        traits::{ ContainsBallots, ContainsProposals, Crypto, ContainsTransactions },
        util::abstract_unpack_dynseq,
    };

    use super::error::MumbaiConversionError;

    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct MumbaiBlockInfo {
        chain_id: ChainId,
        hash: BlockHash,
        header: MumbaiBlockHeader,
        metadata: Option<MumbaiMetadata>,
        operations: Vec<Vec<MumbaiOperation>>,
    }

    impl MumbaiBlockInfo {
        pub fn chain_id(&self) -> ChainId {
            self.chain_id
        }

        pub fn hash(&self) -> BlockHash {
            self.hash
        }

        pub fn header(&self) -> &MumbaiBlockHeader {
            &self.header
        }

        pub fn metadata(&self) -> Option<&MumbaiMetadata> {
            self.metadata.as_ref()
        }

        pub fn operations(&self) -> &[Vec<MumbaiOperation>] {
            &self.operations
        }
    }

    impl ContainsProposals for MumbaiBlockInfo {
        type ProposalsType = MumbaiProposals;

        fn has_proposals(&self) -> bool {
            self.operations.iter().any(|ops| ops.iter().any(|op| op.has_proposals()))
        }

        fn count_proposals(&self) -> usize {
            self.operations
                .iter()
                .map(|ops|
                    ops
                        .iter()
                        .map(|op| op.count_proposals())
                        .sum::<usize>()
                )
                .sum()
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            self.operations
                .iter()
                .flat_map(|ops| ops.iter().flat_map(|op| op.get_proposals()))
                .collect()
        }
    }

    impl ContainsTransactions for MumbaiBlockInfo {
        type TransactionType = MumbaiTransaction;

        fn has_transactions(&self) -> bool {
            self.operations.iter().any(|ops| ops.iter().any(|op| op.has_transactions()))
        }

        fn count_transactions(&self) -> usize {
            self.operations
                .iter()
                .map(|ops|
                    ops
                        .iter()
                        .map(|op| op.count_transactions())
                        .sum::<usize>()
                )
                .sum()
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            self.operations
                .iter()
                .flat_map(|ops| ops.iter().flat_map(|op| op.get_transactions()))
                .collect()
        }
    }

    impl ContainsBallots for MumbaiBlockInfo {
        type BallotType = MumbaiBallot;

        fn has_ballots(&self) -> bool {
            self.operations.iter().any(|ops| ops.iter().any(|op| op.has_ballots()))
        }

        fn count_ballots(&self) -> usize {
            self.operations
                .iter()
                .map(|ops|
                    ops
                        .iter()
                        .map(|op| op.count_ballots())
                        .sum::<usize>()
                )
                .sum()
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            self.operations
                .iter()
                .flat_map(|ops| ops.iter().flat_map(|op| op.get_ballots()))
                .collect()
        }
    }

    impl MumbaiBlockInfo {
        pub fn get_all_ballots(&self) -> Vec<MumbaiBallot> {
            self.get_ballots()
        }

        pub fn get_all_proposals(&self) -> Vec<MumbaiProposals> {
            self.get_proposals()
        }

        pub fn get_all_transactions(&self) -> Vec<MumbaiTransaction> {
            self.get_transactions()
        }
    }

    crate::boilerplate!(MumbaiProofOfWorkNonce = 8);
    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct MumbaiBlockHeader {
        level: i32,
        proto: u8,
        predecessor: crate::core::BlockHash,
        timestamp: crate::core::Timestamp,
        validation_pass: u8,
        operations_hash: crate::core::OperationListListHash,
        fitness: Vec<tedium::Bytes>,
        context: crate::core::ContextHash,
        payload_hash: crate::core::ValueHash,
        payload_round: i32,
        proof_of_work_nonce: MumbaiProofOfWorkNonce,
        seed_nonce_hash: Option<crate::core::NonceHash>,
        liquidity_baking_toggle_vote: i8,
        signature: crate::core::SignatureV1,
    }

    impl MumbaiBlockHeader {
        pub fn level(&self) -> i32 {
            self.level
        }
    }

    impl TryFrom<raw::block_info::RawBlockHeader> for MumbaiBlockHeader {
        type Error = crate::core::InvalidSignatureV1ByteLengthError;

        fn try_from(value: raw::block_info::RawBlockHeader) -> Result<Self, Self::Error> {
            Ok(Self {
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
                proof_of_work_nonce: MumbaiProofOfWorkNonce::from_fixed_bytes(
                    value.proof_of_work_nonce
                ),
                seed_nonce_hash: value.seed_nonce_hash.map(|nonce|
                    NonceHash::from_fixed_bytes(nonce.cycle_nonce)
                ),
                liquidity_baking_toggle_vote: value.liquidity_baking_toggle_vote,
                signature: crate::core::SignatureV1::try_from_bytes(value.signature.signature_v1)?,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct MumbaiOperation {
        chain_id: ChainId,
        hash: OperationHash,
        operation: MumbaiOperationPayload,
    }

    impl ContainsProposals for MumbaiOperation {
        type ProposalsType = MumbaiProposals;

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

    impl ContainsTransactions for MumbaiOperation {
        type TransactionType = MumbaiTransaction;

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

    impl ContainsBallots for MumbaiOperation {
        type BallotType = MumbaiBallot;

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

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct MumbaiOperationPayload {
        shell_header: MumbaiOperationShellHeader,
        operation: MumbaiOperationContainer,
    }

    impl ContainsProposals for MumbaiOperationPayload {
        type ProposalsType = MumbaiProposals;

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

    impl ContainsTransactions for MumbaiOperationPayload {
        type TransactionType = MumbaiTransaction;

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

    impl ContainsBallots for MumbaiOperationPayload {
        type BallotType = MumbaiBallot;

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

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MumbaiOperationShellHeader {
        branch: BlockHash,
    }

    impl MumbaiOperationShellHeader {
        pub const fn branch(&self) -> BlockHash {
            self.branch
        }

        pub const fn into_branch(self) -> BlockHash {
            self.branch
        }
    }

    impl From<raw::block_info::OperationShellHeader> for MumbaiOperationShellHeader {
        fn from(value: raw::block_info::OperationShellHeader) -> Self {
            Self {
                branch: BlockHash::from_fixed_bytes(value.branch.block_hash),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub enum MumbaiOperationContainer {
        WithoutMetadata {
            contents: Vec<MumbaiOperationContents>,
            signature: Option<SignatureV1>,
        },
        WithMetadata {
            contents: Vec<MumbaiOperationContentsAndResult>,
            signature: Option<SignatureV1>,
        },
    }

    impl ContainsTransactions for MumbaiOperationContainer {
        type TransactionType = MumbaiTransaction;

        fn has_transactions(&self) -> bool {
            match self {
                MumbaiOperationContainer::WithoutMetadata { contents, .. } => {
                    contents.iter().any(|op| op.has_transactions())
                }
                MumbaiOperationContainer::WithMetadata { contents, .. } => {
                    contents.iter().any(|op| op.has_transactions())
                }
            }
        }

        fn count_transactions(&self) -> usize {
            match self {
                MumbaiOperationContainer::WithoutMetadata { contents, .. } => {
                    contents
                        .iter()
                        .map(|op| op.count_transactions())
                        .sum()
                }
                MumbaiOperationContainer::WithMetadata { contents, .. } => {
                    contents
                        .iter()
                        .map(|op| op.count_transactions())
                        .sum()
                }
            }
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            match self {
                MumbaiOperationContainer::WithoutMetadata { contents, .. } => {
                    contents
                        .iter()
                        .flat_map(|op| op.get_transactions())
                        .collect()
                }
                MumbaiOperationContainer::WithMetadata { contents, .. } => {
                    contents
                        .iter()
                        .flat_map(|op| op.get_transactions())
                        .collect()
                }
            }
        }
    }

    impl ContainsProposals for MumbaiOperationContainer {
        type ProposalsType = MumbaiProposals;

        fn has_proposals(&self) -> bool {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents.iter().any(|op| op.has_proposals())
                }
                Self::WithMetadata { contents, .. } => contents.iter().any(|op| op.has_proposals()),
            }
        }

        fn count_proposals(&self) -> usize {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents
                        .iter()
                        .map(|op| op.count_proposals())
                        .sum()
                }
                Self::WithMetadata { contents, .. } => {
                    contents
                        .iter()
                        .map(|op| op.count_proposals())
                        .sum()
                }
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents
                        .iter()
                        .flat_map(|op| op.get_proposals())
                        .collect()
                }
                Self::WithMetadata { contents, .. } => {
                    contents
                        .iter()
                        .flat_map(|op| op.get_proposals())
                        .collect()
                }
            }
        }
    }

    impl ContainsBallots for MumbaiOperationContainer {
        type BallotType = MumbaiBallot;

        fn has_ballots(&self) -> bool {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents.iter().any(|op| op.has_ballots())
                }
                Self::WithMetadata { contents, .. } => contents.iter().any(|op| op.has_ballots()),
            }
        }

        fn count_ballots(&self) -> usize {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents
                        .iter()
                        .map(|op| op.count_ballots())
                        .sum()
                }
                Self::WithMetadata { contents, .. } => {
                    contents
                        .iter()
                        .map(|op| op.count_ballots())
                        .sum()
                }
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents
                        .iter()
                        .flat_map(|op| op.get_ballots())
                        .collect()
                }
                Self::WithMetadata { contents, .. } => {
                    contents
                        .iter()
                        .flat_map(|op| op.get_ballots())
                        .collect()
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MumbaiBallot {
        source: PublicKeyHashV1,
        period: i32,
        proposal: ProtocolHash,
        ballot: crate::core::ballot::Ballot,
    }

    impl MumbaiBallot {
        pub fn source(&self) -> PublicKeyHashV1 {
            self.source
        }

        pub fn period(&self) -> i32 {
            self.period
        }

        pub fn proposal(&self) -> ProtocolHash {
            self.proposal
        }

        pub fn ballot(&self) -> crate::core::ballot::Ballot {
            self.ballot
        }
    }

    impl TryFrom<raw::block_info::proto016ptmumbaioperationalphacontents::Ballot> for MumbaiBallot {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::proto016ptmumbaioperationalphacontents::Ballot
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                source: PublicKeyHashV1::from(value.source.signature_public_key_hash),
                period: value.period,
                proposal: value.proposal.protocol_hash.into(),
                ballot: value.ballot.try_into()?,
            })
        }
    }

    impl TryFrom<raw::block_info::proto016ptmumbaioperationalphaoperationcontentsandresult::Ballot>
    for MumbaiBallot {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::proto016ptmumbaioperationalphaoperationcontentsandresult::Ballot
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                source: PublicKeyHashV1::from(value.source.signature_public_key_hash),
                period: value.period,
                proposal: value.proposal.protocol_hash.into(),
                ballot: value.ballot.try_into()?,
            })
        }
    }

    impl TryFrom<raw::block_info::proto016ptmumbaioperationalphacontentsorsignatureprefix::Ballot>
    for MumbaiBallot {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::proto016ptmumbaioperationalphacontentsorsignatureprefix::Ballot
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                source: PublicKeyHashV1::from(value.source.signature_public_key_hash),
                period: value.period,
                proposal: value.proposal.protocol_hash.into(),
                ballot: value.ballot.try_into()?,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub enum MumbaiOperationContents {
        Ballot(MumbaiBallot),
        Proposals(MumbaiProposals),
        Transaction(MumbaiTransaction),
        Raw(raw::block_info::Proto016PtMumbaiOperationAlphaContents),
    }

    pub type MumbaiRawProposals =
        raw::block_info::proto016ptmumbaioperationalphacontents::Proposals;

    pub type MumbaiRawProposalsAndResult =
        raw::block_info::proto016ptmumbaioperationalphaoperationcontentsandresult::Proposals;

    #[derive(Clone, Debug, Hash, PartialEq)]
    pub struct MumbaiProposals {
        source: PublicKeyHashV1,
        period: i32,
        proposals: Vec<ProtocolHash>,
    }

    impl std::fmt::Display for MumbaiProposals {
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

    impl MumbaiProposals {
        pub fn source(&self) -> PublicKeyHashV1 {
            self.source
        }

        pub fn period(&self) -> i32 {
            self.period
        }

        pub fn proposals(&self) -> &[ProtocolHash] {
            self.proposals.as_ref()
        }
    }

    impl From<MumbaiRawProposals> for MumbaiProposals {
        fn from(value: MumbaiRawProposals) -> Self {
            Self {
                source: value.source.signature_public_key_hash.into(),
                period: value.period,
                proposals: value.proposals
                    .into_inner()
                    .into_iter()
                    .map(|proposal| proposal.protocol_hash.into())
                    .collect(),
            }
        }
    }

    impl From<MumbaiRawProposalsAndResult> for MumbaiProposals {
        fn from(value: MumbaiRawProposalsAndResult) -> Self {
            Self {
                source: value.source.signature_public_key_hash.into(),
                period: value.period,
                proposals: value.proposals
                    .into_inner()
                    .into_iter()
                    .map(|proposal| proposal.protocol_hash.into())
                    .collect(),
            }
        }
    }

    impl ContainsTransactions for MumbaiOperationContents {
        type TransactionType = MumbaiTransaction;

        fn has_transactions(&self) -> bool {
            matches!(self, &Self::Transaction(..))
        }

        fn count_transactions(&self) -> usize {
            match self {
                Self::Transaction(..) => 1,
                _ => 0,
            }
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            match self {
                Self::Transaction(ret) => vec![ret.clone()],
                _ => Vec::new(),
            }
        }
    }

    impl ContainsProposals for MumbaiOperationContents {
        type ProposalsType = MumbaiProposals;

        fn has_proposals(&self) -> bool {
            matches!(self, &Self::Proposals(_))
        }

        fn count_proposals(&self) -> usize {
            match self {
                Self::Proposals(_) => 1,
                _ => 0,
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                Self::Proposals(proposals) => vec![proposals.clone()],
                _ => vec![],
            }
        }
    }

    impl ContainsBallots for MumbaiOperationContents {
        type BallotType = MumbaiBallot;

        fn has_ballots(&self) -> bool {
            matches!(self, Self::Ballot(_))
        }

        fn count_ballots(&self) -> usize {
            match self {
                Self::Ballot(_) => 1,
                _ => 0,
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                Self::Ballot(ballot) => vec![*ballot],
                _ => vec![],
            }
        }
    }

    impl TryFrom<raw::block_info::Proto016PtMumbaiOperationAlphaContents>
    for MumbaiOperationContents {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::Proto016PtMumbaiOperationAlphaContents
        ) -> Result<Self, Self::Error> {
            match value {
                block_info::Proto016PtMumbaiOperationAlphaContents::Ballot(ballot) => {
                    Ok(Self::Ballot(ballot.try_into()?))
                }
                block_info::Proto016PtMumbaiOperationAlphaContents::Proposals(proposals) => {
                    Ok(Self::Proposals(proposals.into()))
                }
                block_info::Proto016PtMumbaiOperationAlphaContents::Transaction(transaction) => {
                    Ok(Self::Transaction(transaction.into()))
                }
                other => Ok(Self::Raw(other)),
            }
        }
    }

    pub type MumbaiContractId = crate::core::ContractId<PublicKeyHashV1>;

    impl From<Proto016PtMumbaiContractId> for MumbaiContractId {
        fn from(value: Proto016PtMumbaiContractId) -> Self {
            match value {
                Proto016PtMumbaiContractId::Implicit(Implicit { signature_public_key_hash }) =>
                    Self::Implicit(PublicKeyHashV1::from(signature_public_key_hash)),
                Proto016PtMumbaiContractId::Originated(originated) => {
                    let ch = originated.0.into_inner();
                    Self::Originated(ContractHash::from_fixed_bytes(ch.contract_hash))
                }
            }
        }
    }

    impl serde::Serialize for MumbaiContractId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_base58check())
            } else {
                match self {
                    Self::Implicit(pkh) => {
                        serializer.serialize_newtype_variant("ContractId", 0, "Implicit", pkh)
                    }
                    Self::Originated(ch) => {
                        serializer.serialize_newtype_variant("ContractId", 1, "Originated", ch)
                    }
                }
            }
        }
    }

    impl From<Proto016PtMumbaiEntrypoint> for Entrypoint {
        fn from(value: Proto016PtMumbaiEntrypoint) -> Self {
            match value {
                Proto016PtMumbaiEntrypoint::default(_) => Self::Default,
                Proto016PtMumbaiEntrypoint::root(_) => Self::Root,
                Proto016PtMumbaiEntrypoint::r#do(_) => Self::Do,
                Proto016PtMumbaiEntrypoint::set_delegate(_) => Self::SetDelegate,
                Proto016PtMumbaiEntrypoint::remove_delegate(_) => Self::RemoveDelegate,
                Proto016PtMumbaiEntrypoint::deposit(_) => Self::Deposit,
                Proto016PtMumbaiEntrypoint::named(s) => Self::Named(s.0.into_inner()),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash, Serialize)]
    pub struct MumbaiTransactionParameters {
        entrypoint: Entrypoint,
        value: tedium::Bytes,
    }

    impl From<Proto016PtMumbaiOperationAlphaOperationContentsAndResultTransactionParameters>
    for MumbaiTransactionParameters {
        fn from(
            value: Proto016PtMumbaiOperationAlphaOperationContentsAndResultTransactionParameters
        ) -> Self {
            Self {
                entrypoint: value.entrypoint.into(),
                value: value.value.into_inner(),
            }
        }
    }

    impl From<Proto016PtMumbaiOperationAlphaContentsTransactionParameters>
    for MumbaiTransactionParameters {
        fn from(value: Proto016PtMumbaiOperationAlphaContentsTransactionParameters) -> Self {
            Self {
                entrypoint: value.entrypoint.into(),
                value: value.value.into_inner(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash, Serialize)]
    pub struct MumbaiTransaction {
        source: PublicKeyHashV1,
        fee: MutezPlus,
        counter: BigUint,
        gas_limit: BigUint,
        storage_limit: BigUint,
        amount: MutezPlus,
        destination: MumbaiContractId,
        parameters: std::option::Option<MumbaiTransactionParameters>,
        // metadata: Option<MumbaiTransactionMetadata>,
    }

    impl MumbaiTransaction {
        pub fn source(&self) -> PublicKeyHashV1 {
            self.source
        }

        pub fn fee(&self) -> &MutezPlus {
            &self.fee
        }

        pub fn counter(&self) -> &BigUint {
            &self.counter
        }

        pub fn gas_limit(&self) -> &BigUint {
            &self.gas_limit
        }

        pub fn storage_limit(&self) -> &BigUint {
            &self.storage_limit
        }

        pub fn amount(&self) -> &MutezPlus {
            &self.amount
        }

        pub fn destination(&self) -> ContractId<PublicKeyHashV1> {
            self.destination
        }

        pub fn parameters(&self) -> Option<&MumbaiTransactionParameters> {
            self.parameters.as_ref()
        }
    }

    impl From<raw::block_info::proto016ptmumbaioperationalphacontents::Transaction>
    for MumbaiTransaction {
        fn from(
            value: raw::block_info::proto016ptmumbaioperationalphacontents::Transaction
        ) -> Self {
            Self {
                source: PublicKeyHashV1::from(value.source.signature_public_key_hash),
                fee: MutezPlus::from_biguint(value.fee.into_inner()),
                counter: value.counter.into_inner(),
                gas_limit: value.gas_limit.into_inner(),
                storage_limit: value.storage_limit.into_inner(),
                amount: MutezPlus::from_biguint(value.amount.into_inner()),
                destination: MumbaiContractId::from(value.destination),
                parameters: value.parameters.map(|params| params.into()),
            }
        }
    }

    impl From<raw::block_info::proto016ptmumbaioperationalphaoperationcontentsandresult::Transaction>
    for MumbaiTransaction {
        fn from(
            value: raw::block_info::proto016ptmumbaioperationalphaoperationcontentsandresult::Transaction
        ) -> Self {
            Self {
                source: PublicKeyHashV1::from(value.source.signature_public_key_hash),
                fee: MutezPlus::from_biguint(value.fee.into_inner()),
                counter: value.counter.into_inner(),
                gas_limit: value.gas_limit.into_inner(),
                storage_limit: value.storage_limit.into_inner(),
                amount: MutezPlus::from_biguint(value.amount.into_inner()),
                destination: MumbaiContractId::from(value.destination),
                parameters: value.parameters.map(|params| params.into()),
                // TODO - metadata
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub enum MumbaiOperationContentsAndResult {
        Ballot(MumbaiBallot),
        Proposals(MumbaiProposals),
        Transaction(MumbaiTransaction),
        Raw(raw::block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult),
    }

    impl ContainsTransactions for MumbaiOperationContentsAndResult {
        type TransactionType = MumbaiTransaction;

        fn has_transactions(&self) -> bool {
            matches!(self, &Self::Transaction(..))
        }

        fn count_transactions(&self) -> usize {
            match self {
                Self::Transaction(..) => 1,
                _ => 0,
            }
        }

        fn get_transactions(&self) -> Vec<Self::TransactionType> {
            match self {
                Self::Transaction(ret) => vec![ret.clone()],
                _ => Vec::new(),
            }
        }
    }

    impl ContainsProposals for MumbaiOperationContentsAndResult {
        type ProposalsType = MumbaiProposals;

        fn has_proposals(&self) -> bool {
            matches!(self, &Self::Proposals(_))
        }

        fn count_proposals(&self) -> usize {
            match self {
                MumbaiOperationContentsAndResult::Proposals(_) => 1,
                _ => 0,
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                MumbaiOperationContentsAndResult::Proposals(ret) => vec![ret.clone()],
                _ => vec![],
            }
        }
    }

    impl ContainsBallots for MumbaiOperationContentsAndResult {
        type BallotType = MumbaiBallot;

        fn has_ballots(&self) -> bool {
            matches!(self, Self::Ballot(_))
        }

        fn count_ballots(&self) -> usize {
            match self {
                Self::Ballot(_) => 1,
                _ => 0,
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                Self::Ballot(ballot) => vec![*ballot],
                _ => vec![],
            }
        }
    }

    impl MumbaiOperationContentsAndResult {
        /// Returns `true` if the mumbai operation contents and result is [`Ballot`].
        ///
        /// [`Ballot`]: MumbaiOperationContentsAndResult::Ballot
        #[must_use]
        pub fn is_ballot(&self) -> bool {
            matches!(self, Self::Ballot(..))
        }

        /// Returns `true` if the mumbai operation contents and result is [`Transaction`].
        ///
        /// [`Transaction`]: MumbaiOperationContentsAndResult::Transaction
        #[must_use]
        pub fn is_transaction(&self) -> bool {
            matches!(self, Self::Transaction(..))
        }

        /// Returns `true` if the mumbai operation contents and result is [`Proposals`].
        ///
        /// [`Proposals`]: MumbaiOperationContentsAndResult::Proposals
        #[must_use]
        pub fn is_proposals(&self) -> bool {
            matches!(self, Self::Proposals(..))
        }
    }

    impl TryFrom<block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult>
    for MumbaiOperationContentsAndResult {
        type Error = InvalidBallotError;

        fn try_from(
            value: block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult
        ) -> Result<Self, Self::Error> {
            match value {
                block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult::Ballot(
                    ballot,
                ) => Ok(Self::Ballot(ballot.try_into()?)),
                block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult::Proposals(
                    proposals,
                ) => Ok(Self::Proposals(proposals.into())),
                block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult::Transaction(
                    transaction,
                ) => Ok(Self::Transaction(transaction.into())),
                other => Ok(Self::Raw(other)),
            }
        }
    }

    fn unpack_operation_contents_and_result(
        contents: Dynamic<
            u30,
            Sequence<block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult>
        >
    ) -> Result<Vec<MumbaiOperationContentsAndResult>, InvalidBallotError> {
        contents
            .into_inner()
            .into_iter()
            .map(|op| op.try_into())
            .collect()
    }

    impl TryFrom<raw::block_info::OperationDenestDyn> for MumbaiOperationContainer {
        type Error = super::error::MumbaiConversionError;

        fn try_from(value: raw::block_info::OperationDenestDyn) -> Result<Self, Self::Error> {
            use block_info::{ operationdenestdyn, OperationDenestDyn::* };
            match value {
                Operation_with_too_large_metadata(
                    operationdenestdyn::Operation_with_too_large_metadata {
                        contents_and_signature_prefix,
                        signature_suffix,
                    },
                ) => {
                    let (contents, opt_sig_prefix) = match
                        content_filter::split_operations_sig_prefix(
                            contents_and_signature_prefix.into_inner()
                        )
                    {
                        Ok((contents, opt_sig_prefix)) => (contents, opt_sig_prefix),
                        Err(e) => {
                            return Err(e);
                        }
                    };
                    let signature = content_filter::sigv1_from_parts(
                        opt_sig_prefix,
                        signature_suffix
                    );
                    Ok(Self::WithoutMetadata { contents, signature: Some(signature) })
                }
                Operation_without_metadata(
                    operationdenestdyn::Operation_without_metadata {
                        contents_and_signature_prefix,
                        signature_suffix,
                    },
                ) => {
                    let (contents, opt_sig_prefix) = match
                        content_filter::split_operations_sig_prefix(
                            contents_and_signature_prefix.into_inner()
                        )
                    {
                        Ok((contents, opt_sig_prefix)) => (contents, opt_sig_prefix),
                        Err(e) => {
                            return Err(e);
                        }
                    };
                    let signature = content_filter::sigv1_from_parts(
                        opt_sig_prefix,
                        signature_suffix
                    );
                    Ok(Self::WithoutMetadata { contents, signature: Some(signature) })
                }
                Operation_with_metadata(operationdenestdyn::Operation_with_metadata(op)) => {
                    match op {
                        block_info::Proto016PtMumbaiOperationAlphaOperationWithMetadata::Operation_with_metadata(
                            raw::block_info::proto016ptmumbaioperationalphaoperationwithmetadata::Operation_with_metadata {
                                contents,
                                signature,
                            },
                        ) => {
                            let contents = unpack_operation_contents_and_result(contents)?;
                            let signature = signature
                                .into_inner()
                                .map(|sig| SignatureV1::try_from_bytes(sig.signature_v1))
                                .transpose()?;
                            Ok(Self::WithMetadata { contents, signature })
                        }
                        block_info::Proto016PtMumbaiOperationAlphaOperationWithMetadata::Operation_without_metadata(
                            raw::block_info::proto016ptmumbaioperationalphaoperationwithmetadata::Operation_without_metadata {
                                contents,
                                signature,
                            },
                        ) => {
                            let contents = unpack_operation_contents(contents)?;
                            let signature = signature
                                .into_inner()
                                .map(|sig| SignatureV1::try_from_bytes(sig.signature_v1))
                                .transpose()?;
                            Ok(Self::WithoutMetadata { contents, signature })
                        }
                    }
                }
            }
        }
    }

    fn unpack_operation_contents(
        contents: Dynamic<u30, Sequence<block_info::Proto016PtMumbaiOperationAlphaContents>>
    ) -> Result<Vec<MumbaiOperationContents>, MumbaiConversionError> {
        contents
            .into_inner()
            .into_iter()
            .map(|op| Ok(op.try_into()?))
            .collect()
    }

    mod content_filter {
        use tedium::{ Decode, Encode, FixedBytes };

        use crate::{
            core::{ ballot::InvalidBallotError, SignatureV1 },
            mumbai::error::{ MumbaiConversionError, UnexpectedSignaturePrefixError },
        };

        use super::MumbaiOperationContents;

        pub type ContentsOrSigPref =
            crate::mumbai::raw::block_info::Proto016PtMumbaiOperationAlphaContentsOrSignaturePrefix;

        fn transcode_contents_without_sig(
            value: ContentsOrSigPref
        ) -> Result<MumbaiOperationContents, InvalidBallotError> {
            let buf = value.to_bytes();
            let raw =
                crate::mumbai::raw::block_info::Proto016PtMumbaiOperationAlphaContents::decode(buf);
            raw.try_into()
        }

        impl TryFrom<ContentsOrSigPref> for MumbaiOperationContents {
            type Error = crate::mumbai::error::MumbaiConversionError;

            fn try_from(value: ContentsOrSigPref) -> Result<Self, Self::Error> {
                match value {
                    tezos_codegen::proto016_ptmumbai::block_info::Proto016PtMumbaiOperationAlphaContentsOrSignaturePrefix::Signature_prefix(
                        _,
                    ) =>
                        Err(MumbaiConversionError::SignaturePrefix(UnexpectedSignaturePrefixError)),
                    other => Ok(transcode_contents_without_sig(other)?),
                }
            }
        }

        pub(super) fn split_operations_sig_prefix(
            elts: Vec<ContentsOrSigPref>
        ) -> Result<
            (Vec<super::MumbaiOperationContents>, Option<tedium::FixedBytes<32>>),
            MumbaiConversionError
        > {
            let mut iter = elts.into_iter();
            let opt_sig_prefix = {
                match iter.next_back() {
                    Some(
                        crate::mumbai::raw::block_info::Proto016PtMumbaiOperationAlphaContentsOrSignaturePrefix::Signature_prefix(
                            crate::mumbai::raw::block_info::proto016ptmumbaioperationalphacontentsorsignatureprefix::Signature_prefix {
                                signature_prefix: crate::mumbai::raw::block_info::BlsSignaturePrefix::Bls_prefix(
                                    pref,
                                ),
                            },
                        ),
                    ) => {
                        Some(pref.0)
                    }
                    _ => None,
                }
            };
            let actual_contents = iter
                .map(|elt| Ok(elt.try_into()?))
                .collect::<Result<Vec<MumbaiOperationContents>, MumbaiConversionError>>()?;
            Ok((actual_contents, opt_sig_prefix))
        }

        pub(super) fn sigv1_from_parts(
            opt_sig_prefix: Option<tedium::FixedBytes<32>>,
            signature_suffix: FixedBytes<64>
        ) -> SignatureV1 {
            match opt_sig_prefix {
                Some(pref) => {
                    const TOTLEN: usize = 96;
                    debug_assert_eq!(TOTLEN, pref.len() + signature_suffix.len());
                    let mut accum: Vec<u8> = Vec::with_capacity(TOTLEN);
                    accum.extend_from_slice(pref.bytes());
                    accum.extend_from_slice(signature_suffix.bytes());
                    debug_assert_eq!(accum.len(), TOTLEN);
                    let Ok(arr) = accum.try_into() else { unreachable!() };
                    SignatureV1::Bls(FixedBytes::from_array(arr))
                }
                None => SignatureV1::SigV0(signature_suffix),
            }
        }
    }

    impl TryFrom<raw::block_info::OperationRhs> for MumbaiOperationPayload {
        type Error = MumbaiConversionError;

        fn try_from(value: raw::block_info::OperationRhs) -> Result<Self, Self::Error> {
            Ok(Self {
                shell_header: value.0.into_inner().into(),
                operation: value.1.into_inner().try_into()?,
            })
        }
    }

    impl TryFrom<raw::block_info::Operation> for MumbaiOperation {
        type Error = MumbaiConversionError;

        fn try_from(value: raw::block_info::Operation) -> Result<Self, Self::Error> {
            Ok(Self {
                chain_id: ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: OperationHash::from_fixed_bytes(value.hash.operation_hash),
                operation: value.operation_rhs.try_into()?,
            })
        }
    }

    impl TryFrom<raw::block_info::BlockHeaderMetadata> for MumbaiMetadata {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(value: raw::block_info::BlockHeaderMetadata) -> Result<Self, Self::Error> {
            Ok(Self {
                test_chain_status: value.test_chain_status.into(),
                max_operations_ttl: value.max_operations_ttl.to_i32(),
                max_operation_data_length: value.max_operation_data_length.to_i32(),
                max_block_header_length: value.max_block_header_length.to_i32(),
                max_operation_list_length: unpack_max_operation_list_length(
                    value.max_operation_list_length
                ),
                proposer: value.proposer.signature_public_key_hash.into(),
                baker: value.baker.signature_public_key_hash.into(),
                level_info: value.level_info.into(),
                voting_period_info: value.voting_period_info.try_into()?,
                nonce_hash: unpack_metadata_nonce_hash(value.nonce_hash),
                deactivated: value.deactivated
                    .into_inner()
                    .into_iter()
                    .map(|elt| elt.into())
                    .collect(),
                balance_updates: abstract_unpack_dynseq(value.balance_updates),
                liquidity_baking_toggle_ema: value.liquidity_baking_toggle_ema.into(),
                implicit_operations_results: abstract_unpack_dynseq(
                    value.implicit_operations_results
                ),
                proposer_consensus_key: value.proposer_consensus_key.signature_public_key_hash.into(),
                baker_consensus_key: value.baker_consensus_key.signature_public_key_hash.into(),
                consumed_milligas: value.consumed_milligas.into_inner(),
                dal_attestation: value.dal_attestation.into_inner().map(|elt| elt.into_inner()),
            })
        }
    }

    fn unpack_metadata_nonce_hash(
        nonce_hash: block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataNonceHash
    ) -> Option<NonceHash> {
        match nonce_hash {
            raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataNonceHash::None(_) => None,
            raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataNonceHash::Some(
                raw::block_info::proto016ptmumbaiblockheaderalphametadatanoncehash::Some {
                    cycle_nonce,
                },
            ) => Some(cycle_nonce.into()),
        }
    }

    fn unpack_max_operation_list_length(
        max_operation_list_length: Dynamic<
            u30,
            Dynamic<
                u30,
                Sequence<block_info::BlockHeaderMetadataMaxOperationListLengthDenestDynDenestDynDenestSeq>
            >
        >
    ) -> Vec<block_info::BlockHeaderMetadataMaxOperationListLengthDenestDynDenestDynDenestSeq> {
        max_operation_list_length
            .into_inner()
            .into_inner()
            .into_iter()
            .map(|elt| elt.into())
            .collect()
    }

    /// TODO[epic=facade] - Mumbai test chain status
    pub type MumbaiTestChainStatus = raw::block_info::TestChainStatus;

    /// TODO[epic=facade] - Mumbai level info
    pub type MumbaiLevelInfo = raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataLevelInfo;

    #[derive(Clone, Copy, Debug, PartialEq, Hash)]
    pub struct MumbaiVotingPeriod {
        index: i32,
        kind: VotingPeriodKind,
        start_position: i32,
    }

    type RawVotingPeriodKind =
        raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriodKind;

    impl TryFrom<RawVotingPeriodKind> for VotingPeriodKind {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(value: RawVotingPeriodKind) -> Result<Self, Self::Error> {
            let raw = value.get_tagval();
            Self::try_from_u8(raw)
        }
    }

    impl TryFrom<raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriod>
    for MumbaiVotingPeriod {
        type Error = crate::core::InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(
            value: raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriod
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                index: value.index,
                kind: value.kind.try_into()?,
                start_position: value.start_position,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub struct MumbaiVotingPeriodInfo {
        voting_period: MumbaiVotingPeriod,
        position: i32,
        remaining: i32,
    }

    impl tedium::Decode for MumbaiVotingPeriodInfo {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
            let raw = Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo::parse(p)?;
            Ok(raw.try_into().map_err(tedium::ParseError::reify)?)
        }
    }

    impl TryFrom<Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo>
    for MumbaiVotingPeriodInfo {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(
            value: Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                voting_period: value.voting_period.try_into()?,
                position: value.position,
                remaining: value.remaining,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Hash)]
    pub struct MumbaiMetadata {
        test_chain_status: MumbaiTestChainStatus,
        max_operations_ttl: i32,
        max_operation_data_length: i32,
        max_block_header_length: i32,
        max_operation_list_length: Vec<raw::block_info::BlockHeaderMetadataMaxOperationListLengthDenestDynDenestDynDenestSeq>,
        proposer: PublicKeyHashV1,
        baker: PublicKeyHashV1,
        level_info: MumbaiLevelInfo,
        voting_period_info: MumbaiVotingPeriodInfo,
        nonce_hash: Option<NonceHash>,
        deactivated: Vec<raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataDeactivatedDenestDynDenestSeq>,
        balance_updates: Vec<raw::block_info::Proto016PtMumbaiOperationMetadataAlphaBalance>,
        liquidity_baking_toggle_ema: i32,
        implicit_operations_results: Vec<raw::block_info::Proto016PtMumbaiOperationAlphaSuccessfulManagerOperationResult>,
        proposer_consensus_key: PublicKeyHashV1,
        baker_consensus_key: PublicKeyHashV1,
        consumed_milligas: BigUint,
        dal_attestation: Option<BigInt>,
    }

    mod impls {
        use super::*;

        impl TryFrom<crate::mumbai::raw::BlockInfo> for MumbaiBlockInfo {
            type Error = MumbaiConversionError;

            fn try_from(value: crate::mumbai::raw::BlockInfo) -> Result<Self, Self::Error> {
                Ok(Self {
                    chain_id: value.chain_id.chain_id.into(),
                    hash: value.hash.block_hash.into(),
                    header: value.header.into_inner().try_into()?,
                    metadata: value.metadata.map(|x| x.into_inner().try_into()).transpose()?, // FIXME[epic=facade]
                    operations: unpack_block_operations(value.operations)?,
                })
            }
        }

        fn unpack_block_operations(
            operations: Dynamic<
                u30,
                Sequence<Dynamic<u30, Dynamic<u30, Sequence<crate::mumbai::raw::Operation>>>>
            >
        ) -> Result<Vec<Vec<MumbaiOperation>>, MumbaiConversionError> {
            operations
                .into_inner()
                .into_iter()
                .map(|ddx| {
                    ddx.into_inner()
                        .into_inner()
                        .into_iter()
                        .map(|op| op.try_into())
                        .collect::<Result<Vec<MumbaiOperation>, MumbaiConversionError>>()
                })
                .collect()
        }

        impl tedium::Decode for MumbaiBlockInfo {
            fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
                let raw = <crate::mumbai::raw::BlockInfo as tedium::Decode>::parse(p)?;
                Ok(raw.try_into().map_err(tedium::ParseError::reify)?)
            }
        }
    }

    pub type MumbaiRawConstants = raw::constants::Proto016PtMumbaiConstants;

    // TODO[epic=facade] - DAL parametric constants
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct MumbaiConstantsDalParametric {
        feature_enable: bool,
        number_of_slots: i16,
        attestation_lag: i16,
        availability_threshold: i16,
        redundancy_factor: u8,
        page_size: u16,
        slot_size: i32,
        number_of_shards: u16,
    }

    impl From<raw::constants::Proto016PtMumbaiConstantsDalParametric>
    for MumbaiConstantsDalParametric {
        fn from(value: raw::constants::Proto016PtMumbaiConstantsDalParametric) -> Self {
            Self {
                feature_enable: value.feature_enable,
                number_of_slots: value.number_of_slots,
                attestation_lag: value.attestation_lag,
                availability_threshold: value.availability_threshold,
                redundancy_factor: value.redundancy_factor,
                page_size: value.page_size,
                slot_size: value.slot_size.to_i32(),
                number_of_shards: value.number_of_shards,
            }
        }
    }

    crate::boilerplate!(Seed32 = 32);
    #[derive(Debug, Clone, PartialEq, Hash)]
    pub struct MumbaiConstants {
        proof_of_work_nonce_size: u8,
        nonce_length: u8,
        max_anon_ops_per_block: u8,
        max_operation_data_length: i32,
        max_proposals_per_delegate: u8,
        max_micheline_node_count: i32,
        max_micheline_bytes_limit: i32,
        max_allowed_global_constants_depth: i32,
        cache_layout_size: u8,
        michelson_maximum_type_size: u16,
        smart_rollup_max_wrapped_proof_binary_size: i32,
        smart_rollup_message_size_limit: i32,
        smart_rollup_max_number_of_messages_per_level: BigUint,
        preserved_cycles: u8,
        blocks_per_cycle: i32,
        blocks_per_commitment: i32,
        nonce_revelation_threshold: i32,
        blocks_per_stake_snapshot: i32,
        cycles_per_voting_period: i32,
        hard_gas_limit_per_operation: BigInt,
        hard_gas_limit_per_block: BigInt,
        proof_of_work_threshold: i64,
        minimal_stake: BigUint,
        vdf_difficulty: i64,
        seed_nonce_revelation_tip: BigUint,
        origination_size: i32,
        baking_reward_fixed_portion: BigUint,
        baking_reward_bonus_per_slot: BigUint,
        endorsing_reward_per_slot: BigUint,
        cost_per_byte: BigUint,
        hard_storage_limit_per_operation: BigInt,
        quorum_min: i32,
        quorum_max: i32,
        min_proposal_quorum: i32,
        liquidity_baking_subsidy: BigUint,
        liquidity_baking_toggle_ema_threshold: i32,
        max_operations_time_to_live: i16,
        minimal_block_delay: i64,
        delay_increment_per_round: i64,
        consensus_committee_size: i32,
        consensus_threshold: i32,
        minimal_participation_ratio: RatioU16,
        max_slashing_period: i32,
        frozen_deposits_percentage: i32,
        double_baking_punishment: BigUint,
        ratio_of_frozen_deposits_slashed_per_double_endorsement: RatioU16,
        testnet_dictator: Option<PublicKeyHashV1>,
        initial_seed: Option<Seed32>,
        cache_script_size: i32,
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
        dal_parametric: MumbaiConstantsDalParametric,
        smart_rollup_enable: bool,
        smart_rollup_arith_pvm_enable: bool,
        smart_rollup_origination_size: i32,
        smart_rollup_challenge_window_in_blocks: i32,
        smart_rollup_stake_amount: BigUint,
        smart_rollup_commitment_period_in_blocks: i32,
        smart_rollup_max_lookahead_in_blocks: i32,
        smart_rollup_max_active_outbox_levels: i32,
        smart_rollup_max_outbox_messages_per_level: i32,
        smart_rollup_number_of_sections_in_dissection: u8,
        smart_rollup_timeout_period_in_blocks: i32,
        smart_rollup_max_number_of_cemented_commitments: i32,
        smart_rollup_max_number_of_parallel_games: i32,
        zk_rollup_enable: bool,
        zk_rollup_origination_size: i32,
        zk_rollup_min_pending_to_process: i32,
    }

    impl MumbaiConstants {
        pub fn minimal_block_delay(&self) -> i64 {
            self.minimal_block_delay
        }

        pub fn dal_parametric(&self) -> MumbaiConstantsDalParametric {
            self.dal_parametric
        }
    }

    type RawParticipationRatio = raw::constants::Proto016PtMumbaiConstantsMinimalParticipationRatio;

    impl From<RawParticipationRatio> for RatioU16 {
        fn from(value: RawParticipationRatio) -> Self {
            Self::new(value.numerator, value.denominator)
        }
    }

    type RawSlashingRatio =
        raw::constants::Proto016PtMumbaiConstantsRatioOfFrozenDepositsSlashedPerDoubleEndorsement;

    impl From<RawSlashingRatio> for RatioU16 {
        fn from(value: RawSlashingRatio) -> Self {
            Self::new(value.numerator, value.denominator)
        }
    }

    impl From<MumbaiRawConstants> for MumbaiConstants {
        fn from(value: MumbaiRawConstants) -> Self {
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
                smart_rollup_max_wrapped_proof_binary_size: value.smart_rollup_max_wrapped_proof_binary_size.to_i32(),
                smart_rollup_message_size_limit: value.smart_rollup_message_size_limit.to_i32(),
                smart_rollup_max_number_of_messages_per_level: value.smart_rollup_max_number_of_messages_per_level.into_inner(),
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
                testnet_dictator: value.testnet_dictator.map(|pkh_raw|
                    pkh_raw.signature_public_key_hash.into()
                ),
                initial_seed: value.initial_seed.map(|seed_raw| seed_raw.random.into()),
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
                dal_parametric: value.dal_parametric.into(),
                smart_rollup_enable: value.smart_rollup_enable,
                smart_rollup_arith_pvm_enable: value.smart_rollup_arith_pvm_enable,
                smart_rollup_origination_size: value.smart_rollup_origination_size.to_i32(),
                smart_rollup_challenge_window_in_blocks: value.smart_rollup_challenge_window_in_blocks.to_i32(),
                smart_rollup_stake_amount: value.smart_rollup_stake_amount.into_inner(),
                smart_rollup_commitment_period_in_blocks: value.smart_rollup_commitment_period_in_blocks.to_i32(),
                smart_rollup_max_lookahead_in_blocks: value.smart_rollup_max_lookahead_in_blocks,
                smart_rollup_max_active_outbox_levels: value.smart_rollup_max_active_outbox_levels,
                smart_rollup_max_outbox_messages_per_level: value.smart_rollup_max_outbox_messages_per_level.to_i32(),
                smart_rollup_number_of_sections_in_dissection: value.smart_rollup_number_of_sections_in_dissection,
                smart_rollup_timeout_period_in_blocks: value.smart_rollup_timeout_period_in_blocks.to_i32(),
                smart_rollup_max_number_of_cemented_commitments: value.smart_rollup_max_number_of_cemented_commitments.to_i32(),
                smart_rollup_max_number_of_parallel_games: value.smart_rollup_max_number_of_parallel_games.to_i32(),
                zk_rollup_enable: value.zk_rollup_enable,
                zk_rollup_origination_size: value.zk_rollup_origination_size.to_i32(),
                zk_rollup_min_pending_to_process: value.zk_rollup_min_pending_to_process.to_i32(),
            }
        }
    }

    impl tedium::Decode for MumbaiConstants {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
            let raw = MumbaiRawConstants::parse(p)?;
            Ok(raw.into())
        }
    }
}