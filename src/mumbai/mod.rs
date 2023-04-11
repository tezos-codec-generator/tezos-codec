use tezos_codegen::proto016_ptmumbai::block_info;

pub mod error {
    use std::convert::Infallible;

    use crate::core::{
        ballot::InvalidBallotError, InvalidDiscriminantError, InvalidSignatureV1ByteLengthError,
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
            match value {}
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
            write!(
                f,
                "found unexpected signature prefix in non-final position of contents-list"
            )
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

from_pkh!(block_info);

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
    use super::raw::{self, block_info};
    use num::{BigInt, BigUint};
    use tedium::{u30, Dynamic, Sequence};
    use tezos_codegen::proto016_ptmumbai::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo;

    use crate::{
        core::{
            ballot::InvalidBallotError, BlockHash, ChainId, InvalidDiscriminantError,
            InvalidSignatureV1ByteLengthError, NonceHash, OperationHash, ProtocolHash,
            PublicKeyHashV1, SignatureV1, VotingPeriodKind,
        },
        traits::{ContainsBallots, ContainsProposals, Crypto},
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

    impl From<InvalidSignatureV1ByteLengthError> for tedium::parse::error::ExternalError {
        fn from(value: InvalidSignatureV1ByteLengthError) -> Self {
            Self::WidthViolation(tedium::error::WidthError::InvalidWidth {
                valid: &[64, 96usize],
                actual: value.0,
            })
        }
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
            self.operations
                .iter()
                .any(|ops| ops.iter().any(|op| op.has_proposals()))
        }

        fn count_proposals(&self) -> usize {
            self.operations
                .iter()
                .map(|ops| ops.iter().map(|op| op.count_proposals()).sum::<usize>())
                .sum()
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            self.operations
                .iter()
                .flat_map(|ops| ops.iter().flat_map(|op| op.get_proposals()))
                .collect()
        }
    }

    impl ContainsBallots for MumbaiBlockInfo {
        type BallotType = MumbaiBallot;

        fn has_ballots(&self) -> bool {
            self.operations
                .iter()
                .any(|ops| ops.iter().any(|op| op.has_ballots()))
        }

        fn count_ballots(&self) -> usize {
            self.operations
                .iter()
                .map(|ops| ops.iter().map(|op| op.count_ballots()).sum::<usize>())
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
                    value.operations_hash.operation_list_list_hash,
                ),
                fitness: value
                    .fitness
                    .into_inner()
                    .into_iter()
                    .map(|elt| elt.into_inner())
                    .collect(),
                context: crate::core::ContextHash::from_fixed_bytes(value.context.context_hash),
                payload_hash: crate::core::ValueHash::from_fixed_bytes(
                    value.payload_hash.value_hash,
                ),
                payload_round: value.payload_round,
                proof_of_work_nonce: MumbaiProofOfWorkNonce::from_fixed_bytes(
                    value.proof_of_work_nonce,
                ),
                seed_nonce_hash: value
                    .seed_nonce_hash
                    .map(|nonce| NonceHash::from_fixed_bytes(nonce.cycle_nonce)),
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
                    contents.iter().map(|op| op.count_proposals()).sum()
                }
                Self::WithMetadata { contents, .. } => {
                    contents.iter().map(|op| op.count_proposals()).sum()
                }
            }
        }

        fn get_proposals(&self) -> Vec<Self::ProposalsType> {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents.iter().flat_map(|op| op.get_proposals()).collect()
                }
                Self::WithMetadata { contents, .. } => {
                    contents.iter().flat_map(|op| op.get_proposals()).collect()
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
                    contents.iter().map(|op| op.count_ballots()).sum()
                }
                Self::WithMetadata { contents, .. } => {
                    contents.iter().map(|op| op.count_ballots()).sum()
                }
            }
        }

        fn get_ballots(&self) -> Vec<Self::BallotType> {
            match self {
                Self::WithoutMetadata { contents, .. } => {
                    contents.iter().flat_map(|op| op.get_ballots()).collect()
                }
                Self::WithMetadata { contents, .. } => {
                    contents.iter().flat_map(|op| op.get_ballots()).collect()
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
            value: raw::block_info::proto016ptmumbaioperationalphacontents::Ballot,
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
        for MumbaiBallot
    {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::proto016ptmumbaioperationalphaoperationcontentsandresult::Ballot,
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
        for MumbaiBallot
    {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::proto016ptmumbaioperationalphacontentsorsignatureprefix::Ballot,
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
            writeln!(
                f,
                "` proposed the following protocols during period {}:",
                self.period
            )?;
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
                proposals: value
                    .proposals
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
                proposals: value
                    .proposals
                    .into_inner()
                    .into_iter()
                    .map(|proposal| proposal.protocol_hash.into())
                    .collect(),
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

    impl TryFrom<raw::block_info::Proto016PtMumbaiOperationAlphaContents> for MumbaiOperationContents {
        type Error = InvalidBallotError;

        fn try_from(
            value: raw::block_info::Proto016PtMumbaiOperationAlphaContents,
        ) -> Result<Self, Self::Error> {
            match value {
                block_info::Proto016PtMumbaiOperationAlphaContents::Ballot(ballot) => {
                    Ok(Self::Ballot(ballot.try_into()?))
                }
                block_info::Proto016PtMumbaiOperationAlphaContents::Proposals(proposals) => {
                    Ok(Self::Proposals(proposals.into()))
                }
                other => Ok(Self::Raw(other)),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Hash)]
    pub enum MumbaiOperationContentsAndResult {
        Ballot(MumbaiBallot),
        Proposals(MumbaiProposals),
        Raw(raw::block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult),
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
    }

    impl TryFrom<block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult>
        for MumbaiOperationContentsAndResult
    {
        type Error = InvalidBallotError;

        fn try_from(
            value: block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult,
        ) -> Result<Self, Self::Error> {
            match value {
                block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult::Ballot(
                    ballot,
                ) => Ok(Self::Ballot(ballot.try_into()?)),
                block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult::Proposals(
                    proposals,
                ) => Ok(Self::Proposals(proposals.into())),
                other => Ok(Self::Raw(other)),
            }
        }
    }

    fn unpack_operation_contents_and_result(
        contents: Dynamic<
            u30,
            Sequence<block_info::Proto016PtMumbaiOperationAlphaOperationContentsAndResult>,
        >,
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
            use block_info::{operationdenestdyn, OperationDenestDyn::*};
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
        contents: Dynamic<u30, Sequence<block_info::Proto016PtMumbaiOperationAlphaContents>>,
    ) -> Result<Vec<MumbaiOperationContents>, MumbaiConversionError> {
        contents
            .into_inner()
            .into_iter()
            .map(|op| Ok(op.try_into()?))
            .collect()
    }

    mod content_filter {
        use tedium::{Decode, Encode, FixedBytes};

        use crate::{
            core::{ballot::InvalidBallotError, SignatureV1},
            mumbai::error::{MumbaiConversionError, UnexpectedSignaturePrefixError},
        };

        use super::MumbaiOperationContents;

        pub type ContentsOrSigPref =
            crate::mumbai::raw::block_info::Proto016PtMumbaiOperationAlphaContentsOrSignaturePrefix;

        fn transcode_contents_without_sig(
            value: ContentsOrSigPref,
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
            elts: Vec<ContentsOrSigPref>,
        ) -> Result<
            (
                Vec<super::MumbaiOperationContents>,
                Option<tedium::FixedBytes<32>>,
            ),
            MumbaiConversionError,
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
            signature_suffix: FixedBytes<64>,
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

    fn abstract_unpack_dynseq<T: Into<U>, U, L: tedium::dynamic::LenPref>(
        raw: Dynamic<L, Sequence<T>>,
    ) -> Vec<U> {
        raw.into_inner().into_iter().map(|elt| elt.into()).collect()
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
                    value.max_operation_list_length,
                ),
                proposer: value.proposer.signature_public_key_hash.into(),
                baker: value.baker.signature_public_key_hash.into(),
                level_info: value.level_info.into(),
                voting_period_info: value.voting_period_info.try_into()?,
                nonce_hash: unpack_metadata_nonce_hash(value.nonce_hash),
                deactivated: value
                    .deactivated
                    .into_inner()
                    .into_iter()
                    .map(|elt| elt.into())
                    .collect(),
                balance_updates: abstract_unpack_dynseq(value.balance_updates),
                liquidity_baking_toggle_ema: value.liquidity_baking_toggle_ema.into(),
                implicit_operations_results: abstract_unpack_dynseq(
                    value.implicit_operations_results,
                ),
                proposer_consensus_key: value
                    .proposer_consensus_key
                    .signature_public_key_hash
                    .into(),
                baker_consensus_key: value.baker_consensus_key.signature_public_key_hash.into(),
                consumed_milligas: value.consumed_milligas.into_inner(),
                dal_attestation: value
                    .dal_attestation
                    .into_inner()
                    .map(|elt| elt.into_inner()),
            })
        }
    }

    fn unpack_metadata_nonce_hash(
        nonce_hash: block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataNonceHash,
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
        >,
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

    impl
        TryFrom<
            raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriod,
        > for MumbaiVotingPeriod
    {
        type Error = crate::core::InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(
            value: raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfoVotingPeriod,
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
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
        where
            Self: Sized,
        {
            let raw = Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo::parse(p)?;
            Ok(raw.try_into().map_err(tedium::ParseError::reify)?)
        }
    }

    impl TryFrom<Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo> for MumbaiVotingPeriodInfo {
        type Error = InvalidDiscriminantError<VotingPeriodKind>;

        fn try_from(
            value: Proto016PtMumbaiBlockHeaderAlphaMetadataVotingPeriodInfo,
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
        max_operation_list_length: Vec<
            raw::block_info::BlockHeaderMetadataMaxOperationListLengthDenestDynDenestDynDenestSeq,
        >,
        proposer: PublicKeyHashV1,
        baker: PublicKeyHashV1,
        level_info: MumbaiLevelInfo,
        voting_period_info: MumbaiVotingPeriodInfo,
        nonce_hash: Option<NonceHash>,
        deactivated: Vec<
            raw::block_info::Proto016PtMumbaiBlockHeaderAlphaMetadataDeactivatedDenestDynDenestSeq,
        >,
        balance_updates: Vec<raw::block_info::Proto016PtMumbaiOperationMetadataAlphaBalance>,
        liquidity_baking_toggle_ema: i32,
        implicit_operations_results:
            Vec<raw::block_info::Proto016PtMumbaiOperationAlphaSuccessfulManagerOperationResult>,
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
                    metadata: value
                        .metadata
                        .map(|x| x.into_inner().try_into())
                        .transpose()?, // FIXME[epic=facade]
                    operations: unpack_block_operations(value.operations)?,
                })
            }
        }

        fn unpack_block_operations(
            operations: Dynamic<
                u30,
                Sequence<Dynamic<u30, Dynamic<u30, Sequence<crate::mumbai::raw::Operation>>>>,
            >,
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
            fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
            where
                Self: Sized,
            {
                let raw = <crate::mumbai::raw::BlockInfo as tedium::Decode>::parse(p)?;
                Ok(raw.try_into().map_err(tedium::ParseError::reify)?)
            }
        }
    }
}
