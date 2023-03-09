use tezos_codegen::proto015_ptlimapt::{ block_info, baking_rights, constants };

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
    pub use tezos_codegen::proto015_ptlimapt::level;
    pub use tezos_codegen::proto015_ptlimapt::constants;
    pub use tezos_codegen::proto015_ptlimapt::block_info;
    pub use tezos_codegen::proto015_ptlimapt::baking_rights;

    pub(crate) use block_info::{ Operation, RawBlockHeader, BlockHeaderMetadata };

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
    use tedium::{ Dynamic, Sequence, u30 };
    use super::raw::{
        self,
        block_info::{
            Proto015PtLimaPtOperationAlphaContents,
            Proto015PtLimaPtOperationAlphaOperationWithMetadata,
            Proto015PtLimaPtOperationAlphaOperationContentsAndResult,
            OperationDenestDyn,
        },
    };

    use crate::{
        core::{ ProtocolHash, PublicKeyHashV0, BlockHash, ChainId },
        traits::{ ContainsBallots, Crypto, StaticPrefix },
    };


    crate::boilerplate!(LimaBlockPayloadHash = 32);
    crate::impl_crypto_display!(LimaBlockPayloadHash);

    impl LimaBlockPayloadHash {
        /// Preimage bytes for ciphertext prefix `vh`.
        pub const BASE58_PREFIX: [u8; 3] = [1, 106, 242];
    }

    impl crate::traits::StaticPrefix for LimaBlockPayloadHash {
        const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
    }

    impl crate::traits::Crypto for LimaBlockPayloadHash {}


    crate::boilerplate!(LimaProofOfWorkNonce = 8);

    crate::boilerplate!(LimaNonceHash = 32);
    crate::impl_crypto_display!(LimaNonceHash);

    impl LimaNonceHash {
        /// Preimage bytes for ciphertext prefix `nce`.
        pub const BASE58_PREFIX : [u8; 3] = [69, 220, 169];
    }

    impl StaticPrefix for LimaNonceHash {
        const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
    }
    impl Crypto for LimaNonceHash {}

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
        payload_hash: LimaBlockPayloadHash,
        payload_round: i32,
        proof_of_work_nonce: LimaProofOfWorkNonce,
        seed_nonce_hash: Option<LimaNonceHash>,
        liquidity_baking_toggle_vote: i8,
        signature: crate::core::SignatureV0,
    }

    impl From<raw::RawBlockHeader> for LimaBlockHeader {
        fn from(value: raw::RawBlockHeader) -> Self {
            Self {
                level: value.level,
                proto: value.proto,
                predecessor: BlockHash::from_fixed_bytes(value.predecessor.block_hash),
                timestamp: crate::core::Timestamp::from_i64(value.timestamp),
                validation_pass: value.validation_pass,
                operations_hash: crate::core::OperationListListHash::from_fixed_bytes(value.operations_hash.operation_list_list_hash),
                fitness: value.fitness.into_inner().into_iter().map(|elt| elt.into_inner()).collect(),
                context: crate::core::ContextHash::from_fixed_bytes(value.context.context_hash),
                payload_hash: LimaBlockPayloadHash::from_fixed_bytes(value.payload_hash.value_hash),
                payload_round: value.payload_round,
                proof_of_work_nonce: LimaProofOfWorkNonce::from_fixed_bytes(value.proof_of_work_nonce),
                seed_nonce_hash: value.seed_nonce_hash.map(|nonce| LimaNonceHash::from_fixed_bytes(nonce.cycle_nonce)),
                liquidity_baking_toggle_vote: value.liquidity_baking_toggle_vote,
                signature: crate::core::SignatureV0::from_fixed_bytes(value.signature.signature_v0),
            }
        }
    }

    pub type LimaMetadata = raw::BlockHeaderMetadata;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LimaOperationShellHeader {
        branch: BlockHash,
    }

    impl From<super::raw::block_info::OperationShellHeader> for LimaOperationShellHeader {
        fn from(value: super::raw::block_info::OperationShellHeader) -> Self {
            Self { branch: BlockHash::from_fixed_bytes(value.branch.block_hash) }
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
            let raw : raw::BlockInfo = raw::BlockInfo::parse(p)?;
            Ok(raw.into())
        }
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
                    .collect::<Vec<LimaOperation>>()
            )
            .collect()
    }

    impl From<raw::BlockInfo> for LimaBlockInfo {
        fn from(value: raw::BlockInfo) -> Self {
            Self {
                chain_id: ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: BlockHash::from(value.hash.block_hash),
                header: LimaBlockHeader::from(value.header.into_inner()),
                metadata: value.metadata.map(|x| LimaMetadata::from(x.into_inner())),
                operations: unpack_block_operations(value.operations),
            }
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

    impl From<super::raw::block_info::Operation> for LimaOperation {
        fn from(value: super::raw::block_info::Operation) -> Self {
            Self {
                chain_id: ChainId::from_fixed_bytes(value.chain_id.chain_id),
                hash: crate::core::OperationHash::from_fixed_bytes(value.hash.operation_hash),
                operation: LimaOperationPayload::from(value.operation_rhs),
            }
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
                shell_header: LimaOperationShellHeader::from(value.0.into_inner()),
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
        #[inline(always)]
        #[must_use]
        /// Creates a new [`LimaBallot`] with the given parameters as its respective fields.
        pub fn new(
            source: PublicKeyHashV0,
            period: i32,
            proposal: ProtocolHash,
            ballot: Ballot
        ) -> Self {
            Self { source, period, proposal, ballot }
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