use std::fmt::Display;

use tedium::FixedBytes;

use crate::traits::Crypto;

use super::ProtocolHash;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ProtocolHashPair {
    protocol: ProtocolHash,
    next_protocol: ProtocolHash,
}

impl std::fmt::Debug for ProtocolHashPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolHashPair")
            .field("protocol", &self.protocol.to_base58check())
            .field("next_protocol", &self.next_protocol.to_base58check())
            .finish()
    }
}

impl ProtocolHashPair {
    pub fn new(protocol: ProtocolHash, next_protocol: ProtocolHash) -> Self {
        Self {
            protocol,
            next_protocol,
        }
    }

    pub fn protocol(&self) -> ProtocolHash {
        self.protocol
    }

    pub fn next_protocol(&self) -> ProtocolHash {
        self.next_protocol
    }

    pub fn are_equal(&self) -> bool {
        self.protocol == self.next_protocol
    }

    pub fn are_different(&self) -> bool {
        self.protocol != self.next_protocol
    }
}

impl tedium::Decode for ProtocolHashPair {
    fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
    where
        Self: Sized,
    {
        let protocol: ProtocolHash = FixedBytes::<32>::parse(p)?.into();
        let next_protocol: ProtocolHash = FixedBytes::<32>::parse(p)?.into();
        Ok(Self {
            protocol,
            next_protocol,
        })
    }
}

impl Display for ProtocolHashPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ protocol: {}, next_protocol: {} }}",
            self.protocol, self.next_protocol
        )
    }
}

pub mod proposals {
    use std::{borrow::Borrow, collections::HashMap};

    use tedium::Decode;

    use crate::{core::ProtocolHash, traits::BinaryDataType};

    #[derive(Clone, Copy, Debug, Decode)]
    struct RawItem(pub ProtocolHash, pub i64);

    type RawList = tedium::Dynamic<tedium::u30, tedium::Sequence<RawItem>>;

    #[derive(Clone, Debug)]
    pub struct ProposalMap {
        table: HashMap<ProtocolHash, i64>,
    }

    impl tedium::Decode for ProposalMap {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
        where
            Self: Sized,
        {
            let raw = RawList::parse(p)?;
            let table = raw
                .into_inner()
                .into_iter()
                .map(|item| (item.0, item.1))
                .collect();
            Ok(Self { table })
        }
    }

    impl ProposalMap {
        /// Bleeding-edge lookup that optimizes
        /// for scenarios in which an in-memory [`ProposalMap`] is not necessary; a parse is performed
        /// incrementally and only a single key is interrogated, whose raw pair-element is returned without
        /// any in-memory construction of a proper [`ProposalMap`].
        pub fn transient_lookup<P: tedium::parse::ParserExt>(
            p: &mut P,
            key: &ProtocolHash,
        ) -> tedium::ParseResult<Option<i64>> {
            let _pl = p.process_prefix::<tedium::u30>()?;
            p.fast_kv_search::<ProtocolHash, i64, _, 32, 8>(key.as_array_ref(), i64::from_be_bytes)
        }

        pub fn contains<K>(&self, k: K) -> bool
        where
            K: Borrow<[u8; 32]>,
        {
            let key = ProtocolHash::from(k.borrow());
            self.table.contains_key(&key)
        }

        pub fn get<K>(&self, k: K) -> Option<i64>
        where
            K: Borrow<[u8; 32]>,
        {
            let key = ProtocolHash::from(k.borrow());
            self.table.get(&key).copied()
        }
    }
}

pub mod listings {
    use std::collections::HashMap;

    use tedium::Decode;

    use crate::core::{mutez::Mutez, PublicKeyHashV0};

    #[derive(Clone, Copy, Debug, Decode)]
    struct RawItem(pub PublicKeyHashV0, pub Mutez);

    type RawList = tedium::Dynamic<tedium::u30, tedium::Sequence<RawItem>>;

    #[derive(Clone, Debug)]
    pub struct ListingMap {
        table: HashMap<PublicKeyHashV0, Mutez>,
    }
    impl tedium::Decode for ListingMap {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self>
        where
            Self: Sized,
        {
            let raw = RawList::parse(p)?;
            let table = raw
                .into_inner()
                .into_iter()
                .map(|item| (item.0, item.1))
                .collect();
            Ok(Self { table })
        }
    }

    impl ListingMap {
        /// Bleeding-edge lookup that optimizes
        /// for scenarios in which an in-memory [`ListingMap`] is not necessary; a parse is performed
        /// incrementally and only a single key is interrogated, whose raw paired-value is returned without
        /// any in-memory construction of a proper [`ListingMap`].
        pub fn transient_lookup<P: tedium::parse::ParserExt>(
            p: &mut P,
            key: &PublicKeyHashV0,
        ) -> tedium::ParseResult<Option<Mutez>> {
            let _pl = p.process_prefix::<tedium::u30>()?;
            let raw_key = key.to_discriminated_bytes();
            let key_array = raw_key.try_into().unwrap_or_else(|_| unreachable!());
            p.fast_kv_search::<PublicKeyHashV0, Mutez, _, 21, 8>(&key_array, |arr| {
                i64::from_be_bytes(arr).into()
            })
        }

        pub fn contains<K>(&self, k: K) -> bool
        where
            PublicKeyHashV0: From<K>,
        {
            let key = PublicKeyHashV0::from(k);
            self.table.contains_key(&key)
        }

        pub fn get<K>(&self, k: K) -> Option<Mutez>
        where
            PublicKeyHashV0: From<K>,
        {
            let key = PublicKeyHashV0::from(k);
            self.table.get(&key).copied()
        }
    }
}
