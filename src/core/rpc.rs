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
        Self { protocol, next_protocol }
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
    fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
        let protocol: ProtocolHash = FixedBytes::<32>::parse(p)?.into();
        let next_protocol: ProtocolHash = FixedBytes::<32>::parse(p)?.into();
        Ok(Self { protocol, next_protocol })
    }
}

impl Display for ProtocolHashPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ protocol: {}, next_protocol: {} }}", self.protocol, self.next_protocol)
    }
}

pub mod proposals {
    use std::{ collections::HashMap, borrow::Borrow };

    use tedium::Decode;

    use crate::{ core::ProtocolHash, traits::BinaryDataType };

    #[derive(Clone, Copy, Debug, Decode)]
    struct RawItem(pub ProtocolHash, pub i64);

    type RawList = tedium::Dynamic<tedium::u30, tedium::Sequence<RawItem>>;

    #[derive(Clone, Debug)]
    pub struct ProposalMap {
        table: HashMap<ProtocolHash, i64>,
    }

    impl tedium::Decode for ProposalMap {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
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
        pub fn transient_lookup<P: tedium::Parser>(
            p: &mut P,
            key: &ProtocolHash
        ) -> tedium::ParseResult<Option<i64>> {
            let mut ret = None;
            let _lp: tedium::u30 = tedium::u30::parse(p)?;
            p.set_fit(_lp.into())?;
            while p.remainder() > 0 {
                let _key = p.take_fixed::<32>()?;
                if key.as_array_ref() != &_key {
                    let _ = p.take_fixed::<8>();
                    continue;
                } else {
                    let value = i64::parse(p)?;
                    let _ = ret.replace(value);
                    break;
                }
            }
            Ok(ret)
        }
        pub fn contains<K>(&self, k: K) -> bool where K: Borrow<[u8; 32]> {
            let key = ProtocolHash::from(k.borrow());
            self.table.contains_key(&key)
        }

        pub fn get<K>(&self, k: K) -> Option<i64> where K: Borrow<[u8; 32]> {
            let key = ProtocolHash::from(k.borrow());
            self.table.get(&key).copied()
        }
    }
}

pub mod listings {
    use std::collections::HashMap;

    use tedium::Decode;

    use crate::core::{ PublicKeyHashV0, Mutez };

    #[derive(Clone, Copy, Debug, Decode)]
    struct RawItem(pub PublicKeyHashV0, pub Mutez);

    type RawList = tedium::Dynamic<tedium::u30, tedium::Sequence<RawItem>>;

    #[derive(Clone, Debug)]
    pub struct ListingMap {
        table: HashMap<PublicKeyHashV0, Mutez>,
    }
    impl tedium::Decode for ListingMap {
        fn parse<P: tedium::Parser>(p: &mut P) -> tedium::ParseResult<Self> where Self: Sized {
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
        pub fn transient_lookup<P: tedium::Parser>(
            p: &mut P,
            key: &PublicKeyHashV0
        ) -> tedium::ParseResult<Option<Mutez>> {
            let mut ret = None;
            let _lp: tedium::u30 = tedium::u30::parse(p)?;
            p.set_fit(_lp.into())?;
            while p.remainder() > 0 {
                let headword = p.take_u8()?;
                match (headword, key) {
                    | (0, &PublicKeyHashV0::Ed25519(payload))
                    | (1, &PublicKeyHashV0::Secp256k1(payload))
                    | (2, &PublicKeyHashV0::P256(payload)) => {
                        let _payload = p.take_fixed::<20>()?;
                        if _payload != payload.to_array() {
                            let _ = p.take_fixed::<8>()?;
                            continue;
                        } else {
                            let value = Mutez::parse(p)?;
                            let _ = ret.replace(value);
                            break;
                        }
                    }
                    _ => {
                        let _ = p.take_fixed::<28>()?;
                    }
                }
            }
            Ok(ret)
        }

        pub fn contains<K>(&self, k: K) -> bool where PublicKeyHashV0: From<K> {
            let key = PublicKeyHashV0::from(k);
            self.table.contains_key(&key)
        }

        pub fn get<K>(&self, k: K) -> Option<Mutez> where PublicKeyHashV0: From<K> {
            let key = PublicKeyHashV0::from(k);
            self.table.get(&key).copied()
        }
    }
}