/// Trait for types that store fixed-size binary data in a consistent
/// way across multiple protocols
pub trait BinaryDataType<const N: usize>: AsPayload + Copy {
    const DATA_LEN : usize = N;

    fn as_array_ref(&self) -> &[u8; N];

    fn as_fixed_bytes(&self) -> &rust_runtime::FixedBytes<N>;
}

pub trait ContainsBallots {
    type BallotType;

    fn has_ballots(&self) -> bool;

    fn count_ballots(&self) -> usize;

    fn get_ballots(&self) -> Vec<Self::BallotType>;
}
pub trait ContainsBallotsExt: ContainsBallots {
    fn tally(&self) -> crate::util::VoteStatistics;
}

pub trait AsPayload {
    fn as_payload(&self) -> &[u8];
}

pub trait StaticPrefix {
    const PREFIX: &'static [u8];
}

pub trait DynamicPrefix {
    fn get_prefix(&self) -> &'static [u8];
}

impl<C: StaticPrefix + Sized> DynamicPrefix for C {
    #[inline]
    fn get_prefix(&self) -> &'static [u8] {
        Self::PREFIX
    }
}


pub trait Crypto: AsPayload + DynamicPrefix {
    /// Return a Base58Check-encoded String using the binary prefix
    /// appropriate for the static type (and runtime value).
    fn to_base58check(&self) -> String {
        let prefix : &'static [u8] = self.get_prefix();
        let payload : &[u8] = self.as_payload();
        crate::core::base58::to_base58check(prefix, payload)
    }
}