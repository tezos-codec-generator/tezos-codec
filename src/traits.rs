/// Trait for types that store fixed-size binary data in a consistent
/// way across multiple protocols
pub trait BinaryDataType<const N: usize>: AsPayload + Copy {
    const DATA_LEN : usize = N;

    fn as_array_ref(&self) -> &[u8; N];

    fn as_fixed_bytes(&self) -> &tedium::FixedBytes<N>;
}

pub trait ContainsBallots {
    /// Specific type used to represent the ballot operations that are
    /// possibly contained within values of [`Self`].
    type BallotType;

    /// Returns `true` if there is at least one ballot operation contained within this object.
    fn has_ballots(&self) -> bool;

    /// Returns the cumulative number of ballots contained within this object.
    fn count_ballots(&self) -> usize;

    /// Returns a [`Vec`] containing all the ballots recursively contained within this object.
    fn get_ballots(&self) -> Vec<Self::BallotType>;
}

/// Extension trait on [`ContainsBallots`]
pub trait ContainsBallotsExt: ContainsBallots {
    /// Computes and returns a summary table of the voting statistics for
    /// the set of ballots that are recursively contained within this object.
    fn tally(&self) -> crate::util::VoteStatistics;
}

/// Marker trait for types that are byte-oriented containers with a nominal
/// Base58Check representation.
pub trait AsPayload {
    /// Returns an immutable slice over the payload bytes of `self`.
    fn as_payload(&self) -> &[u8];
}

/// Marker trait for Base58Check-show types that have a value-invariant prefix
pub trait StaticPrefix {
    /// Constant prefix to be prepended to the payload-bytes of the type in question,
    /// just before Base58Check encoding, to ensure a consistent prefix in the resulting
    /// ciphertext.
    const PREFIX: &'static [u8];
}

/// Marker trait for Base58Check-show types whose prefix is computed per value,
/// whether or not it is invariant over all values.
///
/// See the refinement sub-trait, [`StaticPrefix`], which provides a blanket
/// implementation of this trait for all its [`Sized`] implementors.
pub trait DynamicPrefix {
    /// Returns a static byte-slice to be prepended to the payload-bytes before
    /// Base58Check encoding, to ensure a consistent prefix in the resulting
    /// ciphertext.
    fn get_prefix(&self) -> &'static [u8];
}

impl<C: StaticPrefix + Sized> DynamicPrefix for C {
    #[inline]
    fn get_prefix(&self) -> &'static [u8] {
        Self::PREFIX
    }
}


pub trait Crypto: AsPayload + DynamicPrefix {
    /// Returns a Base58Check-encoded String informed by the binary prefix
    /// signified by the type and value of `self`.
    fn to_base58check(&self) -> String {
        let prefix : &'static [u8] = self.get_prefix();
        let payload : &[u8] = self.as_payload();
        crate::core::base58::to_base58check(prefix, payload)
    }
}