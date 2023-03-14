/// Trait for types that store fixed-size binary data in a consistent
/// way across multiple protocols
pub trait BinaryDataType<const N: usize>: AsPayload + Copy {
    const DATA_LEN: usize = N;

    /// Extracts an immutable array reference from `self`.
    fn as_array_ref(&self) -> &[u8; N];

    /// Extracts an immutable [`FixedBytes`] reference from `self`.
    fn as_fixed_bytes(&self) -> &tedium::FixedBytes<N>;
}

/// Marker trait for types representing Ballot values (yay, nay, pass).
pub trait BallotLike {
    /// Returns a [`VoteStatistics`] object that accurately classifies
    /// this ballot-like type.
    fn to_tally(&self) -> crate::util::VoteStatistics;
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

impl<T> ContainsBallotsExt
    for T
    where T: ContainsBallots, <T as ContainsBallots>::BallotType: BallotLike
{
    fn tally(&self) -> crate::util::VoteStatistics {
        let tmp = self.get_ballots();
        let mut ret = crate::util::VoteStatistics::default();
        tmp.iter().for_each(|ballot| {
            ret += ballot.to_tally();
        });
        ret
    }
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
        let prefix: &'static [u8] = self.get_prefix();
        let payload: &[u8] = self.as_payload();
        crate::core::base58::to_base58check(prefix, payload)
    }

    /// [`std::fmt::Display`]-style formatting function for writing the string
    /// representation of a Crypto type.
    fn base58check_fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.to_base58check())
    }
}

#[macro_export]
/// Macro for implementing [`std::fmt::Display`] on `Crypto` types via their
/// implicit human-readable string representation (i.e. Base58Check).
///
/// Accepts a comma-separated list of type-names to implement Display over,
/// with trailing commas allowed.
macro_rules! impl_crypto_display {
    ($($tname:ident),+ $(,)?) => {
        $( impl std::fmt::Display for $tname {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                <Self as $crate::traits::Crypto>::base58check_fmt(&self, f)
            }
        } )+
    };
}