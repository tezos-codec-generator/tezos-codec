pub trait ContainsBallots {
    type BallotType;

    fn get_ballots(&self) -> Vec<Self::BallotType>;
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