pub trait Operation {
    type BallotType;

    fn is_ballot(&self) -> bool;

    fn as_ballot(&self) -> Option<&Self::BallotType>;
}