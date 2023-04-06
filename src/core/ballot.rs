#[repr(i8)]
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Ballot {
    Yay = 0,
    Nay = 1,
    Pass = 2,
}

impl serde::Serialize for Ballot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_i8(*self as i8)
        }
    }
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

impl crate::traits::BallotLike for Ballot {
    fn to_tally(&self) -> crate::util::VoteStatistics {
        match self {
            Self::Yay => crate::util::VoteStatistics::new(1, 0, 0),
            Self::Nay => crate::util::VoteStatistics::new(0, 1, 0),
            Self::Pass => crate::util::VoteStatistics::new(0, 0, 1),
        }
    }
}