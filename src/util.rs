#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct VoteStatistics {
    yay_count: usize,
    nay_count: usize,
    pass_count: usize,
}

impl std::ops::Add for VoteStatistics {
    type Output = VoteStatistics;

    fn add(self, other: VoteStatistics) -> Self::Output {
        Self {
            yay_count: self.yay_count + other.yay_count,
            nay_count: self.nay_count + other.nay_count,
            pass_count: self.pass_count + other.pass_count,
        }
    }
}

impl std::ops::AddAssign for VoteStatistics {
    fn add_assign(&mut self, other: VoteStatistics) {
        self.yay_count += other.yay_count;
        self.nay_count += other.nay_count;
        self.pass_count += other.pass_count;
    }
}

impl VoteStatistics {
    /// Creates a new [`VoteStatistics`] based on the values of the three individual metrics.
    pub const fn new(yay_count: usize, nay_count: usize, pass_count: usize) -> Self {
        Self { yay_count, nay_count, pass_count }
    }

    #[inline]
    pub const fn count(&self) -> usize {
        self.yay_count + self.nay_count + self.pass_count
    }

    /// Returns the `yay_count` field of this [`VoteStatistics`].
    pub const fn yay_count(&self) -> usize {
        self.yay_count
    }

    /// Returns the `nay_count` field of this [`VoteStatistics`].
    pub const fn nay_count(&self) -> usize {
        self.yay_count
    }

    /// Returns the `pass_count` field of this [`VoteStatistics`].
    pub const fn pass_count(&self) -> usize {
        self.pass_count
    }
}