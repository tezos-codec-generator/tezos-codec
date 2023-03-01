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
    fn add_assign(&mut self, other: VoteStatistics) -> () {
        self.yay_count += other.yay_count;
        self.nay_count += other.nay_count;
        self.pass_count += other.pass_count;
    }
}

impl VoteStatistics {

}