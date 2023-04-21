#[derive(Debug, Clone, Serialize, PartialEq, Hash)]
pub enum Entrypoint {
    Default,
    Root,
    Do,
    SetDelegate,
    RemoveDelegate,
    Deposit,
    Named(String),
}
