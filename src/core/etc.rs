use crate::{ traits::{ Crypto, StaticPrefix }, impl_crypto_display, boilerplate };

boilerplate!(OperationHash = 32);
impl_crypto_display!(OperationHash);
impl_serde_crypto!(OperationHash);

impl OperationHash {
    /// Preimage of ciphertext prefix `o`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [5, 116];
}

impl StaticPrefix for OperationHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for OperationHash {}

boilerplate!(ChainId = 4);
impl_crypto_display!(ChainId);
impl_serde_crypto!(ChainId);

impl ChainId {
    /// Preimage of ciphertext prefix `net`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 3] = [87, 82, 0];
}

impl StaticPrefix for ChainId {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for ChainId {}

boilerplate!(BlockHash = 32);

impl_crypto_display!(BlockHash);

impl_serde_crypto!(BlockHash);

impl BlockHash {
    /// Preimage of ciphertext prefix `B`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [1, 52];
}

impl StaticPrefix for BlockHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for BlockHash {}

boilerplate!(ContextHash = 32);
impl_crypto_display!(ContextHash);
impl ContextHash {
    /// Preimage of ciphertext prefix `Co`.
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [79, 199];
}
impl StaticPrefix for ContextHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}
impl Crypto for ContextHash {}

boilerplate!(OperationListListHash = 32);
impl_crypto_display!(OperationListListHash);
impl_serde_crypto!(OperationListListHash);

impl OperationListListHash {
    /// Preimage of ciphertext prefix `LLo`
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 3] = [29, 159, 109];
}

impl StaticPrefix for OperationListListHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for OperationListListHash {}

boilerplate!(ProtocolHash = 32);
impl_crypto_display!(ProtocolHash);
impl_serde_crypto!(ProtocolHash);

impl ProtocolHash {
    /// Preimage of ciphertext prefix `P`.
    ///
    /// TODO: implement mutation tests to verify the correct ciphertext prefix
    pub const BASE58_PREFIX: [u8; 2] = [2, 170];
}

impl StaticPrefix for ProtocolHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl Crypto for ProtocolHash {}

boilerplate!(ValueHash = 32);
impl_crypto_display!(ValueHash);

impl ValueHash {
    /// Preimage bytes for ciphertext prefix `vh`.
    pub const BASE58_PREFIX: [u8; 3] = [1, 106, 242];
}

impl crate::traits::StaticPrefix for ValueHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}

impl crate::traits::Crypto for ValueHash {}

crate::boilerplate!(NonceHash = 32);
crate::impl_crypto_display!(NonceHash);

impl NonceHash {
    /// Preimage bytes for ciphertext prefix `nce`.
    pub const BASE58_PREFIX: [u8; 3] = [69, 220, 169];
}

impl StaticPrefix for NonceHash {
    const PREFIX: &'static [u8] = &Self::BASE58_PREFIX;
}
impl Crypto for NonceHash {}