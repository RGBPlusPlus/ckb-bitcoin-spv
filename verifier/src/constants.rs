//! Constants.

// Constants for the chain type flag
// Specifically utilizing the two highest bits for chain type identification
pub const FLAG_CHAIN_TYPE_MAINNET: u8 = 0b0000_0000; // for mainnet
pub const FLAG_CHAIN_TYPE_TESTNET: u8 = 0b1000_0000; // for testnet
pub const FLAG_CHAIN_TYPE_SIGNET: u8 = 0b0100_0000; // for signet
pub const FLAG_CHAIN_TYPE_TESTNET4: u8 = 0b1100_0000; // for testnet4

/// The minimum difficulty bits (difficulty 1) used by testnet's 20-minute exception rule.
pub const TESTNET_MIN_DIFFICULTY_BITS: u32 = 0x1d00ffff;
