use stylus_sdk::alloy_primitives::B256;

/// System state zero digest used for successful execution claims
/// Reference: https://github.com/risc0/risc0-ethereum/blob/ab2fdafac60327e310121ada9e65bce8a439fba2/contracts/src/IRiscZeroVerifier.sol#L63
pub const SYSTEM_STATE_ZERO_DIGEST: [u8; 32] = [
    0xa3, 0xac, 0xc2, 0x71, 0x17, 0x41, 0x89, 0x96, 0x34, 0x0b, 0x84, 0xe5, 0xa9, 0x0f,
    0x3e, 0xf4, 0xc4, 0x9d, 0x22, 0xc7, 0x9e, 0x44, 0xaa, 0xd8, 0x22, 0xec, 0x9c, 0x31,
    0x3e, 0x1e, 0xb8, 0xe2,
];

/// Get the system state zero digest as a B256
pub fn system_state_zero_digest() -> B256 {
    B256::from(SYSTEM_STATE_ZERO_DIGEST)
}

/// Tag constants for digest computation
pub mod tags {
    /// Tag for ReceiptClaim digest computation
    pub const RECEIPT_CLAIM_TAG: &[u8] = b"risc0.ReceiptClaim";
    
    /// Tag for Output digest computation
    pub const OUTPUT_TAG: &[u8] = b"risc0.Output";
    
    /// Tag for verifying key IC list
    pub const VK_IC_TAG: &[u8] = b"risc0_groth16.VerifyingKey.IC";
    
    /// Tag for verifying key digest
    pub const VK_TAG: &[u8] = b"risc0_groth16.VerifyingKey";
} 