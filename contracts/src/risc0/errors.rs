use stylus_sdk::{
    alloy_primitives::FixedBytes,
    alloy_sol_types::{sol, SolError},
};

use crate::common::VerificationError;

sol! {
    error SelectorMismatch(bytes4 received, bytes4 expected);
}

/// RISC Zero-specific error types
#[derive(Debug)]
pub enum RiscZeroError {
    /// Common verification errors
    Common(VerificationError),
    /// RISC Zero selector mismatch
    SelectorMismatch {
        received: FixedBytes<4>,
        expected: FixedBytes<4>,
    },
}

impl RiscZeroError {
    /// Convert error to ABI-encoded bytes
    pub fn abi_encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            RiscZeroError::Common(e) => e.abi_encode(),
            RiscZeroError::SelectorMismatch { received, expected } => SelectorMismatch {
                received: *received,
                expected: *expected,
            }
            .abi_encode(),
        }
    }
}

impl From<VerificationError> for RiscZeroError {
    fn from(error: VerificationError) -> Self {
        RiscZeroError::Common(error)
    }
}

impl RiscZeroError {
    pub const VERIFICATION_FAILED: RiscZeroError = RiscZeroError::Common(VerificationError::VerificationFailed);
    pub const INVALID_INITIALIZATION: RiscZeroError = RiscZeroError::Common(VerificationError::InvalidInitialization);
    pub const ALREADY_INITIALIZED: RiscZeroError = RiscZeroError::Common(VerificationError::AlreadyInitialized);
    pub const INVALID_PROOF_DATA: RiscZeroError = RiscZeroError::Common(VerificationError::InvalidProofData);
} 