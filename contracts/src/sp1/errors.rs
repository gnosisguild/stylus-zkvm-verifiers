/*!
SP1-specific error types.
*/

use crate::common::VerificationError;

/// SP1-specific error types
#[derive(Debug)]
pub enum Sp1Error {
    /// Common verification errors
    Common(VerificationError),
    /// SP1-specific program ID mismatch
    ProgramIdMismatch,
    /// Invalid SP1 proof format
    InvalidProofFormat,
}

impl Sp1Error {
    /// Convert error to ABI-encoded bytes
    pub fn abi_encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            Sp1Error::Common(e) => e.abi_encode(),
            Sp1Error::ProgramIdMismatch => b"SP1: Program ID mismatch".to_vec(),
            Sp1Error::InvalidProofFormat => b"SP1: Invalid proof format".to_vec(),
        }
    }
}

impl From<VerificationError> for Sp1Error {
    fn from(error: VerificationError) -> Self {
        Sp1Error::Common(error)
    }
}

// Convenience constants for common errors
impl Sp1Error {
    pub const VERIFICATION_FAILED: Sp1Error = Sp1Error::Common(VerificationError::VerificationFailed);
    pub const INVALID_INITIALIZATION: Sp1Error = Sp1Error::Common(VerificationError::InvalidInitialization);
    pub const ALREADY_INITIALIZED: Sp1Error = Sp1Error::Common(VerificationError::AlreadyInitialized);
    pub const INVALID_PROOF_DATA: Sp1Error = Sp1Error::Common(VerificationError::InvalidProofData);
} 