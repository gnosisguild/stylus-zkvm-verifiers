use stylus_sdk::alloy_sol_types::{sol, SolError};

sol! {
    error VerificationFailed();
    error InvalidInitialization();
    error AlreadyInitialized();
    error InvalidProofData();
}

#[derive(Debug)]
pub enum VerificationError {
    VerificationFailed,
    InvalidInitialization,
    AlreadyInitialized,
    InvalidProofData,
}

impl VerificationError {
    pub fn abi_encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            VerificationError::VerificationFailed => VerificationFailed {}.abi_encode(),
            VerificationError::InvalidInitialization => InvalidInitialization {}.abi_encode(),
            VerificationError::AlreadyInitialized => AlreadyInitialized {}.abi_encode(),
            VerificationError::InvalidProofData => InvalidProofData {}.abi_encode(),
        }
    }
} 