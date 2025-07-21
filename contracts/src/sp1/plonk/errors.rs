use stylus_sdk::{
    alloy_primitives::FixedBytes,
    alloy_sol_types::{sol, SolError},
};

use crate::common::VerificationError;

sol! {
    error WrongVerifierSelector(bytes4 received, bytes4 expected);
    error InvalidProofStructure();
    error ChallengeGenerationFailed();
    error OpeningVerificationFailed();
}

#[derive(Debug)]
pub enum Sp1PlonkError {
    Common(VerificationError),
    WrongVerifierSelector {
        received: FixedBytes<4>,
        expected: FixedBytes<4>,
    },
    InvalidProofStructure,
    ChallengeGenerationFailed,
    OpeningVerificationFailed,
}

impl Sp1PlonkError {
    pub fn abi_encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            Sp1PlonkError::Common(e) => e.abi_encode(),
            Sp1PlonkError::WrongVerifierSelector { received, expected } => {
                WrongVerifierSelector {
                    received: *received,
                    expected: *expected,
                }
                .abi_encode()
            }
            Sp1PlonkError::InvalidProofStructure => InvalidProofStructure {}.abi_encode(),
            Sp1PlonkError::ChallengeGenerationFailed => ChallengeGenerationFailed {}.abi_encode(),
            Sp1PlonkError::OpeningVerificationFailed => OpeningVerificationFailed {}.abi_encode(),
        }
    }
}

impl From<VerificationError> for Sp1PlonkError {
    fn from(error: VerificationError) -> Self {
        Sp1PlonkError::Common(error)
    }
}

impl Sp1PlonkError {
    pub const VERIFICATION_FAILED: Sp1PlonkError = 
        Sp1PlonkError::Common(VerificationError::VerificationFailed);
    pub const INVALID_INITIALIZATION: Sp1PlonkError = 
        Sp1PlonkError::Common(VerificationError::InvalidInitialization);
    pub const ALREADY_INITIALIZED: Sp1PlonkError = 
        Sp1PlonkError::Common(VerificationError::AlreadyInitialized);
    pub const INVALID_PROOF_DATA: Sp1PlonkError = 
        Sp1PlonkError::Common(VerificationError::InvalidProofData);
}

#[cfg(test)]
mod tests {
    use super::*;
    use stylus_sdk::alloy_primitives::FixedBytes;

    #[test]
    fn test_error_abi_encoding() {
        // Test common error encoding
        let error = Sp1PlonkError::VERIFICATION_FAILED;
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());

        // Test selector mismatch error
        let received = FixedBytes::<4>::from([0x01, 0x02, 0x03, 0x04]);
        let expected = FixedBytes::<4>::from([0x05, 0x06, 0x07, 0x08]);
        let error = Sp1PlonkError::WrongVerifierSelector { received, expected };
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());

        // Test other error types
        let error = Sp1PlonkError::InvalidProofStructure;
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());

        let error = Sp1PlonkError::ChallengeGenerationFailed;
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());

        let error = Sp1PlonkError::OpeningVerificationFailed;
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_error_conversion() {
        let verification_error = VerificationError::VerificationFailed;
        let sp1_error: Sp1PlonkError = verification_error.into();
        
        match sp1_error {
            Sp1PlonkError::Common(VerificationError::VerificationFailed) => (),
            _ => panic!("Conversion failed"),
        }
    }

    #[test]
    fn test_constant_errors() {
        // Test that constant errors are properly defined
        match Sp1PlonkError::VERIFICATION_FAILED {
            Sp1PlonkError::Common(VerificationError::VerificationFailed) => (),
            _ => panic!("Constant error mismatch"),
        }

        match Sp1PlonkError::INVALID_PROOF_DATA {
            Sp1PlonkError::Common(VerificationError::InvalidProofData) => (),
            _ => panic!("Constant error mismatch"),
        }

        match Sp1PlonkError::INVALID_INITIALIZATION {
            Sp1PlonkError::Common(VerificationError::InvalidInitialization) => (),
            _ => panic!("Constant error mismatch"),
        }

        match Sp1PlonkError::ALREADY_INITIALIZED {
            Sp1PlonkError::Common(VerificationError::AlreadyInitialized) => (),
            _ => panic!("Constant error mismatch"),
        }
    }

    #[test]
    fn test_debug_formatting() {
        let error = Sp1PlonkError::InvalidProofStructure;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("InvalidProofStructure"));

        let error = Sp1PlonkError::ChallengeGenerationFailed;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("ChallengeGenerationFailed"));
    }
}