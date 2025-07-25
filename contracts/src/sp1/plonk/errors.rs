use stylus_sdk::{
    alloy_primitives::FixedBytes,
    alloy_sol_types::{sol, SolError},
};

use crate::common::VerificationError;

sol! {
    error WrongVerifierSelector(bytes4 received, bytes4 expected);
    error InvalidProofData();
    error InvalidProofStructure();
    error InvalidPublicInputCount();
    error ChallengeComputationFailed();
    error LinearizationFailed();
    error KzgVerificationFailed();
    error InvalidFieldElement();
    error PairingCheckFailed();
    error VerificationFailed();
}

#[derive(Debug)]
pub enum Sp1PlonkError {
    Common(VerificationError),
    WrongVerifierSelector {
        received: FixedBytes<4>,
        expected: FixedBytes<4>,
    },
    InvalidProofData,
    InvalidProofStructure,
    InvalidPublicInputCount,
    ChallengeComputationFailed,
    LinearizationFailed,
    KzgVerificationFailed,
    InvalidFieldElement,
    PairingCheckFailed,
    VerificationFailed,
}

impl Sp1PlonkError {
    pub fn abi_encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            Sp1PlonkError::Common(e) => e.abi_encode(),
            Sp1PlonkError::WrongVerifierSelector { received, expected } => WrongVerifierSelector {
                received: *received,
                expected: *expected,
            }
            .abi_encode(),
            Sp1PlonkError::InvalidProofData => InvalidProofData {}.abi_encode(),
            Sp1PlonkError::InvalidProofStructure => InvalidProofStructure {}.abi_encode(),
            Sp1PlonkError::InvalidPublicInputCount => InvalidPublicInputCount {}.abi_encode(),
            Sp1PlonkError::ChallengeComputationFailed => ChallengeComputationFailed {}.abi_encode(),
            Sp1PlonkError::LinearizationFailed => LinearizationFailed {}.abi_encode(),
            Sp1PlonkError::KzgVerificationFailed => KzgVerificationFailed {}.abi_encode(),
            Sp1PlonkError::InvalidFieldElement => InvalidFieldElement {}.abi_encode(),
            Sp1PlonkError::PairingCheckFailed => PairingCheckFailed {}.abi_encode(),
            Sp1PlonkError::VerificationFailed => VerificationFailed {}.abi_encode(),
        }
    }
}