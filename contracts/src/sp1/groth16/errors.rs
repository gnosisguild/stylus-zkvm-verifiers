use stylus_sdk::{
    alloy_primitives::FixedBytes,
    alloy_sol_types::{sol, SolError},
};

use crate::common::VerificationError;

sol! {
    error WrongVerifierSelector(bytes4 received, bytes4 expected);
}

#[derive(Debug)]
pub enum Sp1Error {
    Common(VerificationError),
    WrongVerifierSelector {
        received: FixedBytes<4>,
        expected: FixedBytes<4>,
    },
}

impl Sp1Error {
    pub fn abi_encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            Sp1Error::Common(e) => e.abi_encode(),
            Sp1Error::WrongVerifierSelector { received, expected } => WrongVerifierSelector {
                received: *received,
                expected: *expected,
            }
            .abi_encode(),
        }
    }
}

impl From<VerificationError> for Sp1Error {
    fn from(error: VerificationError) -> Self {
        Sp1Error::Common(error)
    }
}

impl Sp1Error {
    pub const VERIFICATION_FAILED: Sp1Error = Sp1Error::Common(VerificationError::VerificationFailed);
    pub const INVALID_PROOF_DATA: Sp1Error = Sp1Error::Common(VerificationError::InvalidProofData);
} 