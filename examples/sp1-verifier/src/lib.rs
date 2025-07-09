#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

use alloc::{vec, vec::Vec, string::String};
use stylus_sdk::{
    alloy_primitives::B256,
    prelude::*,
};
use stylus_zkvm_verifiers::sp1::{Sp1Verifier, ISp1Verifier};

#[entrypoint]
#[storage]
struct Sp1VerifierExample {
    verifier: Sp1Verifier,
}

#[public]
#[implements(ISp1Verifier<Error = Vec<u8>>)]
impl Sp1VerifierExample {}

#[public]
impl ISp1Verifier for Sp1VerifierExample {
    type Error = Vec<u8>;

    fn verify_proof(
        &self,
        program_vkey: B256,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.verifier.verify_proof(program_vkey, public_values, proof_bytes)
    }

    fn verifier_hash(&self) -> B256 {
        self.verifier.verifier_hash()
    }

    fn version(&self) -> String {
        self.verifier.version()
    }
}

#[cfg(feature = "export-abi")]
pub fn print_from_args() {
    stylus_sdk::abi::export_abi::<Sp1VerifierExample>();
} 