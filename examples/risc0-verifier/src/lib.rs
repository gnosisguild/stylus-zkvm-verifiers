#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use stylus_sdk::{
    alloy_primitives::{FixedBytes, B256, B128},
    prelude::*,
};
use stylus_zkvm_verifiers::risc0::{RiscZeroVerifier, IRiscZeroVerifier};

#[entrypoint]
#[storage]
struct RiscZeroVerifierExample {
    verifier: RiscZeroVerifier,
}

/// Example implementation of a RISC Zero verifier contract
#[public]
#[implements(IRiscZeroVerifier<Error = Vec<u8>>)]
impl RiscZeroVerifierExample {}

/// Trait implementation for the RISC Zero verifier
#[public]
impl IRiscZeroVerifier for RiscZeroVerifierExample {
    type Error = Vec<u8>;

    /// Initialize the verifier with RISC Zero parameters
    fn initialize(
        &mut self,
        control_root: B256,
        bn254_control_id: B256,
        selector: FixedBytes<4>,
    ) -> Result<(), Self::Error> {
        self.verifier.initialize(control_root, bn254_control_id, selector)
    }

    /// Verify a RISC Zero proof
    fn verify(
        &self,
        seal: Vec<u8>,
        image_id: B256,
        journal_digest: B256,
    ) -> Result<bool, Self::Error> {
        self.verifier.verify(seal, image_id, journal_digest)
    }

    /// Verify proof integrity directly
    fn verify_integrity(
        &self,
        receipt_seal: Vec<u8>,
        receipt_claim_digest: B256,
    ) -> Result<bool, Self::Error> {
        self.verifier.verify_integrity(receipt_seal, receipt_claim_digest)
    }

    fn get_selector(&self) -> FixedBytes<4> {
        self.verifier.get_selector()
    }

    fn get_control_root(&self) -> (B128, B128) {
        self.verifier.get_control_root()
    }

    fn get_bn254_control_id(&self) -> B256 {
        self.verifier.get_bn254_control_id()
    }

    fn get_verifier_key_digest(&self) -> B256 {
        self.verifier.get_verifier_key_digest()
    }

    fn is_initialized(&self) -> bool {
        self.verifier.is_initialized()
    }
} 