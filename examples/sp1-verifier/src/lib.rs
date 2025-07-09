/*!
SP1 Verifier Example Contract

TODO: Complete SP1 verifier implementation
*/

#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use stylus_sdk::{alloy_primitives::B256, prelude::*, ArbResult};
use stylus_zkp_verifiers::sp1::Sp1Config;

/// SP1 Verifier Contract
/// 
/// TODO: Replace mock with full SP1 implementation
#[derive(SolidityError)]
#[sol(name = "SP1Verifier")]
pub struct Sp1Verifier {
    config: Sp1Config,
}

impl Default for Sp1Verifier {
    fn default() -> Self {
        Self {
            config: Sp1Config::default(),
        }
    }
}

#[public]
impl Sp1Verifier {
    /// Initialize the SP1 verifier
    /// 
    /// TODO: Add SP1 verification key validation
    pub fn initialize(&mut self, verification_key_hash: B256) -> ArbResult {
        self.config.initialize(verification_key_hash)
    }

    /// Verify an SP1 proof (MOCK IMPLEMENTATION)
    /// 
    /// TODO: Replace with actual SP1 proof verification
    pub fn verify_proof(
        &self,
        _proof_data: Vec<u8>,
        _program_id: B256,
        _public_input_hash: B256,
    ) -> bool {
        // TODO: Implement SP1 verification
        false
    }

    /// Check if verifier is initialized
    pub fn is_initialized(&self) -> bool {
        self.config.is_initialized()
    }

    /// Get verification key hash
    pub fn get_verification_key_hash(&self) -> B256 {
        self.config.get_verification_key_hash()
    }
}

/// Program entrypoint for ABI export
#[cfg(feature = "export-abi")]
fn main() {
    Sp1Verifier::print_from_args();
} 