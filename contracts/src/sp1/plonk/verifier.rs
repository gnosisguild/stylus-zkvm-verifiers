use alloc::{string::String, vec, vec::Vec};
use stylus_sdk::{
    alloy_primitives::{FixedBytes, B256},
    alloy_sol_types::SolType,
    prelude::*,
};

use crate::common::PlonkVerifier;
use crate::sp1::plonk::{
    config,
    crypto,
    errors::Sp1PlonkError,
    types::{Sp1PlonkProof, Sp1PlonkPublicInputs},
};

pub trait ISp1PlonkVerifier {
    type Error;

    fn verify_proof(
        &self,
        program_vkey: B256,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Result<(), Self::Error>;
    
    fn verifier_hash(&self) -> B256;

    fn version(&self) -> String;
}

sol_storage! {
    pub struct Sp1PlonkVerifier {}
}

#[public]
impl ISp1PlonkVerifier for Sp1PlonkVerifier {
    type Error = Vec<u8>;

    fn verify_proof(
        &self,
        program_vkey: B256,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.verify_proof_internal(program_vkey, public_values, proof_bytes)
    }

    fn verifier_hash(&self) -> B256 {
        config::VERIFIER_HASH
    }

    fn version(&self) -> String {
        String::from(config::VERSION)
    }
}

impl Sp1PlonkVerifier {
    fn verify_proof_internal(
        &self,
        program_vkey: B256,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        // Validate proof length
        if proof_bytes.len() < 4 {
            return Err(Sp1PlonkError::INVALID_PROOF_DATA.abi_encode());
        }

        // Check verifier selector
        let received_selector = FixedBytes::<4>::from_slice(&proof_bytes[..4]);
        let expected_selector = config::get_verifier_selector();

        if received_selector != expected_selector {
            return Err(Sp1PlonkError::WrongVerifierSelector {
                received: received_selector,
                expected: expected_selector,
            }
            .abi_encode());
        }

        // Parse proof data
        let proof_data = &proof_bytes[4..];
        let sp1_proof = match <Sp1PlonkProof as SolType>::abi_decode(proof_data, true) {
            Ok(proof) => proof,
            Err(_) => return Err(Sp1PlonkError::InvalidProofStructure.abi_encode()),
        };

        // Convert to internal proof format
        let plonk_proof = sp1_proof.into();

        // Prepare public inputs
        let public_inputs = Sp1PlonkPublicInputs::new(program_vkey, &public_values);
        let public_signals = public_inputs.to_array();

        // Get verification key
        let verification_key = crypto::get_verification_key();

        // Validate verification key
        if !crypto::validate_verification_key(&verification_key) {
            return Err(Sp1PlonkError::INVALID_INITIALIZATION.abi_encode());
        }

        // Perform Plonk verification
        let verifier = PlonkVerifier::new();
        let verified = verifier.verify_proof_with_key(
            &verification_key,
            &plonk_proof,
            &public_signals,
        );

        if !verified {
            return Err(Sp1PlonkError::VERIFICATION_FAILED.abi_encode());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stylus_sdk::alloy_primitives::U256;

    fn create_dummy_sp1_plonk_proof() -> Sp1PlonkProof {
        Sp1PlonkProof {
            wire_commitments: [1, 2, 3, 4, 5, 6].map(U256::from),
            permutation_commitment: [7, 8].map(U256::from),
            quotient_commitments: [9, 10, 11, 12, 13, 14].map(U256::from),
            wire_evaluations: [15, 16, 17].map(U256::from),
            permutation_evaluations: [18, 19, 20].map(U256::from),
            quotient_evaluation: U256::from(21),
            opening_proof: [22, 23].map(U256::from),
            opening_proof_at_omega: [24, 25].map(U256::from),
        }
    }

    #[test]
    fn test_verifier_metadata() {
        let verifier = Sp1PlonkVerifier {};
        
        assert_eq!(verifier.verifier_hash(), config::VERIFIER_HASH);
        assert_eq!(verifier.version(), config::VERSION);
    }

    #[test]
    fn test_verify_proof_invalid_length() {
        let verifier = Sp1PlonkVerifier {};
        let program_vkey = B256::from([1u8; 32]);
        let public_values = vec![1, 2, 3, 4];
        let short_proof = vec![1, 2, 3]; // Too short

        let result = verifier.verify_proof_internal(program_vkey, public_values, short_proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_proof_wrong_selector() {
        let verifier = Sp1PlonkVerifier {};
        let program_vkey = B256::from([1u8; 32]);
        let public_values = vec![1, 2, 3, 4];
        
        // Create proof with wrong selector
        let mut proof_bytes = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Wrong selector
        proof_bytes.extend(vec![0u8; 100]); // Dummy proof data

        let result = verifier.verify_proof_internal(program_vkey, public_values, proof_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_proof_invalid_proof_data() {
        let verifier = Sp1PlonkVerifier {};
        let program_vkey = B256::from([1u8; 32]);
        let public_values = vec![1, 2, 3, 4];
        
        // Create proof with correct selector but invalid data
        let selector = config::get_verifier_selector();
        let mut proof_bytes = selector.to_vec();
        proof_bytes.extend(vec![0xFF; 10]); // Invalid proof data (too short)

        let result = verifier.verify_proof_internal(program_vkey, public_values, proof_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_sp1_plonk_public_inputs_processing() {
        let program_vkey = B256::from([1u8; 32]);
        let public_values = b"test public values";
        
        let inputs = Sp1PlonkPublicInputs::new(program_vkey, public_values);
        let array = inputs.to_array();
        
        assert_eq!(array.len(), 2);
        assert_eq!(array[0], U256::from_be_bytes(program_vkey.0));
        assert!(array[1] > U256::ZERO); // Should have non-zero hash
    }

    #[test]
    fn test_verification_key_validation() {
        let vk = crypto::get_verification_key();
        assert!(crypto::validate_verification_key(&vk));
        
        // Test that we can get the verification key without panicking
        assert_eq!(vk.num_public_inputs, 2);
        assert!(vk.domain_size > 0);
        assert!(!vk.omega.is_zero());
    }

    #[test]
    fn test_proof_conversion() {
        let sp1_proof = create_dummy_sp1_plonk_proof();
        let plonk_proof = sp1_proof.into();
        
        // Verify conversion worked correctly
        assert_eq!(plonk_proof.wire_commitments[0].x, U256::from(1));
        assert_eq!(plonk_proof.wire_commitments[0].y, U256::from(2));
        assert_eq!(plonk_proof.quotient_evaluation, U256::from(21));
    }

    #[test]
    fn test_error_encoding() {
        // Test that errors can be encoded without panicking
        let error = Sp1PlonkError::VERIFICATION_FAILED;
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());

        let error = Sp1PlonkError::InvalidProofStructure;
        let encoded = error.abi_encode();
        assert!(!encoded.is_empty());
    }
}