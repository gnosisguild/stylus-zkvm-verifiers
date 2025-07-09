use alloc::{vec, vec::Vec, string::String};
use stylus_sdk::{
    alloy_primitives::{FixedBytes, B256},
    alloy_sol_types::SolType,
    prelude::*,
};

use crate::common::Groth16Verifier;
use crate::sp1::{
    config,
    crypto::vk,
    errors::Sp1Error,
    types::{Sp1Proof, Sp1PublicInputs},
};

pub trait ISp1Verifier {
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
    pub struct Sp1Verifier {}
}

#[public]
impl ISp1Verifier for Sp1Verifier {
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

impl Sp1Verifier {
    fn verify_proof_internal(
        &self,
        program_vkey: B256,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        if proof_bytes.len() < 4 {
            return Err(Sp1Error::INVALID_PROOF_DATA.abi_encode());
        }

        let received_selector = FixedBytes::<4>::from_slice(&proof_bytes[..4]);
        let expected_selector = config::get_verifier_selector();
        
        if received_selector != expected_selector {
            return Err(Sp1Error::WrongVerifierSelector {
                received: received_selector,
                expected: expected_selector,
            }.abi_encode());
        }

        let proof_data = &proof_bytes[4..];
        let sp1_proof = match <Sp1Proof as SolType>::abi_decode(proof_data, true) {
            Ok(proof) => proof,
            Err(_) => return Err(Sp1Error::INVALID_PROOF_DATA.abi_encode()),
        };

        let public_inputs = Sp1PublicInputs::new(program_vkey, &public_values);
        let public_signals = public_inputs.to_array();

        let proof_array = sp1_proof.proof;
        let a = [proof_array[0], proof_array[1]];
        let b = [[proof_array[2], proof_array[3]], [proof_array[4], proof_array[5]]];
        let c = [proof_array[6], proof_array[7]];

        let verification_key = vk::get_verification_key();
        let verified = Groth16Verifier::new().verify_proof_with_key(
            &verification_key,
            a,
            b,
            c,
            &public_signals,
        );

        if !verified {
            return Err(Sp1Error::VERIFICATION_FAILED.abi_encode());
        }

        Ok(())
    }
} 