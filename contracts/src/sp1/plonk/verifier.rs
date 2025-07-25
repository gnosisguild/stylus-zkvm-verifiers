#![allow(dead_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec, vec};
use stylus_sdk::{
    alloy_primitives::{B256, FixedBytes},
    alloy_sol_types::SolType,
    prelude::*,
};

use crate::common::plonk;
use crate::sp1::plonk::{
    config,
    crypto::utils,
    errors::Sp1PlonkError,
    types::{PlonkProof, Sp1PlonkProof},
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

    fn version(&self) -> String {
        String::from(config::VERSION)
    }

    fn verifier_hash(&self) -> B256 {
        config::VERIFIER_HASH
    }

    fn verify_proof(
        &self,
        program_vkey: B256,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        if proof_bytes.len() < 4 {
            return Err(Sp1PlonkError::InvalidProofData.abi_encode());
        }

        let received = FixedBytes::<4>::from_slice(&proof_bytes[..4]);
        let expected = FixedBytes::<4>::from_slice(&config::VERIFIER_HASH.as_slice()[..4]);
        if received != expected {
            return Err(
                Sp1PlonkError::WrongVerifierSelector {
                    received,
                    expected,
                }.abi_encode()
            );
        }

        let proof_data = &proof_bytes[4..];
        let sp1_proof = match <Sp1PlonkProof as SolType>::abi_decode(proof_data, true) {
            Ok(p) => p,
            Err(_) => return Err(Sp1PlonkError::InvalidProofStructure.abi_encode()),
        };

        let proof = PlonkProof::from(sp1_proof);

        let public_inputs = utils::bn254_public_values(&program_vkey.0, &public_values);

        let vk = config::vk::get_verification_key();

        if public_inputs.len() != vk.nb_public_variables {
            return Err(Sp1PlonkError::InvalidPublicInputCount.abi_encode());
        }

        match plonk::verify_plonk_algebraic(&vk, &proof, &public_inputs) {
            Ok(()) => Ok(()),
            Err(_) => Err(Sp1PlonkError::VerificationFailed.abi_encode()),
        }
    }
}