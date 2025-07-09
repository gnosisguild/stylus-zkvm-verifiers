use alloc::{vec, vec::Vec};
use alloy_primitives::B128;
use sha2::{Digest, Sha256};
use stylus_sdk::{
    alloy_primitives::{FixedBytes, B256, U256},
    alloy_sol_types::{SolType, SolValue},
    prelude::*,
};

use crate::common::Groth16Verifier;
use crate::risc0::{
    config::tags,
    crypto::{digest_utils, vk},
    errors::RiscZeroError,
    types::{ReceiptClaim, Seal},
};

pub trait IRiscZeroVerifier {
    type Error;

    fn initialize(&mut self, control_root: B256, bn254_control_id: B256)
        -> Result<(), Self::Error>;

    fn verify(
        &self,
        seal: Vec<u8>,
        image_id: B256,
        journal_digest: B256,
    ) -> Result<bool, Self::Error>;

    fn verify_integrity(
        &self,
        receipt_seal: Vec<u8>,
        receipt_claim_digest: B256,
    ) -> Result<bool, Self::Error>;

    fn get_selector(&self) -> FixedBytes<4>;
    fn get_control_root(&self) -> (B128, B128);
    fn get_bn254_control_id(&self) -> B256;
    fn get_verifier_key_digest(&self) -> B256;
    fn is_initialized(&self) -> bool;
}

sol_storage! {
    pub struct RiscZeroVerifier {
        bytes16 control_root_0;
        bytes16 control_root_1;
        bytes32 bn254_control_id;
        bytes4 selector;
        bool initialized;
    }
}

#[public]
impl IRiscZeroVerifier for RiscZeroVerifier {
    type Error = Vec<u8>;

    fn initialize(
        &mut self,
        control_root: B256,
        bn254_control_id: B256,
    ) -> Result<(), Self::Error> {
        if self.initialized.get() {
            return Err(RiscZeroError::ALREADY_INITIALIZED.abi_encode());
        }

        let (ctrl_lo, ctrl_hi) = digest_utils::split_digest(control_root);
        self.control_root_0.set(B128::from(ctrl_lo));
        self.control_root_1.set(B128::from(ctrl_hi));
        self.bn254_control_id.set(bn254_control_id);
        let selector = Self::calculate_selector(control_root, bn254_control_id);
        self.selector.set(selector);
        self.initialized.set(true);

        Ok(())
    }

    fn verify(
        &self,
        seal: Vec<u8>,
        image_id: B256,
        journal_digest: B256,
    ) -> Result<bool, Self::Error> {
        if !self.initialized.get() {
            return Err(RiscZeroError::INVALID_INITIALIZATION.abi_encode());
        }

        let claim = ReceiptClaim::ok(image_id, journal_digest);
        let claim_digest = claim.digest();

        self.verify_integrity_internal(seal, claim_digest)
    }

    fn verify_integrity(
        &self,
        receipt_seal: Vec<u8>,
        receipt_claim_digest: B256,
    ) -> Result<bool, Self::Error> {
        if !self.initialized.get() {
            return Err(RiscZeroError::INVALID_INITIALIZATION.abi_encode());
        }

        self.verify_integrity_internal(receipt_seal, receipt_claim_digest)
    }

    fn get_selector(&self) -> FixedBytes<4> {
        self.selector.get()
    }

    fn get_control_root(&self) -> (B128, B128) {
        (self.control_root_0.get(), self.control_root_1.get())
    }

    fn get_bn254_control_id(&self) -> B256 {
        self.bn254_control_id.get()
    }

    fn get_verifier_key_digest(&self) -> B256 {
        digest_utils::compute_verifier_key_digest()
    }

    fn is_initialized(&self) -> bool {
        self.initialized.get()
    }
}

impl RiscZeroVerifier {
    fn calculate_selector(control_root: B256, bn254_control_id: B256) -> FixedBytes<4> {
        let tag_digest = B256::from_slice(&Sha256::digest(
            tags::GROTH16_RECEIPT_VERIFIER_PARAMETERS_TAG,
        ));

        let packed_data = (
            tag_digest,
            control_root,
            digest_utils::reverse_byte_order_uint256(bn254_control_id),
            digest_utils::compute_verifier_key_digest(),
            3u16 << 8,
        )
            .abi_encode_packed();

        let hash = Sha256::digest(&packed_data);
        FixedBytes::<4>::from_slice(&hash[..4])
    }

    fn verify_integrity_internal(
        &self,
        seal: Vec<u8>,
        claim_digest: B256,
    ) -> Result<bool, Vec<u8>> {
        if seal.len() < 4 {
            return Err(RiscZeroError::INVALID_PROOF_DATA.abi_encode());
        }

        let received_selector = FixedBytes::<4>::from_slice(&seal[..4]);
        let expected_selector = self.selector.get();

        if received_selector != expected_selector {
            return Err(RiscZeroError::SelectorMismatch {
                received: received_selector,
                expected: expected_selector,
            }
            .abi_encode());
        }

        let proof_data = &seal[4..];
        let decoded_seal = match <Seal as SolType>::abi_decode(proof_data, true) {
            Ok(seal) => seal,
            Err(_) => return Err(RiscZeroError::INVALID_PROOF_DATA.abi_encode()),
        };

        let (claim_lo, claim_hi) = digest_utils::split_digest(claim_digest);
        let public_signals = [
            U256::from_be_slice(self.control_root_0.get().as_slice()),
            U256::from_be_slice(self.control_root_1.get().as_slice()),
            U256::from_be_slice(&claim_lo),
            U256::from_be_slice(&claim_hi),
            U256::from_be_slice(self.bn254_control_id.get().as_slice()),
        ];

        let verification_key = vk::get_verification_key();
        let verified = Groth16Verifier::new().verify_proof_with_key(
            &verification_key,
            decoded_seal.a,
            decoded_seal.b,
            decoded_seal.c,
            &public_signals,
        );

        if !verified {
            return Err(RiscZeroError::VERIFICATION_FAILED.abi_encode());
        }

        Ok(true)
    }
}
