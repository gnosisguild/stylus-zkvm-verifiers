use sha2::{Digest, Sha256};
use stylus_sdk::{
    alloy_primitives::{B256, U256},
    alloy_sol_types::sol,
};

use crate::common::groth16::R;
sol! {
    struct Sp1Proof {
        uint256[8] proof;
    }
}

#[derive(Clone, Debug)]
pub struct Sp1PublicInputs {
    pub program_vkey: U256,
    pub public_values_digest: U256,
}

impl Sp1PublicInputs {
    pub fn new(program_vkey: B256, public_values: &[u8]) -> Self {
        Self {
            program_vkey: U256::from_be_bytes(program_vkey.0),
            public_values_digest: hash_public_values(public_values),
        }
    }

    pub fn to_array(&self) -> [U256; 2] {
        [self.program_vkey, self.public_values_digest]
    }
}

pub fn hash_public_values(public_values: &[u8]) -> U256 {
    let mut hash = Sha256::digest(public_values);
    hash[0] &= 0x1F;
    let hash_u256 = U256::from_be_bytes(hash.into());
    hash_u256 % R
} 