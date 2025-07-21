use sha2::{Digest, Sha256};
use stylus_sdk::{
    alloy_primitives::{B256, U256},
    alloy_sol_types::sol,
};

use crate::sp1::plonk::config;
use crate::common::{groth16::R, types::{PlonkProof, G1Point}};

sol! {
    struct Sp1PlonkProof {
        // Wire commitments [L], [R], [O] - 3 * 2 * 32 = 192 bytes
        uint256[6] wire_commitments;
        // Permutation commitment [Z] - 2 * 32 = 64 bytes  
        uint256[2] permutation_commitment;
        // Quotient commitments [H_0], [H_1], [H_2] - 3 * 2 * 32 = 192 bytes
        uint256[6] quotient_commitments;
        // Wire evaluations L(ζ), R(ζ), O(ζ) - 3 * 32 = 96 bytes
        uint256[3] wire_evaluations;
        // Permutation evaluations Z(ζω), S_σ1(ζ), S_σ2(ζ) - 3 * 32 = 96 bytes
        uint256[3] permutation_evaluations;
        // Quotient evaluation H(ζ) - 32 bytes
        uint256 quotient_evaluation;
        // Opening proof at ζ - 2 * 32 = 64 bytes
        uint256[2] opening_proof;
        // Opening proof at ζω - 2 * 32 = 64 bytes
        uint256[2] opening_proof_at_omega;
    }
}

#[derive(Clone, Debug)]
pub struct Sp1PlonkPublicInputs {
    pub program_vkey: U256,
    pub public_values_digest: U256,
}

impl Sp1PlonkPublicInputs {
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

impl From<Sp1PlonkProof> for PlonkProof {
    fn from(sp1_proof: Sp1PlonkProof) -> Self {
        PlonkProof {
            wire_commitments: [
                G1Point {
                    x: sp1_proof.wire_commitments[0],
                    y: sp1_proof.wire_commitments[1],
                },
                G1Point {
                    x: sp1_proof.wire_commitments[2],
                    y: sp1_proof.wire_commitments[3],
                },
                G1Point {
                    x: sp1_proof.wire_commitments[4],
                    y: sp1_proof.wire_commitments[5],
                },
            ],
            permutation_commitment: G1Point {
                x: sp1_proof.permutation_commitment[0],
                y: sp1_proof.permutation_commitment[1],
            },
            quotient_commitments: [
                G1Point {
                    x: sp1_proof.quotient_commitments[0],
                    y: sp1_proof.quotient_commitments[1],
                },
                G1Point {
                    x: sp1_proof.quotient_commitments[2],
                    y: sp1_proof.quotient_commitments[3],
                },
                G1Point {
                    x: sp1_proof.quotient_commitments[4],
                    y: sp1_proof.quotient_commitments[5],
                },
            ],
            wire_evaluations: sp1_proof.wire_evaluations,
            permutation_evaluations: sp1_proof.permutation_evaluations,
            quotient_evaluation: sp1_proof.quotient_evaluation,
            opening_proof: G1Point {
                x: sp1_proof.opening_proof[0],
                y: sp1_proof.opening_proof[1],
            },
            opening_proof_at_omega: G1Point {
                x: sp1_proof.opening_proof_at_omega[0],
                y: sp1_proof.opening_proof_at_omega[1],
            },
        }
    }
}

pub fn hash_public_values(public_values: &[u8]) -> U256 {
    let hash = Sha256::digest(public_values);
    let hash_u256 = U256::from_be_bytes(hash.into());
    (hash_u256 & config::FIELD_MASK) % R
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_plonk_public_inputs_creation() {
        let program_vkey = B256::from([1u8; 32]);
        let public_values = b"test public values";
        
        let inputs = Sp1PlonkPublicInputs::new(program_vkey, public_values);
        
        assert_eq!(inputs.program_vkey, U256::from_be_bytes(program_vkey.0));
        assert!(inputs.public_values_digest < R);
        
        let array = inputs.to_array();
        assert_eq!(array[0], inputs.program_vkey);
        assert_eq!(array[1], inputs.public_values_digest);
    }

    #[test]
    fn test_hash_public_values() {
        let public_values = b"test data";
        let hash1 = hash_public_values(public_values);
        let hash2 = hash_public_values(public_values);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be in field
        assert!(hash1 < R);
        
        // Different input should produce different hash
        let different_values = b"different test data";
        let hash3 = hash_public_values(different_values);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_public_values_empty() {
        let empty_values = b"";
        let hash = hash_public_values(empty_values);
        assert!(hash < R);
    }

    #[test]
    fn test_sp1_plonk_proof_conversion() {
        let sp1_proof = Sp1PlonkProof {
            wire_commitments: [1, 2, 3, 4, 5, 6].map(U256::from),
            permutation_commitment: [7, 8].map(U256::from),
            quotient_commitments: [9, 10, 11, 12, 13, 14].map(U256::from),
            wire_evaluations: [15, 16, 17].map(U256::from),
            permutation_evaluations: [18, 19, 20].map(U256::from),
            quotient_evaluation: U256::from(21),
            opening_proof: [22, 23].map(U256::from),
            opening_proof_at_omega: [24, 25].map(U256::from),
        };

        let plonk_proof: PlonkProof = sp1_proof.into();

        // Test wire commitments conversion
        assert_eq!(plonk_proof.wire_commitments[0].x, U256::from(1));
        assert_eq!(plonk_proof.wire_commitments[0].y, U256::from(2));
        assert_eq!(plonk_proof.wire_commitments[1].x, U256::from(3));
        assert_eq!(plonk_proof.wire_commitments[1].y, U256::from(4));
        assert_eq!(plonk_proof.wire_commitments[2].x, U256::from(5));
        assert_eq!(plonk_proof.wire_commitments[2].y, U256::from(6));

        // Test permutation commitment conversion
        assert_eq!(plonk_proof.permutation_commitment.x, U256::from(7));
        assert_eq!(plonk_proof.permutation_commitment.y, U256::from(8));

        // Test quotient commitments conversion
        assert_eq!(plonk_proof.quotient_commitments[0].x, U256::from(9));
        assert_eq!(plonk_proof.quotient_commitments[0].y, U256::from(10));
        assert_eq!(plonk_proof.quotient_commitments[1].x, U256::from(11));
        assert_eq!(plonk_proof.quotient_commitments[1].y, U256::from(12));
        assert_eq!(plonk_proof.quotient_commitments[2].x, U256::from(13));
        assert_eq!(plonk_proof.quotient_commitments[2].y, U256::from(14));

        // Test evaluations
        assert_eq!(plonk_proof.wire_evaluations, [15, 16, 17].map(U256::from));
        assert_eq!(plonk_proof.permutation_evaluations, [18, 19, 20].map(U256::from));
        assert_eq!(plonk_proof.quotient_evaluation, U256::from(21));

        // Test opening proofs conversion
        assert_eq!(plonk_proof.opening_proof.x, U256::from(22));
        assert_eq!(plonk_proof.opening_proof.y, U256::from(23));
        assert_eq!(plonk_proof.opening_proof_at_omega.x, U256::from(24));
        assert_eq!(plonk_proof.opening_proof_at_omega.y, U256::from(25));
    }

    #[test]
    fn test_sp1_plonk_public_inputs_debug() {
        let program_vkey = B256::from([1u8; 32]);
        let public_values = b"test";
        let inputs = Sp1PlonkPublicInputs::new(program_vkey, public_values);
        
        let debug_str = format!("{:?}", inputs);
        assert!(debug_str.contains("Sp1PlonkPublicInputs"));
        assert!(debug_str.contains("program_vkey"));
        assert!(debug_str.contains("public_values_digest"));
    }

    #[test]
    fn test_sp1_plonk_public_inputs_clone() {
        let program_vkey = B256::from([1u8; 32]);
        let public_values = b"test";
        let inputs = Sp1PlonkPublicInputs::new(program_vkey, public_values);
        
        let cloned_inputs = inputs.clone();
        assert_eq!(inputs.program_vkey, cloned_inputs.program_vkey);
        assert_eq!(inputs.public_values_digest, cloned_inputs.public_values_digest);
    }
}