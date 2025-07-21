use stylus_sdk::alloy_primitives::U256;

#[derive(Clone, Copy, Debug)]
pub struct G1Point {
    pub x: U256,
    pub y: U256,
}

#[derive(Clone, Copy, Debug)]
pub struct G2Point {
    /// `x = x_c0 + x_c1·u`
    pub x: [U256; 2],
    /// `y = y_c0 + y_c1·u`
    pub y: [U256; 2],
}

pub struct VerificationKey {
    pub alpha1: G1Point,
    pub beta2: G2Point,
    pub gamma2: G2Point,
    pub delta2: G2Point,
    pub ic: &'static [G1Point],
}

#[derive(Clone, Copy)]
pub enum VMType { Risc0, Sp1 }

// Plonk-specific types
#[derive(Clone, Copy, Debug)]
pub struct PlonkProof {
    /// Wire polynomial commitments [L], [R], [O]
    pub wire_commitments: [G1Point; 3],
    /// Grand product polynomial commitment [Z]
    pub permutation_commitment: G1Point,
    /// Quotient polynomial commitments [H_0], [H_1], [H_2]
    pub quotient_commitments: [G1Point; 3],
    /// Wire polynomial evaluations L(ζ), R(ζ), O(ζ)
    pub wire_evaluations: [U256; 3],
    /// Permutation polynomial evaluations Z(ζω), S_σ1(ζ), S_σ2(ζ)
    pub permutation_evaluations: [U256; 3],
    /// Quotient polynomial evaluation H(ζ)
    pub quotient_evaluation: U256,
    /// KZG opening proof at ζ
    pub opening_proof: G1Point,
    /// KZG opening proof at ζω
    pub opening_proof_at_omega: G1Point,
}

#[derive(Clone, Debug)]
pub struct PlonkVerificationKey {
    /// Size of the evaluation domain
    pub domain_size: u32,
    /// Number of public inputs
    pub num_public_inputs: u32,
    /// Selector polynomial commitments [Q_L], [Q_R], [Q_M], [Q_O], [Q_K]
    pub selector_commitments: [G1Point; 5],
    /// Permutation polynomial commitments [S_σ1], [S_σ2], [S_σ3]
    pub permutation_commitments: [G1Point; 3],
    /// KZG commitment scheme G2 generator
    pub kzg_g2: G2Point,
    /// Omega - primitive root of unity for the domain
    pub omega: U256,
    /// Coset shift for permutation argument
    pub coset_shift: U256,
}

#[derive(Clone, Copy, Debug)]
pub struct PlonkChallenges {
    /// Challenge β for permutation argument
    pub beta: U256,
    /// Challenge γ for permutation argument  
    pub gamma: U256,
    /// Challenge α for quotient polynomial
    pub alpha: U256,
    /// Challenge ζ for evaluation point
    pub zeta: U256,
    /// Challenge v for batch opening
    pub v: U256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_point_creation() {
        let point = G1Point {
            x: U256::from(1u64),
            y: U256::from(2u64),
        };
        assert_eq!(point.x, U256::from(1u64));
        assert_eq!(point.y, U256::from(2u64));
    }

    #[test]
    fn test_g2_point_creation() {
        let point = G2Point {
            x: [U256::from(1u64), U256::from(2u64)],
            y: [U256::from(3u64), U256::from(4u64)],
        };
        assert_eq!(point.x[0], U256::from(1u64));
        assert_eq!(point.x[1], U256::from(2u64));
        assert_eq!(point.y[0], U256::from(3u64));
        assert_eq!(point.y[1], U256::from(4u64));
    }

    #[test]
    fn test_plonk_proof_structure() {
        let proof = PlonkProof {
            wire_commitments: [
                G1Point { x: U256::from(1u64), y: U256::from(2u64) },
                G1Point { x: U256::from(3u64), y: U256::from(4u64) },
                G1Point { x: U256::from(5u64), y: U256::from(6u64) },
            ],
            permutation_commitment: G1Point { x: U256::from(7u64), y: U256::from(8u64) },
            quotient_commitments: [
                G1Point { x: U256::from(9u64), y: U256::from(10u64) },
                G1Point { x: U256::from(11u64), y: U256::from(12u64) },
                G1Point { x: U256::from(13u64), y: U256::from(14u64) },
            ],
            wire_evaluations: [U256::from(15u64), U256::from(16u64), U256::from(17u64)],
            permutation_evaluations: [U256::from(18u64), U256::from(19u64), U256::from(20u64)],
            quotient_evaluation: U256::from(21u64),
            opening_proof: G1Point { x: U256::from(22u64), y: U256::from(23u64) },
            opening_proof_at_omega: G1Point { x: U256::from(24u64), y: U256::from(25u64) },
        };

        assert_eq!(proof.wire_commitments.len(), 3);
        assert_eq!(proof.quotient_commitments.len(), 3);
        assert_eq!(proof.wire_evaluations.len(), 3);
        assert_eq!(proof.permutation_evaluations.len(), 3);
        assert_eq!(proof.quotient_evaluation, U256::from(21u64));
    }

    #[test]
    fn test_plonk_verification_key_structure() {
        let vk = PlonkVerificationKey {
            domain_size: 1024,
            num_public_inputs: 2,
            selector_commitments: [
                G1Point { x: U256::from(1u64), y: U256::from(2u64) },
                G1Point { x: U256::from(3u64), y: U256::from(4u64) },
                G1Point { x: U256::from(5u64), y: U256::from(6u64) },
                G1Point { x: U256::from(7u64), y: U256::from(8u64) },
                G1Point { x: U256::from(9u64), y: U256::from(10u64) },
            ],
            permutation_commitments: [
                G1Point { x: U256::from(11u64), y: U256::from(12u64) },
                G1Point { x: U256::from(13u64), y: U256::from(14u64) },
                G1Point { x: U256::from(15u64), y: U256::from(16u64) },
            ],
            kzg_g2: G2Point {
                x: [U256::from(17u64), U256::from(18u64)],
                y: [U256::from(19u64), U256::from(20u64)],
            },
            omega: U256::from(21u64),
            coset_shift: U256::from(22u64),
        };

        assert_eq!(vk.domain_size, 1024);
        assert_eq!(vk.num_public_inputs, 2);
        assert_eq!(vk.selector_commitments.len(), 5);
        assert_eq!(vk.permutation_commitments.len(), 3);
    }

    #[test]
    fn test_plonk_challenges_structure() {
        let challenges = PlonkChallenges {
            beta: U256::from(1u64),
            gamma: U256::from(2u64),
            alpha: U256::from(3u64),
            zeta: U256::from(4u64),
            v: U256::from(5u64),
        };

        assert_eq!(challenges.beta, U256::from(1u64));
        assert_eq!(challenges.gamma, U256::from(2u64));
        assert_eq!(challenges.alpha, U256::from(3u64));
        assert_eq!(challenges.zeta, U256::from(4u64));
        assert_eq!(challenges.v, U256::from(5u64));
    }

    #[test]
    fn test_vm_type_enum() {
        let risc0_type = VMType::Risc0;
        let sp1_type = VMType::Sp1;
        
        // Test that we can match on the enum variants
        match risc0_type {
            VMType::Risc0 => assert!(true),
            VMType::Sp1 => assert!(false),
        }
        
        match sp1_type {
            VMType::Risc0 => assert!(false),
            VMType::Sp1 => assert!(true),
        }
    }
}