use alloc::{vec, vec::Vec};
use stylus_sdk::{
    alloy_primitives::U256,
    alloy_sol_types::sol,
};
use crate::common::{G1Point, G2Point};

/////////////////////////////////////////////////////////////////
// ABI proof type
/////////////////////////////////////////////////////////////////

sol! {
    struct Sp1PlonkProof {
        uint256[6] wire_commitments;          // l, r, o
        uint256[2] permutation_commitment;    // z
        uint256[6] quotient_commitments;      // h0,h1,h2
        uint256[2] bsb22_commitment;          // 1 BSB22 commitment
        uint256[3] wire_evaluations;          // l, r, o
        uint256[3] permutation_evaluations;   // z(ωζ), s1(ζ), s2(ζ)
        uint256 bsb22_evaluation;             // 1
        uint256 quotient_evaluation;          
        uint256[2] opening_proof;             // batched proof h (at ζ)
        uint256[2] opening_proof_at_omega;    // proof at ωζ
    }
}

/////////////////////////////////////////////////////////////////
// Internal types
/////////////////////////////////////////////////////////////////
#[derive(Clone, Debug)]
pub struct PlonkVerifyingKey {
    pub size: usize,
    pub size_inv: U256,
    pub generator: U256,
    pub nb_public_variables: usize,
    pub coset_shift: U256,
    pub g1: G1Point,
    pub g2: [G2Point; 2],
    pub s: [G1Point; 3],
    pub ql: G1Point,
    pub qr: G1Point,
    pub qm: G1Point,
    pub qo: G1Point,
    pub qk: G1Point,
    pub qcp: Vec<G1Point>,
    pub commitment_constraint_indexes: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct OpeningProof {
    pub h: G1Point,
    pub claimed_value: U256,
}

#[derive(Clone, Debug)]
pub struct BatchOpeningProof {
    pub h: G1Point,
    pub claimed_values: Vec<U256>,
}

#[derive(Clone, Debug)]
pub struct PlonkProof {
    pub lro: [G1Point; 3],
    pub z: G1Point,
    pub h: [G1Point; 3],
    pub bsb22_commitments: Vec<G1Point>,
    pub batched_proof: BatchOpeningProof,
    pub z_shifted_opening: OpeningProof,
}

impl From<Sp1PlonkProof> for PlonkProof {
    fn from(p: Sp1PlonkProof) -> Self {
        let l = G1Point { x: p.wire_commitments[0], y: p.wire_commitments[1] };
        let r = G1Point { x: p.wire_commitments[2], y: p.wire_commitments[3] };
        let o = G1Point { x: p.wire_commitments[4], y: p.wire_commitments[5] };
        let z = G1Point { x: p.permutation_commitment[0], y: p.permutation_commitment[1] };
        let h0 = G1Point { x: p.quotient_commitments[0], y: p.quotient_commitments[1] };
        let h1 = G1Point { x: p.quotient_commitments[2], y: p.quotient_commitments[3] };
        let h2 = G1Point { x: p.quotient_commitments[4], y: p.quotient_commitments[5] };

        let bsb = vec![G1Point { x: p.bsb22_commitment[0], y: p.bsb22_commitment[1] }];

        // claimed_values = l(ζ), r(ζ), o(ζ), s1(ζ), s2(ζ) + bsb22_eval
        let mut claimed = Vec::with_capacity(5 + 1);
        claimed.push(p.wire_evaluations[0]);
        claimed.push(p.wire_evaluations[1]);
        claimed.push(p.wire_evaluations[2]);
        claimed.push(p.permutation_evaluations[1]); // s1
        claimed.push(p.permutation_evaluations[2]); // s2
        claimed.push(p.bsb22_evaluation);

        let batched_proof = BatchOpeningProof {
            h: G1Point { x: p.opening_proof[0], y: p.opening_proof[1] },
            claimed_values: claimed,
        };

        let z_shifted = OpeningProof {
            h: G1Point { x: p.opening_proof_at_omega[0], y: p.opening_proof_at_omega[1] },
            claimed_value: p.permutation_evaluations[0], // z(ωζ)
        };

        PlonkProof {
            lro: [l, r, o],
            z,
            h: [h0, h1, h2],
            bsb22_commitments: bsb,
            batched_proof,
            z_shifted_opening: z_shifted,
        }
    }
}