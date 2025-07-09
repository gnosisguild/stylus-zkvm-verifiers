/*!
Generic Groth16 proof verification for different ZKP systems.
*/

use alloc::vec::Vec;
use stylus_sdk::{
    alloy_primitives::{uint, Address, U256},
    call::RawCall,
};

const R: U256 = uint!(0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001_U256);
const Q: U256 = uint!(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47_U256);

#[derive(Clone, Copy)]
pub struct G1Point {
    pub x: U256,
    pub y: U256,
}

#[derive(Clone, Copy)]
pub struct G2Point {
    /// `x = x_c0 + x_c1·u`
    pub x: [U256; 2],
    /// `y = y_c0 + y_c1·u`
    pub y: [U256; 2],
}

/// Groth16 verification key
pub struct VerificationKey {
    pub alpha1: G1Point,
    pub beta2: G2Point,
    pub gamma2: G2Point,
    pub delta2: G2Point,
    pub ic: &'static [G1Point],
}

/// Generic Groth16 verifier that works with any verification key
pub struct Groth16Verifier;

impl Groth16Verifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify a Groth16 proof with the given verification key
    pub fn verify_proof_with_key(
        &self,
        vk: &VerificationKey,
        a: [U256; 2],
        b: [[U256; 2]; 2],
        c: [U256; 2],
        public_signals: &[U256],
    ) -> bool {
        // Ensure we have the right number of public signals
        if public_signals.len() + 1 != vk.ic.len() {
            return false;
        }

        // Check that all public signals are within the field
        if public_signals.iter().any(|&x| x >= R) {
            return false;
        }

        let mut vk_x = vk.ic[0];
        for (sig, ic) in public_signals.iter().zip(&vk.ic[1..]) {
            if let Ok(t) = self
                .scalar_mul(ic, *sig)
                .and_then(|p| self.point_add(&vk_x, &p))
            {
                vk_x = t;
            } else {
                return false;
            }
        }

        let proof_a = G1Point { x: a[0], y: a[1] };
        let proof_b = G2Point {
            x: [b[0][0], b[0][1]],
            y: [b[1][0], b[1][1]],
        };
        let proof_c = G1Point { x: c[0], y: c[1] };

        match self.pairing_check(
            &self.negate(&proof_a),
            &proof_b,
            &vk.alpha1,
            &vk.beta2,
            &vk_x,
            &vk.gamma2,
            &proof_c,
            &vk.delta2,
        ) {
            Ok(ok) => ok,
            Err(_) => false,
        }
    }

    fn negate(&self, p: &G1Point) -> G1Point {
        if p.x.is_zero() && p.y.is_zero() {
            return *p;
        }
        G1Point {
            x: p.x,
            y: Q - (p.y % Q),
        }
    }

    fn point_add(&self, p1: &G1Point, p2: &G1Point) -> Result<G1Point, Vec<u8>> {
        let calldata = [p1.x, p1.y, p2.x, p2.y]
            .into_iter()
            .flat_map(to_bytes)
            .collect::<Vec<u8>>();

        unsafe {
            RawCall::new_static().gas(u64::MAX).call(
                Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6]),
                &calldata,
            )
        }
        .map(|ret| G1Point {
            x: U256::from_be_slice(&ret[0..32]),
            y: U256::from_be_slice(&ret[32..64]),
        })
        .map_err(|_| b"point_add failed".to_vec())
    }

    fn scalar_mul(&self, p: &G1Point, s: U256) -> Result<G1Point, Vec<u8>> {
        let calldata = [p.x, p.y, s]
            .into_iter()
            .flat_map(to_bytes)
            .collect::<Vec<u8>>();

        unsafe {
            RawCall::new_static().gas(u64::MAX).call(
                Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]),
                &calldata,
            )
        }
        .map(|ret| G1Point {
            x: U256::from_be_slice(&ret[0..32]),
            y: U256::from_be_slice(&ret[32..64]),
        })
        .map_err(|_| b"scalar_mul failed".to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    fn pairing_check(
        &self,
        a1: &G1Point,
        a2: &G2Point,
        b1: &G1Point,
        b2: &G2Point,
        c1: &G1Point,
        c2: &G2Point,
        d1: &G1Point,
        d2: &G2Point,
    ) -> Result<bool, Vec<u8>> {
        let calldata = [
            a1.x, a1.y, a2.x[1], a2.x[0], a2.y[1], a2.y[0], b1.x, b1.y, b2.x[1], b2.x[0],
            b2.y[1], b2.y[0], c1.x, c1.y, c2.x[1], c2.x[0], c2.y[1], c2.y[0], d1.x, d1.y,
            d2.x[1], d2.x[0], d2.y[1], d2.y[0],
        ]
        .into_iter()
        .flat_map(to_bytes)
        .collect::<Vec<u8>>();

        unsafe {
            RawCall::new_static().gas(u64::MAX).call(
                Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]),
                &calldata,
            )
        }
        .map(|ret| !ret[31] != 0)
        .map_err(|_| b"pairing_check failed".to_vec())
    }
}

fn to_bytes(x: U256) -> [u8; 32] {
    x.to_be_bytes()
}

impl Default for Groth16Verifier {
    fn default() -> Self {
        Self::new()
    }
} 