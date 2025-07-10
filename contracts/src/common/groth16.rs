use alloc::vec::Vec;
use stylus_sdk::{
    alloy_primitives::{uint, Address, U256},
    call::RawCall,
};

use super::types::{G1Point, G2Point, VMType, VerificationKey};

pub const R: U256 = uint!(0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001_U256);
pub const Q: U256 = uint!(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47_U256);

const EC_ADD_BYTES: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];
const EC_MUL_BYTES: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const EC_PAIRING_BYTES: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];

pub struct Groth16Verifier;

impl Groth16Verifier {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_proof_with_key(
        &self,
        vm_type: VMType,
        vk: &VerificationKey,
        a: [U256; 2],
        b: [[U256; 2]; 2],
        c: [U256; 2],
        public_signals: &[U256],
    ) -> bool {
        if public_signals.len() + 1 != vk.ic.len() || public_signals.iter().any(|&x| x >= R) {
            return false;
        }

        let vk_x = match self.compute_vk_x(vk, public_signals) {
            Ok(x) => x,
            Err(_) => return false,
        };

        let proof_a = G1Point { x: a[0], y: a[1] };
        let proof_b = G2Point {
            x: [b[0][0], b[0][1]],
            y: [b[1][0], b[1][1]],
        };
        let proof_c = G1Point { x: c[0], y: c[1] };

        self.verify_pairing(vm_type, &proof_a, &proof_b, &proof_c, &vk_x, vk)
    }

    fn compute_vk_x(&self, vk: &VerificationKey, signals: &[U256]) -> Result<G1Point, ()> {
        let mut vk_x = vk.ic[0];
        for (sig, ic) in signals.iter().zip(&vk.ic[1..]) {
            let mul_result = self.ec_call(&EC_MUL_BYTES, &[ic.x, ic.y, *sig])?;
            vk_x = self.ec_call(&EC_ADD_BYTES, &[vk_x.x, vk_x.y, mul_result.x, mul_result.y])?;
        }
        Ok(vk_x)
    }

    fn ec_call(&self, addr_bytes: &[u8; 20], params: &[U256]) -> Result<G1Point, ()> {
        let calldata: Vec<u8> = params.iter().flat_map(|x| x.to_be_bytes::<32>()).collect();

        unsafe {
            RawCall::new_static()
                .gas(u64::MAX)
                .call(Address::from(*addr_bytes), &calldata)
        }
        .map(|ret| G1Point {
            x: U256::from_be_slice(&ret[0..32]),
            y: U256::from_be_slice(&ret[32..64]),
        })
        .map_err(|_| ())
    }

    fn negate_g1(&self, p: &G1Point) -> G1Point {
        if p.x.is_zero() && p.y.is_zero() {
            *p
        } else {
            G1Point {
                x: p.x,
                y: Q.wrapping_sub(p.y),
            }
        }
    }

    fn verify_pairing(
        &self,
        vm: VMType,
        a: &G1Point,
        b: &G2Point,
        c: &G1Point,
        l: &G1Point,
        vk: &VerificationKey,
    ) -> bool {
        let (g1s, g2s) = match vm {
            VMType::Risc0 => (
                [self.negate_g1(a), vk.alpha1, *l, *c],
                [*b, vk.beta2, vk.gamma2, vk.delta2],
            ),
            VMType::Sp1 => (
                [*a, vk.alpha1, *l, *c],
                [*b, vk.beta2, vk.gamma2, vk.delta2],
            ),
        };

        self.pairing_check(&g1s, &g2s).unwrap_or(false)
    }

    fn pairing_check(&self, g1s: &[G1Point; 4], g2s: &[G2Point; 4]) -> Result<bool, ()> {
        let mut calldata = Vec::with_capacity(768); // 4 * 6 * 32 bytes

        for (g1, g2) in g1s.iter().zip(g2s.iter()) {
            calldata.extend_from_slice(&g1.x.to_be_bytes::<32>());
            calldata.extend_from_slice(&g1.y.to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.x[0].to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.x[1].to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.y[0].to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.y[1].to_be_bytes::<32>());
        }

        unsafe {
            RawCall::new_static()
                .gas(u64::MAX)
                .call(Address::from(EC_PAIRING_BYTES), &calldata)
        }
        .map(|ret| !U256::from_be_slice(&ret[0..32]).is_zero())
        .map_err(|_| ())
    }
}

impl Default for Groth16Verifier {
    fn default() -> Self {
        Self::new()
    }
}
