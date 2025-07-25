use alloc::{vec, vec::Vec};
use core::cmp::min;
use stylus_sdk::{
    alloy_primitives::U256,
    call::RawCall,
};

use crate::sp1::plonk::config;
use crate::common::{G1Point, G2Point};

/////////////////////////////////////////////////////////////////
// Math utilities
/////////////////////////////////////////////////////////////////

pub mod math {
    use super::*;

    #[inline(always)]
    pub fn mod_add(a: U256, b: U256, m: U256) -> U256 {
        let (res, overflow) = a.overflowing_add(b);
        if overflow || res >= m { res - m } else { res }
    }

    #[inline(always)]
    pub fn mod_sub(a: U256, b: U256, m: U256) -> U256 {
        if a >= b { a - b } else { m - (b - a) }
    }

    #[inline(always)]
    pub fn mod_mul(a: U256, b: U256, m: U256) -> U256 {
        (a % m * b % m) % m
    }

    pub fn pow_mod(mut base: U256, mut exp: U256, m: U256) -> U256 {
        let mut res = U256::from(1);
        base %= m;
        while !exp.is_zero() {
            if (exp & U256::from(1)) == U256::from(1) {
                res = mod_mul(res, base, m);
            }
            base = mod_mul(base, base, m);
            exp >>= 1;
        }
        res
    }

    pub fn mod_inv(a: U256, m: U256) -> Option<U256> {
        if a.is_zero() { return None; }
        // Fermat: a^(p-2) mod p
        Some(pow_mod(a, m - U256::from(2), m))
    }

    pub fn batch_invert(fr: &mut [U256]) -> Option<Vec<U256>> {
        let n = fr.len();
        if n == 0 { return Some(Vec::new()); }
        let m = config::R_MOD;
        let mut prefix = vec![U256::from(1); n];
        for i in 1..n {
            prefix[i] = mod_mul(prefix[i-1], fr[i-1], m);
        }
        let mut acc = mod_mul(prefix[n-1], fr[n-1], m);
        acc = mod_inv(acc, m)?;
        let mut res = vec![U256::ZERO; n];
        for i in (0..n).rev() {
            res[i] = mod_mul(acc, prefix[i], m);
            acc = mod_mul(acc, fr[i], m);
        }
        Some(res)
    }
}

/////////////////////////////////////////////////////////////////
// SHA256 via precompile
/////////////////////////////////////////////////////////////////

pub mod sha2evm {
    use super::*;

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        // SHA256 precompile (0x02)
        unsafe {
            RawCall::new_static()
                .call(config::SHA2, data)
                .map(|ret| {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&ret[..32]);
                    out
                })
                .unwrap_or([0u8; 32])
        }
    }
}

/////////////////////////////////////////////////////////////////
// Fiat-Shamir transcript
/////////////////////////////////////////////////////////////////

pub mod fs {
    use super::*;

    #[derive(Clone)]
    pub struct Challenge {
        pub position: usize,
        pub bindings: Vec<Vec<u8>>,
        pub value: [u8; 32],
        pub computed: bool,
        pub id: &'static str,
    }

    pub struct Transcript {
        pub ordered: Vec<Challenge>,
        pub last_pos: isize,
    }

    impl Transcript {
        pub fn new(ids: &[&'static str]) -> Self {
            let mut ordered = Vec::with_capacity(ids.len());
            for (pos, id) in ids.iter().enumerate() {
                ordered.push(Challenge {
                    position: pos,
                    bindings: Vec::new(),
                    value: [0u8; 32],
                    computed: false,
                    id,
                });
            }
            Self { ordered, last_pos: -1 }
        }

        pub fn bind(&mut self, id: &'static str, bytes: &[u8]) -> Result<(), ()> {
            let idx = self.idx_of(id)?;
            if self.ordered[idx].computed { return Err(()); }
            self.ordered[idx].bindings.push(bytes.to_vec());
            Ok(())
        }

        pub fn compute(&mut self, id: &'static str) -> Result<[u8; 32], ()> {
            let idx = self.idx_of(id)?;
            if self.ordered[idx].computed {
                return Ok(self.ordered[idx].value);
            }
            if idx as isize != self.last_pos + 1 {
                return Err(()); // out-of-order
            }
            // hash: name || prev_challenge || bindings...
            let mut hasher_input = Vec::new();
            hasher_input.extend_from_slice(id.as_bytes());

            if self.last_pos >= 0 {
                hasher_input.extend_from_slice(&self.ordered[self.last_pos as usize].value);
            }

            for b in &self.ordered[idx].bindings {
                hasher_input.extend_from_slice(b);
            }

            let h = sha2evm::sha256(&hasher_input);

            self.ordered[idx].value = h;
            self.ordered[idx].computed = true;
            self.last_pos = idx as isize;
            Ok(h)
        }

        fn idx_of(&self, id: &'static str) -> Result<usize, ()> {
            for (i, ch) in self.ordered.iter().enumerate() {
                if ch.id == id {
                    return Ok(i);
                }
            }
            Err(())
        }
    }

    pub fn to_fr_mod_r(bytes32: [u8; 32]) -> U256 {
        let x = U256::from_be_slice(&bytes32);
        x % config::R_MOD
    }
}

/////////////////////////////////////////////////////////////////
// BN254 elliptic curve operations via precompiles
/////////////////////////////////////////////////////////////////

pub mod ec {
    use super::*;

    pub fn ec_add(p: &G1Point, q: &G1Point) -> Result<G1Point, ()> {
        let mut input = [0u8; 128];
        p.x.to_be_bytes::<32>().copy_from_slice(&mut input[0..32]);
        p.y.to_be_bytes::<32>().copy_from_slice(&mut input[32..64]);
        q.x.to_be_bytes::<32>().copy_from_slice(&mut input[64..96]);
        q.y.to_be_bytes::<32>().copy_from_slice(&mut input[96..128]);
        let out = unsafe { RawCall::new_static().call(config::EC_ADD, &input) }.map_err(|_| ())?;
        Ok(G1Point {
            x: U256::from_be_slice(&out[0..32]),
            y: U256::from_be_slice(&out[32..64]),
        })
    }

    pub fn ec_mul(p: &G1Point, s: U256) -> Result<G1Point, ()> {
        let mut input = [0u8; 96];
        p.x.to_be_bytes::<32>().copy_from_slice(&mut input[0..32]);
        p.y.to_be_bytes::<32>().copy_from_slice(&mut input[32..64]);
        s.to_be_bytes::<32>().copy_from_slice(&mut input[64..96]);
        let out = unsafe { RawCall::new_static().call(config::EC_MUL, &input) }.map_err(|_| ())?;
        Ok(G1Point {
            x: U256::from_be_slice(&out[0..32]),
            y: U256::from_be_slice(&out[32..64]),
        })
    }

    pub fn g1_neg(p: &G1Point) -> G1Point {
        if p.x.is_zero() && p.y.is_zero() { return *p; }
        G1Point { x: p.x, y: config::P_MOD - p.y }
    }

    pub fn pairing(pairs: &[(G1Point, G2Point)]) -> Result<bool, ()> {
        let mut calldata = Vec::with_capacity(pairs.len() * 192);
        for (g1, g2) in pairs {
            calldata.extend_from_slice(&g1.x.to_be_bytes::<32>());
            calldata.extend_from_slice(&g1.y.to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.x[0].to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.x[1].to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.y[0].to_be_bytes::<32>());
            calldata.extend_from_slice(&g2.y[1].to_be_bytes::<32>());
        }
        let ret = unsafe { RawCall::new_static().call(config::EC_PAIR, &calldata) }.map_err(|_| ())?;
        Ok(!U256::from_be_slice(&ret[0..32]).is_zero())
    }

    pub fn msm(points: &[G1Point], scalars: &[U256]) -> Result<G1Point, ()> {
        let mut acc = G1Point { x: U256::ZERO, y: U256::ZERO };
        for (p, s) in points.iter().zip(scalars.iter()) {
            if s.is_zero() { continue; }
            let ps = ec_mul(p, *s)?;
            acc = ec_add(&acc, &ps)?;
        }
        Ok(acc)
    }
}

/////////////////////////////////////////////////////////////////
// Hash-to-field for BSB22
/////////////////////////////////////////////////////////////////

pub mod hash_to_field {
    use super::*;

    const DST: &[u8] = b"BSB22-Plonk";

    pub fn hash_g1_to_fr(point: &G1Point) -> U256 {
        let msg = {
            let mut v = Vec::with_capacity(64);
            v.extend_from_slice(&point.x.to_be_bytes::<32>());
            v.extend_from_slice(&point.y.to_be_bytes::<32>());
            v
        };
        let pseudo = expand_msg_xmd_sha256(&msg, DST, 48);
        let x = U256::from_be_slice(&pseudo[..32]);
        x % config::R_MOD
    }

    fn expand_msg_xmd_sha256(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        let b_in_bytes = 32;
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        assert!(ell <= 255);

        let mut dst_prime = Vec::with_capacity(dst.len() + 1);
        dst_prime.extend_from_slice(dst);
        dst_prime.push(dst.len() as u8);

        let z_pad = [0u8; 64];
        let mut l_i_b_str = [0u8; 2];
        l_i_b_str[0] = ((len_in_bytes >> 8) & 0xff) as u8;
        l_i_b_str[1] = (len_in_bytes & 0xff) as u8;

        let mut b0_input = Vec::with_capacity(64 + msg.len() + 2 + 1 + dst_prime.len());
        b0_input.extend_from_slice(&z_pad);
        b0_input.extend_from_slice(msg);
        b0_input.extend_from_slice(&l_i_b_str);
        b0_input.push(0);
        b0_input.extend_from_slice(&dst_prime);

        let b0 = sha2evm::sha256(&b0_input);

        let mut bi = Vec::with_capacity(ell);
        let mut b1_input = Vec::with_capacity(32 + 1 + dst_prime.len());
        b1_input.extend_from_slice(&b0);
        b1_input.push(1);
        b1_input.extend_from_slice(&dst_prime);
        let mut last = sha2evm::sha256(&b1_input);
        bi.push(last);

        for i in 2..=ell {
            let mut tmp = [0u8; 32];
            for j in 0..32 {
                tmp[j] = b0[j] ^ last[j];
            }
            let mut bi_input = Vec::with_capacity(32 + 1 + dst_prime.len());
            bi_input.extend_from_slice(&tmp);
            bi_input.push(i as u8);
            bi_input.extend_from_slice(&dst_prime);

            last = sha2evm::sha256(&bi_input);
            bi.push(last);
        }

        let mut out = vec![0u8; len_in_bytes];
        for (i, b) in bi.iter().enumerate() {
            let start = i * b_in_bytes;
            let end = min(start + b_in_bytes, len_in_bytes);
            out[start..end].copy_from_slice(&b[..(end - start)]);
        }
        out
    }
}

/////////////////////////////////////////////////////////////////
// Utility functions
/////////////////////////////////////////////////////////////////

pub mod utils {
    use super::*;

    pub fn hash_public_values(public_values: &[u8]) -> [u8; 32] {
        let mut out = sha2evm::sha256(public_values);
        out[0] &= 0x1F;
        out
    }

    pub fn bn254_public_values(sp1_vkey_hash: &[u8; 32], sp1_public_inputs: &[u8]) -> [U256; 2] {
        let committed_values_digest = hash_public_values(sp1_public_inputs);
        let vkey_hash = U256::from_be_slice(&sp1_vkey_hash[1..]);
        let committed_values_digest = U256::from_be_slice(&committed_values_digest);
        [vkey_hash % config::R_MOD, committed_values_digest % config::R_MOD]
    }

    pub fn g1_to_bytes(p: &G1Point) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&p.x.to_be_bytes::<32>());
        out.extend_from_slice(&p.y.to_be_bytes::<32>());
        out
    }
}