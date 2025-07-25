use alloc::vec::Vec;
use alloc::vec;
use stylus_sdk::alloy_primitives::U256;

use crate::sp1::plonk::{
    config,
    crypto::{ec, fs, hash_to_field, math, utils},
    types::{BatchOpeningProof, OpeningProof, PlonkProof, PlonkVerifyingKey},
};
use crate::common::G1Point;

const GAMMA: &str = "gamma";
const BETA: &str = "beta";
const ALPHA: &str = "alpha";
const ZETA: &str = "zeta";
const U: &str = "u";

pub fn verify_plonk_algebraic(
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof,
    public_inputs: &[U256],
) -> Result<(), ()> {
    if proof.bsb22_commitments.len() != vk.qcp.len() {
        return Err(());
    }
    if public_inputs.len() != vk.nb_public_variables {
        return Err(());
    }

    // Initialize transcript
    let mut tr = fs::Transcript::new(&[GAMMA, BETA, ALPHA, ZETA, U]);

    // Bind public data for gamma
    bind_public_data(&mut tr, vk, public_inputs)?;

    // Generate gamma challenge
    bind_points(&mut tr, GAMMA, &[proof.lro[0], proof.lro[1], proof.lro[2]])?;
    let gamma = fs::to_fr_mod_r(tr.compute(GAMMA)?);

    // Generate beta challenge
    let beta = fs::to_fr_mod_r(tr.compute(BETA)?);

    // Generate alpha challenge
    let mut alpha_deps = Vec::with_capacity(proof.bsb22_commitments.len() + 1);
    alpha_deps.extend_from_slice(&proof.bsb22_commitments);
    alpha_deps.push(proof.z);
    bind_points(&mut tr, ALPHA, &alpha_deps)?;
    let alpha = fs::to_fr_mod_r(tr.compute(ALPHA)?);

    // Generate zeta challenge
    bind_points(&mut tr, ZETA, &proof.h)?;
    let zeta = fs::to_fr_mod_r(tr.compute(ZETA)?);

    // Compute zh(zeta) = zeta^n - 1
    let n_u = U256::from(vk.size as u64);
    let zeta_power_n = math::pow_mod(zeta, n_u, config::R_MOD);
    let one = U256::from(1);
    let zh_zeta = math::mod_sub(zeta_power_n, one, config::R_MOD);

    // Compute L1(zeta)
    let zeta_minus_one = math::mod_sub(zeta, one, config::R_MOD);
    let inv_zm1 = math::mod_inv(zeta_minus_one, config::R_MOD).ok_or(())?;
    let mut lagrange_one = math::mod_mul(zh_zeta, inv_zm1, config::R_MOD);
    lagrange_one = math::mod_mul(lagrange_one, vk.size_inv, config::R_MOD);

    // Compute ∑ L_i(zeta)*w_i (public input contribution)
    let mut pi = U256::ZERO;
    let mut accw = U256::from(1);
    let mut dens = Vec::with_capacity(public_inputs.len());
    for _ in 0..public_inputs.len() {
        let tmp = math::mod_sub(zeta, accw, config::R_MOD);
        dens.push(tmp);
        accw = math::mod_mul(accw, vk.generator, config::R_MOD);
    }
    let inv_dens = math::batch_invert(&mut dens.clone()).ok_or(())?;
    accw = U256::from(1);
    for (i, w) in public_inputs.iter().enumerate() {
        let mut li = zh_zeta;
        li = math::mod_mul(li, inv_dens[i], config::R_MOD);
        li = math::mod_mul(li, vk.size_inv, config::R_MOD);
        li = math::mod_mul(li, accw, config::R_MOD);
        li = math::mod_mul(li, *w, config::R_MOD);
        accw = math::mod_mul(accw, vk.generator, config::R_MOD);
        pi = math::mod_add(pi, li, config::R_MOD);
    }

    // Process BSB22 commitments (hash_to_field contributions)
    for (idx, bsb) in proof.bsb22_commitments.iter().enumerate() {
        let hashed = hash_to_field::hash_g1_to_fr(bsb);

        let exp = U256::from((vk.nb_public_variables + vk.commitment_constraint_indexes[idx]) as u64);
        let w_pow_i = math::pow_mod(vk.generator, exp, config::R_MOD);
        let den = math::mod_sub(zeta, w_pow_i, config::R_MOD);
        let inv = math::mod_inv(den, config::R_MOD).ok_or(())?;

        let mut lagrange = zh_zeta;
        lagrange = math::mod_mul(lagrange, w_pow_i, config::R_MOD);
        lagrange = math::mod_mul(lagrange, inv, config::R_MOD);
        lagrange = math::mod_mul(lagrange, vk.size_inv, config::R_MOD);

        let contrib = math::mod_mul(lagrange, hashed, config::R_MOD);
        pi = math::mod_add(pi, contrib, config::R_MOD);
    }

    // Extract claimed values from proof
    let l = proof.batched_proof.claimed_values[0];
    let r = proof.batched_proof.claimed_values[1];
    let o = proof.batched_proof.claimed_values[2];
    let s1 = proof.batched_proof.claimed_values[3];
    let s2 = proof.batched_proof.claimed_values[4];
    let zu = proof.z_shifted_opening.claimed_value;

    // Compute alpha^2 * L1(zeta)
    let mut alpha2_l1 = math::mod_mul(alpha, alpha, config::R_MOD);
    alpha2_l1 = math::mod_mul(alpha2_l1, lagrange_one, config::R_MOD);

    // Compute constant linearization term
    let mut t1 = math::mod_add(math::mod_mul(beta, s1, config::R_MOD), l, config::R_MOD);
    t1 = math::mod_add(t1, gamma, config::R_MOD);

    let mut t2 = math::mod_add(math::mod_mul(beta, s2, config::R_MOD), r, config::R_MOD);
    t2 = math::mod_add(t2, gamma, config::R_MOD);

    let t3 = math::mod_add(o, gamma, config::R_MOD);

    let mut const_lin = math::mod_mul(t1, t2, config::R_MOD);
    const_lin = math::mod_mul(const_lin, t3, config::R_MOD);
    const_lin = math::mod_mul(const_lin, alpha, config::R_MOD);
    const_lin = math::mod_mul(const_lin, zu, config::R_MOD);

    const_lin = math::mod_sub(const_lin, alpha2_l1, config::R_MOD);
    const_lin = math::mod_add(const_lin, pi, config::R_MOD);
    const_lin = math::mod_sub(U256::ZERO, const_lin, config::R_MOD);

    // Compute s1 coefficient: alpha * (l+β*s1+γ)*(r+β*s2+γ)*β * z(ωζ)
    let mut s1_coeff = math::mod_add(math::mod_mul(beta, s1, config::R_MOD), l, config::R_MOD);
    s1_coeff = math::mod_add(s1_coeff, gamma, config::R_MOD);
    let tmp2 = math::mod_add(math::mod_mul(beta, s2, config::R_MOD), r, config::R_MOD);
    let tmp2 = math::mod_add(tmp2, gamma, config::R_MOD);
    s1_coeff = math::mod_mul(s1_coeff, tmp2, config::R_MOD);
    s1_coeff = math::mod_mul(s1_coeff, beta, config::R_MOD);
    s1_coeff = math::mod_mul(s1_coeff, alpha, config::R_MOD);
    s1_coeff = math::mod_mul(s1_coeff, zu, config::R_MOD);

    // Compute z coefficient
    let mut s2_coeff = math::mod_add(math::mod_mul(beta, zeta, config::R_MOD), gamma, config::R_MOD);
    s2_coeff = math::mod_add(s2_coeff, l, config::R_MOD);

    let mut tmp = math::mod_mul(vk.coset_shift, zeta, config::R_MOD);
    tmp = math::mod_mul(beta, tmp, config::R_MOD);
    tmp = math::mod_add(tmp, gamma, config::R_MOD);
    tmp = math::mod_add(tmp, r, config::R_MOD);
    s2_coeff = math::mod_mul(s2_coeff, tmp, config::R_MOD);

    let mut tmp2 = math::mod_mul(vk.coset_shift, vk.coset_shift, config::R_MOD);
    tmp2 = math::mod_mul(tmp2, zeta, config::R_MOD);
    tmp2 = math::mod_mul(beta, tmp2, config::R_MOD);
    tmp2 = math::mod_add(tmp2, gamma, config::R_MOD);
    tmp2 = math::mod_add(tmp2, o, config::R_MOD);

    s2_coeff = math::mod_mul(s2_coeff, tmp2, config::R_MOD);
    s2_coeff = math::mod_mul(s2_coeff, alpha, config::R_MOD);
    s2_coeff = math::mod_sub(U256::ZERO, s2_coeff, config::R_MOD);

    let coeff_z = math::mod_add(alpha2_l1, s2_coeff, config::R_MOD);

    // Compute powers of zeta for quotient polynomial evaluation
    let n_plus_two = U256::from(vk.size as u64 + 2);
    let zeta_n2 = math::pow_mod(zeta, n_plus_two, config::R_MOD);
    let zeta_2n2 = math::mod_mul(zeta_n2, zeta_n2, config::R_MOD);

    // Compute zh coefficients: -(ζ^n-1), -ζ^{n+2}(ζ^n-1), -ζ^{2(n+2)}(ζ^n-1)
    let zh = math::mod_sub(U256::ZERO, zh_zeta, config::R_MOD);
    let zh_z_n2 = math::mod_sub(U256::ZERO, math::mod_mul(zeta_n2, zh_zeta, config::R_MOD), config::R_MOD);
    let zh_z_2n2 = math::mod_sub(U256::ZERO, math::mod_mul(zeta_2n2, zh_zeta, config::R_MOD), config::R_MOD);

    // Compute l*r for gate constraint
    let rl = math::mod_mul(l, r, config::R_MOD);

    // Compose linearized polynomial via MSM
    let mut points: Vec<G1Point> = Vec::new();
    let mut scalars: Vec<U256> = Vec::new();

    // BSB22 commitments
    for c in &proof.bsb22_commitments {
        points.push(*c);
    }
    for i in 0..proof.bsb22_commitments.len() {
        scalars.push(proof.batched_proof.claimed_values[5 + i]);
    }

    // Gate selectors: ql, qr, qm, qo, qk
    points.push(vk.ql); scalars.push(l);
    points.push(vk.qr); scalars.push(r);
    points.push(vk.qm); scalars.push(rl);
    points.push(vk.qo); scalars.push(o);
    points.push(vk.qk); scalars.push(U256::from(1));

    // Permutation: s3 * s1_coeff
    points.push(vk.s[2]); scalars.push(s1_coeff);

    // Permutation accumulator: z * coeff_z
    points.push(proof.z); scalars.push(coeff_z);

    // Quotient polynomial: h0, h1, h2 with zh coefficients
    points.push(proof.h[0]); scalars.push(zh);
    points.push(proof.h[1]); scalars.push(zh_z_n2);
    points.push(proof.h[2]); scalars.push(zh_z_2n2);

    // Compute linearized digest
    let linearized_digest = ec::msm(&points, &scalars)?;

    // Prepare digests for batched opening
    let mut digests_to_fold = Vec::with_capacity(6 + vk.qcp.len());
    digests_to_fold.push(linearized_digest);
    digests_to_fold.push(proof.lro[0]);
    digests_to_fold.push(proof.lro[1]);
    digests_to_fold.push(proof.lro[2]);
    digests_to_fold.push(vk.s[0]);
    digests_to_fold.push(vk.s[1]);
    digests_to_fold.extend_from_slice(&vk.qcp);

    // Prepend const_lin to claimed values
    let mut claimed_values = Vec::with_capacity(1 + proof.batched_proof.claimed_values.len());
    claimed_values.push(const_lin);
    claimed_values.extend_from_slice(&proof.batched_proof.claimed_values);

    let batched = BatchOpeningProof {
        h: proof.batched_proof.h,
        claimed_values,
    };

    // Fold the proof
    let (folded_proof, folded_digest) = kzg::fold_proof(
        &digests_to_fold, 
        &batched, 
        &zeta, 
        Some(zu), 
        &mut tr
    )?;

    // Generate final challenge u
    tr.bind(U, &utils::g1_to_bytes(&folded_digest))?;
    tr.bind(U, &utils::g1_to_bytes(&proof.z))?;
    tr.bind(U, &utils::g1_to_bytes(&folded_proof.h))?;
    tr.bind(U, &utils::g1_to_bytes(&proof.z_shifted_opening.h))?;
    let u = fs::to_fr_mod_r(tr.compute(U)?);

    let shifted_zeta = math::mod_mul(zeta, vk.generator, config::R_MOD);

    // Final batched pairing verification
    kzg::batch_verify_multi_points(
        vec![folded_digest, proof.z],
        vec![folded_proof, proof.z_shifted_opening.clone()],
        vec![zeta, shifted_zeta],
        u,
        vk,
    )
}

fn bind_public_data(
    tr: &mut fs::Transcript, 
    vk: &PlonkVerifyingKey, 
    public_inputs: &[U256]
) -> Result<(), ()> {
    // Bind verification key elements
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.s[0]))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.s[1]))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.s[2]))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.ql))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.qr))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.qm))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.qo))?;
    tr.bind(GAMMA, &utils::g1_to_bytes(&vk.qk))?;
    
    // Bind custom gates
    for q in &vk.qcp {
        tr.bind(GAMMA, &utils::g1_to_bytes(q))?;
    }
    
    // Bind public inputs
    for w in public_inputs {
        tr.bind(GAMMA, &w.to_be_bytes::<32>())?;
    }
    Ok(())
}

fn bind_points(tr: &mut fs::Transcript, id: &'static str, pts: &[G1Point]) -> Result<(), ()> {
    for p in pts {
        tr.bind(id, &utils::g1_to_bytes(p))?;
    }
    Ok(())
}

/////////////////////////////////////////////////////////////////
// KZG polynomial commitment utilities
/////////////////////////////////////////////////////////////////

mod kzg {
    use super::*;

    pub fn fold_proof(
        digests: &[G1Point],
        batch_opening_proof: &BatchOpeningProof,
        point: &U256,
        data_transcript: Option<U256>,
        tr: &mut fs::Transcript,
    ) -> Result<(OpeningProof, G1Point), ()> {
        // Derive gamma for folding
        let gamma = derive_gamma(point, digests, &batch_opening_proof.claimed_values, data_transcript)?;

        // Bind gamma into main transcript for challenge U
        tr.bind(U, &gamma.to_be_bytes::<32>())?;

        // Compute gamma powers
        let mut gammas = vec![U256::from(1); digests.len()];
        if digests.len() > 1 {
            gammas[1] = gamma;
        }
        for i in 2..digests.len() {
            gammas[i] = math::mod_mul(gammas[i-1], gamma, config::R_MOD);
        }

        // Fold digests and evaluations
        let (folded_digest, folded_eval) = fold(digests, &batch_opening_proof.claimed_values, &gammas)?;

        let open_proof = OpeningProof {
            h: batch_opening_proof.h,
            claimed_value: folded_eval,
        };

        Ok((open_proof, folded_digest))
    }

    pub fn batch_verify_multi_points(
        digests: Vec<G1Point>,
        proofs: Vec<OpeningProof>,
        points: Vec<U256>,
        u: U256,
        vk: &PlonkVerifyingKey,
    ) -> Result<(), ()> {
        let n = digests.len();
        if proofs.len() != n || points.len() != n { return Err(()); }
        if n == 1 { return Err(()); }

        // Generate random coefficients: [1, u, u^2, ...]
        let mut rnd = vec![U256::from(1); n];
        for i in 1..n {
            rnd[i] = math::mod_mul(u, rnd[i-1], config::R_MOD);
        }

        // Fold quotient commitments
        let q_points: Vec<G1Point> = proofs.iter().map(|p| p.h).collect();
        let mut folded_quotients = ec::msm(&q_points, &rnd)?;

        // Fold digests and evaluations
        let evals: Vec<U256> = proofs.iter().map(|p| p.claimed_value).collect();
        let (mut folded_digests, folded_evals) = fold(&digests, &evals, &rnd)?;

        // Subtract [folded_evals]*g1
        let folded_evals_commit = ec::ec_mul(&vk.g1, folded_evals)?;
        let folded_evals_commit_neg = ec::g1_neg(&folded_evals_commit);
        folded_digests = ec::ec_add(&folded_digests, &folded_evals_commit_neg)?;

        // Add ∑ rnd[i]*points[i]*proofs[i].h
        let mut rnd_points = rnd.clone();
        for i in 0..n {
            rnd_points[i] = math::mod_mul(rnd_points[i], points[i], config::R_MOD);
        }
        let folded_points_quot = ec::msm(&q_points, &rnd_points)?;
        folded_digests = ec::ec_add(&folded_digests, &folded_points_quot)?;

        folded_quotients = ec::g1_neg(&folded_quotients);

        // Final pairing check
        let ok = ec::pairing(&[
            (folded_digests, vk.g2[0]),
            (folded_quotients, vk.g2[1]),
        ])?;
        if !ok { return Err(()); }
        Ok(())
    }

    fn derive_gamma(
        point: &U256,
        digests: &[G1Point],
        claimed_values: &[U256],
        data_transcript: Option<U256>,
    ) -> Result<U256, ()> {
        let mut tr = fs::Transcript::new(&[GAMMA]);
        tr.bind(GAMMA, &point.to_be_bytes::<32>())?;
        for d in digests {
            tr.bind(GAMMA, &utils::g1_to_bytes(d))?;
        }
        for v in claimed_values {
            tr.bind(GAMMA, &v.to_be_bytes::<32>())?;
        }
        if let Some(dt) = data_transcript {
            tr.bind(GAMMA, &dt.to_be_bytes::<32>())?;
        }
        let b = tr.compute(GAMMA)?;
        Ok(fs::to_fr_mod_r(b))
    }

    fn fold(di: &[G1Point], vals: &[U256], coeffs: &[U256]) -> Result<(G1Point, U256), ()> {
        let folded_d = ec::msm(di, coeffs)?;
        let mut folded_v = U256::ZERO;
        for i in 0..vals.len() {
            folded_v = math::mod_add(folded_v, math::mod_mul(vals[i], coeffs[i], config::R_MOD), config::R_MOD);
        }
        Ok((folded_d, folded_v))
    }
}