use stylus_sdk::alloy_primitives::U256;

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

pub struct VerificationKey {
    pub alpha1: G1Point,
    pub beta2: G2Point,
    pub gamma2: G2Point,
    pub delta2: G2Point,
    pub ic: &'static [G1Point],
}

#[derive(Clone, Copy)]
pub enum VMType { Risc0, Sp1 }