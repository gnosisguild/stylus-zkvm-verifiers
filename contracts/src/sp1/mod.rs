/*!
SP1 proof verifier for Arbitrum Stylus.

This module provides a complete SP1 proof verification system.
SP1 uses a different architecture than RISC Zero:
- No selectors or control roots
- Uses PLONK verification instead of Groth16
- Different proof format and validation logic
- Simpler initialization without RISC Zero-specific parameters
*/

pub mod config;
pub mod errors;
pub mod plonk;
pub mod types;
pub mod verifier;

// Re-export the main types
pub use errors::Sp1Error;
pub use types::Sp1Proof;
pub use verifier::{Sp1Verifier, ISp1Verifier}; 