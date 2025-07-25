// SP1 Groth16 verifier (enabled with "sp1" feature)
#[cfg(feature = "sp1")]
pub mod groth16;

// SP1 PLONK verifier (enabled with "sp1-plonk" feature)
#[cfg(feature = "sp1-plonk")]
pub mod plonk;

// Re-export Groth16 types when the sp1 feature is enabled
#[cfg(feature = "sp1")]
pub use groth16::{Sp1Error, Sp1Proof, Sp1PublicInputs, Sp1Verifier, ISp1Verifier};

// Re-export PLONK types when the sp1-plonk feature is enabled
#[cfg(feature = "sp1-plonk")]
pub use plonk::{Sp1PlonkVerifier, Sp1PlonkError, ISp1PlonkVerifier}; 