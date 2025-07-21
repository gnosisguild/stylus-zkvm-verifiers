pub mod config;
pub mod crypto;
pub mod errors;
pub mod types;
pub mod verifier;

#[cfg(feature = "sp1-plonk")]
pub mod plonk;

pub use errors::Sp1Error;
pub use types::{Sp1Proof, Sp1PublicInputs};
pub use verifier::{Sp1Verifier, ISp1Verifier};

#[cfg(feature = "sp1-plonk")]
pub use plonk::{Sp1PlonkVerifier, ISp1PlonkVerifier, Sp1PlonkError, Sp1PlonkPublicInputs}; 