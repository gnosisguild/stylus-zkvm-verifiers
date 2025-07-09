/*!
Common types and utilities shared across different ZKP verifiers.
*/

pub mod errors;
pub mod groth16;

// Re-export common types
pub use errors::*;
pub use groth16::*; 