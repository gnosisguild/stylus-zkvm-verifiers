/*!
# Stylus ZKP Verifiers

A library for zero-knowledge proof verification written in Rust for
[Arbitrum Stylus](https://docs.arbitrum.io/stylus/gentle-introduction).
This library offers verifiers for multiple ZKP systems.

## Supported ZKP Systems

- **RISC Zero**: Verify RISC Zero proofs using Groth16
- **SP1**: Verify SP1 proofs using Groth16/PLONK
- More verifiers coming soon...

## Usage

Add `stylus-zkp-verifiers` to your `Cargo.toml`:

```toml
[dependencies]
stylus-zkp-verifiers = "0.1.0"
```

Then import the verifier you need:

```rust
// For RISC Zero verification
use stylus_zkvm_verifiers::risc0::{RiscZeroVerifier, IRiscZeroVerifier};

// For SP1 Groth16 verification (requires "sp1" feature)
use stylus_zkvm_verifiers::sp1::{Sp1Verifier, ISp1Verifier};

// For SP1 PLONK verification (requires "sp1-plonk" feature)
use stylus_zkvm_verifiers::sp1::{Sp1PlonkVerifier, ISp1PlonkVerifier};

use stylus_sdk::prelude::*;

#[entrypoint]
#[storage]
struct MyContract {
    // Choose the verifier you need
    risc0_verifier: RiscZeroVerifier,
    sp1_groth16_verifier: Sp1Verifier,
    sp1_plonk_verifier: Sp1PlonkVerifier,
}
```

## Features

- `risc0`: Enable RISC Zero verifier support
- `sp1`: Enable SP1 Groth16 verifier support
- `sp1-plonk`: Enable SP1 Plonk verifier support
*/

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
#![allow(clippy::module_name_repetitions)]
extern crate alloc;

pub mod common;

#[cfg(feature = "risc0")]
pub mod risc0;

#[cfg(any(feature = "sp1", feature = "sp1-plonk"))]
pub mod sp1;

// Re-export commonly used types
pub use common::*; 