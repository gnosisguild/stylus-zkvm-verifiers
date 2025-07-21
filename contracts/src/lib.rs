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
use stylus_zkvm_verifiers::risc0::{RiscZeroVerifier, IRiscZeroVerifier};
use stylus_sdk::prelude::*;

#[entrypoint]
#[storage]
struct MyContract {
    verifier: RiscZeroVerifier,
}

#[public]
impl IRiscZeroVerifier for MyContract {
    // Implementation here
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

#[cfg(feature = "sp1")]
pub mod sp1;

// Re-export commonly used types
pub use common::*; 