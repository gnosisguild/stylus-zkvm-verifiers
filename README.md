# Stylus zkVM Verifiers

A comprehensive library for zero-knowledge proof verification on [Arbitrum Stylus](https://docs.arbitrum.io/stylus/gentle-introduction). This library provides a modular architecture for integrating multiple ZKP verification systems into your smart contracts. Each zkVM system is isolated in its own module and can be compiled and deployed separately. You only need to compile the verifiers you need using feature flags.

> [!CAUTION]
>
> This repository is not audited for production use.


## 📋 Supported zkVM Systems

| System | Status | Proof System | Version |
|--------|--------|--------------|----------|
| **RISC Zero** | ✅ | Groth16 | v2.1 |
| **SP1** | ✅ | Groth16 | v5.0.0 |

## 📁 Project Structure

```
stylus-zkvm-verifiers/
├── contracts/                    # 📚 Main verification library
│   ├── src/
│   │   ├── common/              # Shared cryptographic utilities
│   │   ├── risc0/               # RISC Zero Groth16 verifier
│   │   └── sp1/                 # SP1 Groth16 verifier (PLONK in progress)
│   └── Cargo.toml
├── examples/                     # 🏗️ Complete contract examples
│   ├── risc0-verifier/          # Working RISC Zero contract
│   └── sp1-verifier/            # Working SP1 contract
└── Cargo.toml                   # Workspace configuration
```

## 📚 Library Contracts
- RISC Zero Verifier (`contracts/src/risc0/`)
- SP1 Verifier (`contracts/src/sp1/`)

## 🏗️ Example Contracts

### RISC Zero Example (`examples/risc0-verifier/`)

**Complete Working Example:**
- **Contract Size**: ~21.7 KiB deployed
- **Deployment Cost**: ~0.000114 ETH
- **Real Proof Verification**: Uses actual RISC Zero proofs in interaction script

**Files:**
- `src/lib.rs`: Main verifier contract implementation
- `examples/interact.rs`: **Contains real RISC Zero proof verification**
- `.env.example`: Configuration template
- `Cargo.toml`: Independent project setup

## 🛠️ Local Development Setup

### Prerequisites

1. **Install Stylus CLI**
```bash
cargo install --force cargo-stylus
```

2. **Install WebAssembly Target**
```bash
rustup target add wasm32-unknown-unknown
```

3. **Setup Nitro Dev Node** (required for local testing):
```bash
git clone https://github.com/OffchainLabs/nitro-devnode.git
cd nitro-devnode
./run-dev-node.sh
```

This starts a local Arbitrum node at `http://localhost:8547` with pre-funded accounts.

### Working with Examples

#### RISC Zero Verifier

1. **Navigate to example:**
```bash
cd examples/risc0-verifier
```

2. **Setup environment:**
```bash
cp .env.example .env
# Edit .env if needed - defaults work for local nitro-devnode
```

3. **Check contract compilation:**
```bash
cargo stylus check
```

4. **Deploy contract:**
```bash
cargo stylus deploy --no-verify \
  --endpoint='http://localhost:8547' \
  --private-key="0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659"
```

5. **Update contract address in .env** (use address from deploy output)

6. **Run interaction script with real RISC Zero proof:**
```bash
cargo run --example interact
```

**Note**: The `interact` script uses a **real RISC Zero proof** and demonstrates actual on-chain verification.

## 📦 Using the Library

### Add to Your Project

```toml
[dependencies]
stylus-zkvm-verifiers = { git = "https://github.com/gnosisguild/stylus-zkvm-verifiers", features = ["risc0"] }
```

### Feature Flags

- `risc0`: Enable RISC Zero verifier
- `sp1`: Enable SP1 verifier
- `export-abi`: Enable ABI export for deployment

### Example Usage

```rust
use stylus_zkp_verifiers::risc0::{RiscZeroVerifier, IRiscZeroVerifier};
use stylus_sdk::prelude::*;

#[storage]
#[entrypoint]
pub struct MyVerifier {
    risc0: RiscZeroVerifier,
}

#[public]
#[implements(IRiscZeroVerifier<Error = Vec<u8>>)]
impl MyVerifier {}

#[public]
impl IRiscZeroVerifier for MyVerifier {
    type Error = Vec<u8>;

    pub fn verify_risc0_proof(
        &self,
        seal: Vec<u8>,
        image_id: B256,
        journal_digest: B256,
    ) -> bool {
        self.risc0.verify(seal, image_id, journal_digest)
    }
}
```

### Adding New Verifiers

1. Create module in `contracts/src/your_zkp/`
2. Follow the established patterns from `risc0/` 
3. Add feature flag and example
4. Ensure complete isolation from other verifiers
