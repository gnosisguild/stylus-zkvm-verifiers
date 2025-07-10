/*!
RISC Zero proof verification interaction script.

This script demonstrates how to:
1. Connect to a deployed RISC Zero verifier contract
2. Initialize the contract with proper parameters
3. Verify a RISC Zero proof

Usage:
```bash
# Set environment variables
export PRIV_KEY="your_private_key"
export RPC_URL="https://sepolia-rollup.arbitrum.io/rpc"
export STYLUS_CONTRACT_ADDRESS="your_deployed_contract_address"

# Run the script
cargo run --example interact
```
*/

use alloy::{
    network::EthereumWallet,
    primitives::{hex, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use dotenv::dotenv;
use eyre::Result;

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract RiscZeroVerifier {
        function initialize(bytes32 control_root, bytes32 bn254_control_id) external;
        function verify(uint8[] memory seal, bytes32 image_id, bytes32 journal_digest) external view returns (bool);
        function verifyIntegrity(bytes memory receipt_seal, bytes32 receipt_claim_digest) external view returns (bool);
        function isInitialized() external view returns (bool);
        function getSelector() external view returns (bytes4);
        function getControlRoot() external view returns (bytes16, bytes16);
        function getBn254ControlId() external view returns (bytes32);
        function getVerifierKeyDigest() external view returns (bytes32);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    println!("🚀 RISC Zero Verifier Interaction Script");
    println!("=========================================");

    // Load environment variables
    let private_key = std::env::var("PRIV_KEY")?;
    let rpc_url = std::env::var("RPC_URL")?;
    let contract_address = std::env::var("STYLUS_CONTRACT_ADDRESS")?;

    println!("📡 Connecting to RPC: {}", rpc_url);
    println!("📋 Contract Address: {}", contract_address);

    // Setup provider
    let signer: PrivateKeySigner = private_key.parse()?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse()?);

    let verifier = RiscZeroVerifier::new(contract_address.parse()?, provider);

    // Check if contract is initialized
    println!("\n🔍 Checking contract initialization...");
    let is_initialized = verifier.isInitialized().call().await?._0;

    if !is_initialized {
        println!("🔧 Initializing contract...");

        // RISC Zero control parameters
        let control_root = B256::from_slice(&hex!(
            "539032186827b06719244873b17b2d4c122e2d02cfb1994fe958b2523b844576"
        ));
        let bn254_control_id = B256::from_slice(&hex!(
            "04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0"
        ));

        println!("  Control Root: 0x{}", hex::encode(control_root));
        println!("  BN254 Control ID: 0x{}", hex::encode(bn254_control_id));

        let tx = verifier
            .initialize(control_root, bn254_control_id)
            .send()
            .await?;
        let receipt = tx.get_receipt().await?;
        println!("✅ Contract initialized! Tx: {}", receipt.transaction_hash);
    } else {
        println!("✅ Contract already initialized");

        // Display current contract state
        let selector = verifier.getSelector().call().await?._0;
        let control_root = verifier.getControlRoot().call().await?;
        let bn254_id = verifier.getBn254ControlId().call().await?._0;
        let vk_digest = verifier.getVerifierKeyDigest().call().await?._0;

        println!("  Current Selector: 0x{}", hex::encode(selector));
        println!("  Control Root: 0x{} 0x{}", hex::encode(control_root._0), hex::encode(control_root._1));
        println!("  BN254 Control ID: 0x{}", hex::encode(bn254_id));
        println!("  VK Digest: 0x{}", hex::encode(vk_digest));
    }

    // TODO: Add Proof generation script, currently this is hardcoded but it fine for testing
    // Test proof verification
    println!("\n🧪 Testing proof verification...");

    let seal = vec![
        159, 57, 105, 108, 8, 181, 34, 166, 199, 54, 98, 123, 10, 68, 94, 138,
        123, 1, 40, 39, 66, 37, 71, 147, 185, 121, 0, 151, 43, 24, 133, 240,
        138, 234, 58, 104, 24, 205, 177, 232, 161, 138, 32, 12, 52, 180, 221, 44,
        150, 181, 206, 188, 65, 75, 236, 189, 30, 243, 4, 57, 13, 230, 122, 207,
        23, 215, 119, 177, 32, 112, 243, 194, 22, 197, 35, 101, 25, 64, 95, 242,
        176, 18, 212, 198, 207, 197, 223, 40, 130, 39, 95, 50, 12, 128, 69, 62,
        83, 160, 227, 36, 11, 124, 218, 194, 155, 36, 205, 45, 105, 77, 59, 166,
        205, 200, 92, 15, 110, 8, 220, 79, 33, 137, 152, 186, 58, 225, 105, 177,
        59, 11, 183, 251, 12, 23, 103, 211, 169, 180, 203, 253, 98, 98, 175, 102,
        190, 123, 61, 17, 209, 140, 50, 60, 218, 93, 182, 0, 230, 21, 17, 11,
        235, 125, 30, 6, 30, 206, 6, 22, 149, 23, 20, 138, 44, 162, 71, 159,
        223, 117, 111, 95, 141, 199, 213, 85, 196, 228, 235, 43, 105, 20, 135,
        172, 43, 225, 248, 67, 15, 237, 246, 196, 212, 187, 126, 66, 215, 154,
        100, 137, 171, 60, 238, 125, 103, 239, 189, 67, 143, 255, 189, 98, 108,
        166, 68, 170, 199, 37, 193, 84, 39, 223, 59, 115, 40, 140, 45, 55, 187,
        163, 79, 119, 182, 165, 134, 168, 89, 242, 89, 214, 213, 36, 96, 74, 130,
        208, 192, 59, 49, 88, 136, 159
    ];
    
    let image_id = B256::from_slice(&hex!("886c206b82e4f2dbdc4220f32c3a278c357ddc31ea800574b850c93647ddb5ff"));
    
    let journal_digest = B256::from_slice(&[
        209, 236, 103, 89, 2, 239, 22, 51, 66, 124, 163, 96, 178, 144, 176, 179,
        4, 90, 13, 144, 88, 221, 181, 230, 72, 180, 195, 195, 34, 76, 92, 104
    ]);

    println!("  Image ID: 0x{}", hex::encode(image_id));
    println!("  Journal Digest: 0x{}", hex::encode(journal_digest));
    println!("  Seal Length: {} bytes", seal.len());

    // Verify proof
    println!("\n🔍 Verifying proof...");
    match verifier.verify(seal.into(), image_id, journal_digest).call().await {
        Ok(result) => {
            if result._0 {
                println!("🎉 PROOF VERIFICATION SUCCESSFUL!");
                println!("   The RISC Zero proof is valid and verified on-chain!");
                println!("\n🏁 Verification complete!");
            } else {
                println!("❌ Proof verification failed");
                println!("   The proof did not pass verification");
            }
        }
        Err(e) => {
            println!("❌ Error during verification: {}", e);
            println!("Contract reverted. This could be due to:");
            println!("  - Invalid proof data");
            println!("  - Selector mismatch");
            println!("  - Cryptographic verification failure");
            println!("  - Contract not properly initialized");
        }
    }
    Ok(())
} 