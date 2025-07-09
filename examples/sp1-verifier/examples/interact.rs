use alloy::{
    network::EthereumWallet,
    primitives::{hex, B256, FixedBytes},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use dotenv::dotenv;
use eyre::Result;

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    interface ISp1Verifier {
        function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
        function verifier_hash() external view returns (bytes32);
        function version() external view returns (string memory);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    println!("🚀 SP1 Verifier Interaction Script");
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

    let verifier = ISp1Verifier::new(contract_address.parse()?, provider);

    // Test verifier info
    println!("\n📋 Verifier Information:");
    match verifier.version().call().await {
        Ok(version) => println!("   • Version: {}", version._0),
        Err(e) => println!("   • Version: Error - {}", e),
    }
    
    match verifier.verifier_hash().call().await {
        Ok(hash) => println!("   • Verifier Hash: {:#x}", hash._0),
        Err(e) => println!("   • Verifier Hash: Error - {}", e),
    }

    // Test SP1 proof verification
    let test_data = load_test_fixture();
    println!("📁 Loaded test fixture:");
    println!("   • Program VKey: {:#x}", test_data.vkey);
    println!("   • Public Values: {} bytes", test_data.public_values.len());
    println!("   • Proof: {} bytes", test_data.proof.len());
    println!();

    match verifier
        .verifyProof(test_data.vkey, test_data.public_values, test_data.proof)
        .call()
        .await
    {
        Ok(_) => {
            println!("✅ SP1 proof verification SUCCESSFUL!");
            println!("   The provided proof is valid for the given program and public values.");
        }
        Err(e) => {
            println!("❌ SP1 proof verification FAILED!");
            println!("   Error: {}", e);
            
            if let Some(revert_reason) = e.to_string().split("reverted: ").nth(1) {
                println!("   Revert reason: {}", revert_reason);
            }
        }
    }

    println!("\n✨ SP1 Verifier interaction complete!");
    Ok(())
}

struct TestFixture {
    vkey: B256,
    public_values: Vec<u8>,
    proof: Vec<u8>,
}

fn load_test_fixture() -> TestFixture {
    TestFixture {
        vkey: B256::from_str("0x00b51cef3572d1a49ae7f4a332221cab31cdb72b131dbf28fb6ab26e15458fe2").unwrap(),
        public_values: hex::decode("00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000001a6d0000000000000000000000000000000000000000000000000000000000002ac2").unwrap(),
        proof: hex::decode("11b6a09d07727e8889e440a3a4fe6b3cc7e438d232daa177c762d3267ada247e165b06ca1beaf42fbaaa7676caf3dd978af6c1b7b64968f67f41e3d356790a09337566d81122aa6904fd105ff2a499c1f3264a3f55e740cda6521be1877225f4073f7a4a22fe10987f12d67a145738de4e301bb8e37347556bead5bb003ce32653ffae5a281be092e26c9d16eb569b3592eb766b0197fe05d359952a05958b2596239f061333369ab1d6576f80e965d0e3d8f1d3a74722e794e72199c3dee91bff8f3a5e087ac3fac78f5372befa133b94764b43c4c88ee4f3fc0495e52c74ad5a6d2c18008e6740d0aad32976971c95db159fb37d4f8428d7c5abe658a58d516acd664c").unwrap(),
    }
} 