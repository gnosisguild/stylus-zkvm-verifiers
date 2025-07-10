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
    interface ISp1Verifier {
        function verifyProof(bytes32 programVKey, uint8[] calldata publicValues, uint8[] calldata proofBytes) external view;
        function verifierHash() external view returns (bytes32);
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
    
    match verifier.verifierHash().call().await {
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
        .verifyProof(test_data.vkey, test_data.public_values.into(), test_data.proof.into())
        .call()
        .await
    {
        Ok(_) => {
            println!("🎉 PROOF VERIFICATION SUCCESSFUL!");
            println!("   The provided proof is valid for the given program and public values.");
            println!("\n🏁 Verification complete!");
        }
        Err(e) => {
            println!("❌ SP1 proof verification FAILED!");
            println!("   Error: {}", e);
            
            if let Some(revert_reason) = e.to_string().split("reverted: ").nth(1) {
                println!("   Revert reason: {}", revert_reason);
            }
        }
    }

    Ok(())
}

struct TestFixture {
    vkey: B256,
    public_values: Vec<u8>,
    proof: Vec<u8>,
}

fn load_test_fixture() -> TestFixture {
    TestFixture {
        vkey: B256::from_slice(&hex!("0x00d2f2f7952cbd9ececcf5303b2da21af20dc24953485d345df73c2854f498bc")),
        public_values: hex::decode("0x00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000001a6d0000000000000000000000000000000000000000000000000000000000002ac2").unwrap(),
        proof: hex::decode("0xa4594c5929754e82587e66fd1bb8d8e4e98e6777a1adf400c405506a09173829f224450f1b17a81870ab2aef2fbbb236f1d397bb6c4ff793bf0e350d58fc191b5e85d7233010220b72c9ee5cb184f6c2bf486f3cae5d21c1e7145e957f36d8716df245c7028365cbff8d03a827a8fcfadb43af2c15c7ca2434db227ab399719aeae87e2d111448ae96af93c333b0a23f9a4be33c6396d1ab823d927d51153d05ec87df332988ebd31b243498e1cb1f8d97f84324ad242e7bc3ea9c1bf3165be46b8302952f3ea26440093819356240a700aa424487f6aab1eb664e5aed296c8356b252f11579161a3ec93bdb657e57ba9d5480195da51d0a74ea2f343f85a12f8d2477eb").unwrap(),
    }
}