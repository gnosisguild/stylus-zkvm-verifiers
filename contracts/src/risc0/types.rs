use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use stylus_sdk::{alloy_primitives::B256, alloy_sol_types::sol};

use crate::risc0::config::{system_state_zero_digest, tags};

sol! {
    struct Seal {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExitCode {
    pub system: SystemExitCode,
    pub user: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SystemExitCode {
    Halted = 0,
    Paused = 1,
    SystemSplit = 2,
}

#[derive(Clone)]
pub struct ReceiptClaim {
    pub pre_state_digest: B256,
    pub post_state_digest: B256,
    pub exit_code: ExitCode,
    pub input: B256,
    pub output: B256,
}

#[derive(Clone)]
pub struct Output {
    pub journal_digest: B256,
    pub assumptions_digest: B256,
}

impl ReceiptClaim {
    pub fn ok(image_id: B256, journal_digest: B256) -> Self {
        let output = Output {
            journal_digest,
            assumptions_digest: B256::ZERO,
        };

        ReceiptClaim {
            pre_state_digest: image_id,
            post_state_digest: system_state_zero_digest(),
            exit_code: ExitCode {
                system: SystemExitCode::Halted,
                user: 0,
            },
            input: B256::ZERO,
            output: output.digest(),
        }
    }

    pub fn digest(&self) -> B256 {
        let tag_digest = B256::from_slice(&Sha256::digest(tags::RECEIPT_CLAIM_TAG));

        let exit_system_be = ((self.exit_code.system as u32) << 24).to_be_bytes();
        let exit_user_be   = ((self.exit_code.user   as u32) << 24).to_be_bytes(); 

        // 32×5  + 4 + 4 + 2 = 178 bytes
        let mut buf = Vec::with_capacity(178);
        buf.extend_from_slice(tag_digest.as_slice());
        buf.extend_from_slice(self.input.as_slice());
        buf.extend_from_slice(self.pre_state_digest.as_slice());
        buf.extend_from_slice(self.post_state_digest.as_slice());
        buf.extend_from_slice(self.output.as_slice());
        buf.extend_from_slice(&exit_system_be);
        buf.extend_from_slice(&exit_user_be);
        buf.extend_from_slice(&(4u16 << 8).to_be_bytes());

        B256::from_slice(&Sha256::digest(&buf))
    }
}

impl Output {
    pub fn digest(&self) -> B256 {
        let tag_digest = B256::from_slice(&Sha256::digest(tags::OUTPUT_TAG));

        let mut buf = Vec::with_capacity(98);
        buf.extend_from_slice(tag_digest.as_slice());
        buf.extend_from_slice(self.journal_digest.as_slice());
        buf.extend_from_slice(self.assumptions_digest.as_slice());
        buf.extend_from_slice(&(2u16 << 8).to_be_bytes());  

        B256::from_slice(&Sha256::digest(&buf))
    }
}
