use alloc::{vec, vec::Vec};
use sha2::{Digest, Sha256};
use stylus_sdk::{
    alloy_primitives::B256,
    alloy_sol_types::SolValue,
};

use crate::common::VerificationKey;
use crate::risc0::config::tags;

pub mod vk {
    use super::*;
    use crate::common::{G1Point, G2Point};
    use stylus_sdk::alloy_primitives::uint;

    pub const ALPHA1: G1Point = G1Point {
        x: uint!(0x2D4D9AA7E302D9DF41749D5507949D05DBEA33FBB16C643B22F599A2BE6DF2E2_U256),
        y: uint!(0x14BEDD503C37CEB061D8EC60209FE345CE89830A19230301F076CAFF004D1926_U256),
    };

    pub const BETA2: G2Point = G2Point {
        x: [
            uint!(0x967032FCBF776D1AFC985F88877F182D38480A653F2DECAA9794CBC3BF3060C_U256),
            uint!(0xE187847AD4C798374D0D6732BF501847DD68BC0E071241E0213BC7FC13DB7AB_U256),
        ],
        y: [
            uint!(0x304CFBD1E08A704A99F5E847D93F8C3CAAFDDEC46B7A0D379DA69A4D112346A7_U256),
            uint!(0x1739C1B1A457A8C7313123D24D2F9192F896B7C63EEA05A9D57F06547AD0CEC8_U256),
        ],
    };

    pub const GAMMA2: G2Point = G2Point {
        x: [
            uint!(0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2_U256),
            uint!(0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED_U256),
        ],
        y: [
            uint!(0x90689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B_U256),
            uint!(0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA_U256),
        ],
    };

    pub const DELTA2: G2Point = G2Point {
        x: [
            uint!(0x3B03CD5EFFA95AC9BEE94F1F5EF907157BDA4812CCF0B4C91F42BB629F83A1C_U256),
            uint!(0x1AA085FF28179A12D922DBA0547057CCAAE94B9D69CFAA4E60401FEA7F3E0333_U256),
        ],
        y: [
            uint!(0x110C10134F200B19F6490846D518C9AEA868366EFB7228CA5C91D2940D030762_U256),
            uint!(0x1E60F31FCBF757E837E867178318832D0B2D74D59E2FEA1C7142DF187D3FC6D3_U256),
        ],
    };

    pub const IC: [G1Point; 6] = [
        G1Point {
            x: uint!(0x12AC9A25DCD5E1A832A9061A082C15DD1D61AA9C4D553505739D0F5D65DC3BE4_U256),
            y: uint!(0x25AA744581EBE7AD91731911C898569106FF5A2D30F3EEE2B23C60EE980ACD4_U256),
        },
        G1Point {
            x: uint!(0x707B920BC978C02F292FAE2036E057BE54294114CCC3C8769D883F688A1423F_U256),
            y: uint!(0x2E32A094B7589554F7BC357BF63481ACD2D55555C203383782A4650787FF6642_U256),
        },
        G1Point {
            x: uint!(0xBCA36E2CBE6394B3E249751853F961511011C7148E336F4FD974644850FC347_U256),
            y: uint!(0x2EDE7C9ACF48CF3A3729FA3D68714E2A8435D4FA6DB8F7F409C153B1FCDF9B8B_U256),
        },
        G1Point {
            x: uint!(0x1B8AF999DBFBB3927C091CC2AAF201E488CBACC3E2C6B6FB5A25F9112E04F2A7_U256),
            y: uint!(0x2B91A26AA92E1B6F5722949F192A81C850D586D81A60157F3E9CF04F679CCCD6_U256),
        },
        G1Point {
            x: uint!(0x2B5F494ED674235B8AC1750BDFD5A7615F002D4A1DCEFEDDD06EDA5A076CCD0D_U256),
            y: uint!(0x2FE520AD2020AAB9CBBA817FCBB9A863B8A76FF88F14F912C5E71665B2AD5E82_U256),
        },
        G1Point {
            x: uint!(0xF1C3C0D5D9DA0FA03666843CDE4E82E869BA5252FCE3C25D5940320B1C4D493_U256),
            y: uint!(0x214BFCFF74F425F6FE8C0D07B307482D8BC8BB2F3608F68287AA01BD0B69E809_U256),
        },
    ];

    pub fn get_verification_key() -> VerificationKey {
        VerificationKey {
            alpha1: ALPHA1,
            beta2: BETA2,
            gamma2: GAMMA2,
            delta2: DELTA2,
            ic: &IC,
        }
    }
}

pub mod digest_utils {
    use super::*;

    pub fn reverse_byte_order_uint256(value: B256) -> B256 {
        let mut reversed = [0u8; 32];
        reversed.iter_mut()
            .zip(value.as_slice().iter().rev())
            .for_each(|(dst, src)| *dst = *src);
        B256::from(reversed)
    }

    pub fn split_digest(d: B256) -> ([u8; 16], [u8; 16]) {
        let rev = reverse_byte_order_uint256(d);
        let mut low = [0u8; 16];
        let mut high = [0u8; 16];
        low.copy_from_slice(&rev[16..]);
        high.copy_from_slice(&rev[..16]);
        (low, high)
    }

    pub fn tagged_struct(tag_digest: B256, down: Vec<B256>) -> B256 {
        let mut buf = Vec::with_capacity(32 + 32 * down.len() + 2);

        buf.extend_from_slice(tag_digest.as_slice());
        for d in &down {
            buf.extend_from_slice(d.as_slice())
        }
        buf.extend_from_slice(&((down.len() as u16) << 8).to_be_bytes());

        B256::from_slice(&Sha256::digest(&buf))
    }

    pub fn tagged_list_cons(tag_digest: B256, head: B256, tail: B256) -> B256 {
        tagged_struct(tag_digest, vec![head, tail])
    }

    pub fn tagged_list(tag_digest: B256, list: Vec<B256>) -> B256 {
        let mut curr = B256::ZERO;
        for element in list.into_iter().rev() {
            curr = tagged_list_cons(tag_digest, element, curr);
        }
        curr
    }

    pub fn compute_verifier_key_digest() -> B256 {
        let mut ic_digests = Vec::with_capacity(6);
        for pt in &vk::IC {
            let encoded = (pt.x, pt.y).abi_encode_packed();
            ic_digests.push(B256::from_slice(&Sha256::digest(&encoded)));
        }

        let alpha_digest = {
            let e = (vk::ALPHA1.x, vk::ALPHA1.y).abi_encode_packed();
            B256::from_slice(&Sha256::digest(&e))
        };
        let beta_digest = {
            let e = (
                vk::BETA2.x[0],
                vk::BETA2.x[1],
                vk::BETA2.y[0],
                vk::BETA2.y[1],
            )
                .abi_encode_packed();
            B256::from_slice(&Sha256::digest(&e))
        };
        let gamma_digest = {
            let e = (
                vk::GAMMA2.x[0],
                vk::GAMMA2.x[1],
                vk::GAMMA2.y[0],
                vk::GAMMA2.y[1],
            )
                .abi_encode_packed();
            B256::from_slice(&Sha256::digest(&e))
        };
        let delta_digest = {
            let e = (
                vk::DELTA2.x[0],
                vk::DELTA2.x[1],
                vk::DELTA2.y[0],
                vk::DELTA2.y[1],
            )
                .abi_encode_packed();
            B256::from_slice(&Sha256::digest(&e))
        };

        let ic_tag = B256::from_slice(&Sha256::digest(tags::VK_IC_TAG));
        let ic_list_digest = tagged_list(ic_tag, ic_digests);

        let vk_tag = B256::from_slice(&Sha256::digest(tags::VK_TAG));

        let encoded = (
            vk_tag,
            alpha_digest,
            beta_digest,
            gamma_digest,
            delta_digest,
            ic_list_digest,
            (5u16) << 8,
        )
            .abi_encode_packed();

        B256::from_slice(&Sha256::digest(&encoded))
    }
} 