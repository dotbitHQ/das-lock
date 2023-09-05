use crate::error::Error;
use crate::structures::AlgId;
use alloc::vec::Vec;
use das_proc_macro::{test_level};

#[cfg(test)]
use crate::test_framework::Testable;

#[cfg(all(feature = "mainnet", feature = "testnet2"))]
core::compile_error!("features `mainnet` and `testnet2` cannot be enabled simultaneously");

#[cfg(all(feature = "mainnet", feature = "testnet3"))]
core::compile_error!("features `mainnet` and `testnet3` cannot be enabled simultaneously");

#[cfg(all(feature = "testnet2", feature = "testnet3"))]
core::compile_error!("features `testnet2` and `testnet3` cannot be enabled simultaneously");

#[allow(dead_code)]
#[cfg(feature = "mainnet")]
const TYPE_ID_TABLE: [&str; 9] = [
    "f7e5ee57bfc0a17d3796cdae5a5b07c590668777166499d56178d510e1344765", //ckb
    "144f1ba88ec1fd316a37b5498552efce3447be8b74300fb6b92ad0efcbe964bb", //ckb-multi
    "",                                                                 //anyone can pay
    "6bbd5ca9bbdbe9a03f51329b2c6d06017ee2ae20546f724f70f79b8922a7d5b1", //eth
    "79e9a08713a6818f1fbabb05da5a048342781b34d80e7f64b758be581197bdd3", //tron
    "6bbd5ca9bbdbe9a03f51329b2c6d06017ee2ae20546f724f70f79b8922a7d5b1", //eth eip712
    "3000f8c98b8b020b8a0785320d24f73b3ba37fc1d4697c1a00fc8dda0bbc1cc7", // ed25519
    "1d13b5f6956c55dc13e8fb58b8aa7be2db429078d131fc140ccf94132a302a57", //doge
    "1d13b5f6956c55dc13e8fb58b8aa7be2db429078d131fc140ccf94132a302a57", //webauthn
];

#[allow(dead_code)]
#[cfg(feature = "testnet2")]
const TYPE_ID_TABLE: [&str; 9] = [
    "c9fc9f3dc050f8bf11019842a2426f48420f79da511dd169ee243f455e9f84ed", //ckb
    "991bcf61b6d7a26e6c27bda87d5468313d99ef0cd37113eee9e16c2680fa4532", //ckb-multi
    "",                                                                 //anyone can pay
    "6d0f4c38ae82383c619b9752ed8140019aa49128e39d48b271239a668c40a174", //eth
    "f8f6b58d548231bc6fe19c1a1ceafa3a429f54c21a458b211097ebe564b14615", //tron
    "6d0f4c38ae82383c619b9752ed8140019aa49128e39d48b271239a668c40a174", //eth eip712
    "ebb79383a2947f36a095b434dd4f7c670dec6c2a53d925fb5c5f949104e59a6f", // ed25519
    "7ab1b06d51c579d528395d7f472582bf1d3dce45ba96c2bff2c19e30f0d90281", //doge
    "b2d54e4da02130a9f7a9067ced1996180c0f2b122a6399090649a1050a66b2d8", //webauthn
];

#[allow(dead_code)]
#[cfg(feature = "testnet3")]
const TYPE_ID_TABLE: [&str; 9] = [
    "c9fc9f3dc050f8bf11019842a2426f48420f79da511dd169ee243f455e9f84ed", //ckb
    "991bcf61b6d7a26e6c27bda87d5468313d99ef0cd37113eee9e16c2680fa4532", //ckb-multi
    "",                                                                 //anyone can pay
    "6d0f4c38ae82383c619b9752ed8140019aa49128e39d48b271239a668c40a174", //eth
    "f8f6b58d548231bc6fe19c1a1ceafa3a429f54c21a458b211097ebe564b14615", //tron
    "6d0f4c38ae82383c619b9752ed8140019aa49128e39d48b271239a668c40a174", //eth eip712
    "ebb79383a2947f36a095b434dd4f7c670dec6c2a53d925fb5c5f949104e59a6f", // ed25519
    "7ab1b06d51c579d528395d7f472582bf1d3dce45ba96c2bff2c19e30f0d90281", //doge
    "b2d54e4da02130a9f7a9067ced1996180c0f2b122a6399090649a1050a66b2d8", //webauthn
];

//tyep id checksum

#[allow(dead_code)]
#[cfg(feature = "mainnet")]
const TYPE_ID_CHECK: [u32; 9] = [4280, 4675, 0, 4569, 4397, 4569, 4543, 4467, 4467];

#[allow(dead_code)]
#[cfg(feature = "testnet2")]
const TYPE_ID_CHECK: [u32; 9] = [4452, 4499, 0, 4154, 4472, 4154, 4508, 4485, 4223];

#[allow(dead_code)]
#[cfg(feature = "testnet3")]
const TYPE_ID_CHECK: [u32; 9] = [4452, 4499, 0, 4154, 4472, 4154, 4508, 4485, 4223];

#[allow(dead_code)]
#[cfg(feature = "mainnet")]
const SUB_ACCOUNT_TYPE_ID: &str =
    "63516de8bb518ed1225e3b63f138ccbe18e417932d240f1327c8e86ba327f4b4";

#[allow(dead_code)]
#[cfg(feature = "testnet2")]
const SUB_ACCOUNT_TYPE_ID: &str =
    "8bb0413701cdd2e3a661cc8914e6790e16d619ce674930671e695807274bd14c";

#[allow(dead_code)]
#[cfg(feature = "testnet3")]
const SUB_ACCOUNT_TYPE_ID: &str =
    "8bb0413701cdd2e3a661cc8914e6790e16d619ce674930671e695807274bd14c";

#[allow(dead_code)]
#[cfg(feature = "mainnet")]
const BALANCE_TYPE_ID: &str = "ebafc1ebe95b88cac426f984ed5fce998089ecad0cd2f8b17755c9de4cb02162";

#[allow(dead_code)]
#[cfg(feature = "testnet2")]
const BALANCE_TYPE_ID: &str = "4ff58f2c76b4ac26fdf675aa82541e02e4cf896279c6d6982d17b959788b2f0c";

#[allow(dead_code)]
#[cfg(feature = "testnet3")]
const BALANCE_TYPE_ID: &str = "4ff58f2c76b4ac26fdf675aa82541e02e4cf896279c6d6982d17b959788b2f0c";

//convert the hex string into [u8] then return all
pub fn get_type_id(alg_id: AlgId) -> Result<Vec<u8>, Error> {
    let len = TYPE_ID_TABLE.len();
    if alg_id as usize >= len {
        return Err(Error::InvalidAlgId);
    }

    //not support ckb yet
    if alg_id == AlgId::CkbMultiSig || alg_id == AlgId::AlwaysSuccess {
        return Err(Error::InvalidAlgId);
    }

    let type_id = TYPE_ID_TABLE[alg_id as usize];

    Ok(decode_hex("type id", type_id))
    //Ok(hex::decode(type_id).map_err(|_| Error::InvalidAlgId)?)
}

fn decode_hex(title: &str, hex_str: &str) -> Vec<u8> {
    match hex::decode(hex_str) {
        Ok(v) => v,
        Err(e) => {
            panic!(
                "decode hex ({}) error: {:?}, hex string = {}",
                title, e, hex_str
            );
        }
    }
}
pub fn get_balance_type_id() -> Vec<u8> {
    decode_hex("balance type id", BALANCE_TYPE_ID)
}
pub fn get_sub_account_type_id() -> Vec<u8> {
    decode_hex("sub account type id", SUB_ACCOUNT_TYPE_ID)
}
#[allow(dead_code)]
fn checksum(s: &str) -> u32 {
    s.as_bytes().iter().map(|&b| b as u32).sum()
}

pub const MAX_WITNESS_SIZE: usize = 32768;
pub const ONE_BATCH_SIZE: usize = 32768;

pub const SCRIPT_SIZE: usize = 32768;

pub const SIZE_UINT64: usize = core::mem::size_of::<u64>();

pub const BLAKE160_SIZE: usize = 20;
pub const RIPEMD160_HASH_SIZE: usize = 20;
pub const HASH_SIZE: usize = 32;
pub const WEBAUTHN_PAYLOAD_LEN: usize = 20;

pub const SIGNATURE_SIZE: usize = 64;
pub const CHAIN_ID_LEN: usize = 8;
pub const WITNESS_ARGS_LOCK_LEN: usize = SIGNATURE_SIZE + HASH_SIZE + CHAIN_ID_LEN;
pub const WITNESS_ARGS_HEADER_LEN: usize = 16;
// 1 byte for sub alg id, 20 bytes for payload
pub const WEBAUTHN_SIZE: usize = 1 + WEBAUTHN_PAYLOAD_LEN;

pub const FLAGS_SIZE: usize = 4;

//todo fn get_devicekey_list_type_id

// fn main() {
//     println!("Hello, world!");
//     println!("{:?}", TYPE_ID_TABLE);
//     for i in TYPE_ID_TABLE {
//         print!("{}, ", checksum(i));
//     }
// }
#[test_level(1)]
fn test_get_type_id() {
    let expected_check_sum = TYPE_ID_CHECK;
    for (id, expected) in TYPE_ID_TABLE.iter().zip(expected_check_sum.iter()) {
        let real = checksum(id);
        assert_eq!(expected, &real);
    }
}
#[cfg(feature = "mainnet")]
#[test_level(1)]
fn test_get_type_id_mainnet() {
    let expected_type_id_str = "f7e5ee57bfc0a17d3796cdae5a5b07c590668777166499d56178d510e1344765";

    let real_ckb_type_id = TYPE_ID_TABLE[0];
    assert_eq!(expected_type_id_str, real_ckb_type_id);

    let real_ckb_checksum = TYPE_ID_CHECK[0];
    let ckb_checksum = checksum(expected_type_id_str);
    assert_eq!(ckb_checksum, real_ckb_checksum);
}

#[cfg(feature = "testnet2")]
#[test_level(1)]
fn test_get_type_id_testnet2() {
    let expected_type_id_str = "c9fc9f3dc050f8bf11019842a2426f48420f79da511dd169ee243f455e9f84ed";

    let real_ckb_type_id = TYPE_ID_TABLE[0];
    assert_eq!(expected_type_id_str, real_ckb_type_id);

    let real_ckb_checksum = TYPE_ID_CHECK[0];
    let ckb_checksum = checksum(expected_type_id_str);
    assert_eq!(ckb_checksum, real_ckb_checksum);
}

#[cfg(feature = "testnet3")]
#[test_level(1)]
fn test_get_type_id_testnet3() {
    let expected_type_id_str = "c9fc9f3dc050f8bf11019842a2426f48420f79da511dd169ee243f455e9f84ed";

    let real_ckb_type_id = TYPE_ID_TABLE[0];
    assert_eq!(expected_type_id_str, real_ckb_type_id);

    let real_ckb_checksum = TYPE_ID_CHECK[0];
    let ckb_checksum = checksum(expected_type_id_str);
    assert_eq!(ckb_checksum, real_ckb_checksum);
}

#[test_level(1)]
fn test_decode_hex() {
    let expected = alloc::vec![0x12, 0x34, 0x56, 0x78];
    let real = decode_hex("test", "12345678");
    assert_eq!(expected, real);
}
