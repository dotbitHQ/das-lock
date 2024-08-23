use crate::dlopen::DynLibDesc;
use crate::error::Error;
use crate::structures::AlgId;
use alloc::vec::Vec;
use ckb_std::ckb_types::core::ScriptHashType;

use config::constants::FieldKey;
use config::Config;
use das_core::warn;

#[cfg(test)]
use crate::test_framework::Testable;
#[cfg(test)]
use das_proc_macro::test_level;

//multiple features cannot be specified at the same time
#[cfg(any(
    all(feature = "mainnet", feature = "testnet2"),
    all(feature = "mainnet", feature = "testnet3"),
    all(feature = "testnet2", feature = "testnet3")
))]
core::compile_error!("Conflicting features: `mainnet`, `testnet2`, and `testnet3` cannot be enabled simultaneously");

const DYNAMIC_LIB_NUMS: usize = 9;
const ENTRY_CATEGORY_TYPE_TABLE: [u8; DYNAMIC_LIB_NUMS] = [
    1, //ckb
    1, //ckb-multi
    1, //anyone can pay
    1, //eth
    1, //tron
    0, //eip712 //0 is exec
    1, //ed25519
    1, //doge
    1, //webauthn
];

const EXPORTED_FUNC_NAME_STR_TABLE: [[&str; 3]; DYNAMIC_LIB_NUMS] = [
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", ""],
    ["validate", "validate_str", "validate_device"],
];
#[allow(dead_code)]
#[cfg(feature = "mainnet")]
const TYPE_ID_TABLE: [&str; DYNAMIC_LIB_NUMS] = [
    "f7e5ee57bfc0a17d3796cdae5a5b07c590668777166499d56178d510e1344765", //ckb
    "144f1ba88ec1fd316a37b5498552efce3447be8b74300fb6b92ad0efcbe964bb", //ckb-multi
    "",                                                                 //anyone can pay
    "6bbd5ca9bbdbe9a03f51329b2c6d06017ee2ae20546f724f70f79b8922a7d5b1", //eth
    "79e9a08713a6818f1fbabb05da5a048342781b34d80e7f64b758be581197bdd3", //tron
    "6bbd5ca9bbdbe9a03f51329b2c6d06017ee2ae20546f724f70f79b8922a7d5b1", //eth eip712
    "3000f8c98b8b020b8a0785320d24f73b3ba37fc1d4697c1a00fc8dda0bbc1cc7", // ed25519
    "1d13b5f6956c55dc13e8fb58b8aa7be2db429078d131fc140ccf94132a302a57", //doge
    "23bb512344f12fac23353466d436d0021a0df82114bcbcf23b733e447bcde404", //webauthn
];

#[allow(dead_code)]
#[cfg(feature = "testnet2")]
const TYPE_ID_TABLE: [&str; DYNAMIC_LIB_NUMS] = [
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
const TYPE_ID_TABLE: [&str; DYNAMIC_LIB_NUMS] = [
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
const TYPE_ID_CHECK: [u32; DYNAMIC_LIB_NUMS] = [4280, 4675, 0, 4569, 4397, 4569, 4543, 4467, 4336];

#[allow(dead_code)]
#[cfg(feature = "testnet2")]
const TYPE_ID_CHECK: [u32; DYNAMIC_LIB_NUMS] = [4452, 4499, 0, 4154, 4472, 4154, 4508, 4485, 4223];

#[allow(dead_code)]
#[cfg(feature = "testnet3")]
const TYPE_ID_CHECK: [u32; DYNAMIC_LIB_NUMS] = [4452, 4499, 0, 4154, 4472, 4154, 4508, 4485, 4223];

pub const MAX_WITNESS_SIZE: usize = 32768;
pub const ONE_BATCH_SIZE: usize = 32768;

pub const SCRIPT_SIZE: usize = 32768;

pub const SIZE_UINT64: usize = core::mem::size_of::<u64>();

pub const BLAKE160_SIZE: usize = 20;
pub const RIPEMD160_HASH_SIZE: usize = 20;
pub const HASH_SIZE: usize = 32;
pub const WEBAUTHN_PAYLOAD_LEN: usize = 20;

pub const SIGNATURE_SIZE: usize = 65;
pub const CHAIN_ID_LEN: usize = 8;
pub const WITNESS_ARGS_LOCK_LEN: usize = SIGNATURE_SIZE + HASH_SIZE + CHAIN_ID_LEN;
pub const WITNESS_ARGS_HEADER_LEN: usize = 16;
// 1 byte for sub alg id, 20 bytes for payload
pub const WEBAUTHN_SIZE: usize = 1 + WEBAUTHN_PAYLOAD_LEN;

pub const FLAGS_SIZE: usize = 4;

pub fn get_dyn_lib_desc_info(alg_id: AlgId) -> Result<DynLibDesc, Error> {
    let len = TYPE_ID_TABLE.len();
    if alg_id as usize >= len {
        return Err(Error::InvalidAlgId);
    }

    let type_id = TYPE_ID_TABLE[alg_id as usize];
    let type_id_checksum = TYPE_ID_CHECK[alg_id as usize];
    if checksum(type_id) != type_id_checksum {
        return Err(Error::InvalidTypeId);
    }
    let entry_category = ENTRY_CATEGORY_TYPE_TABLE[alg_id as usize].into();
    let mut entry_name = Vec::new();
    for i in 0..EXPORTED_FUNC_NAME_STR_TABLE[alg_id as usize].len() {
        if EXPORTED_FUNC_NAME_STR_TABLE[alg_id as usize][i] != "" {
            entry_name.push(EXPORTED_FUNC_NAME_STR_TABLE[alg_id as usize][i].into());
        }
    }
    Ok(DynLibDesc {
        dyn_lib_name: alg_id.into(),
        code_hash: <[u8; 32]>::try_from(decode_hex("type id", type_id)).unwrap(),
        hash_type: ScriptHashType::Type,
        entry_category,
        entry_name,
    })
}

pub(crate) fn decode_hex(title: &str, hex_str: &str) -> Vec<u8> {
    match hex::decode(hex_str) {
        Ok(v) => v,
        Err(e) => {
            panic!("decode hex ({}) error: {:?}, hex string = {}", title, e, hex_str);
        }
    }
}

pub fn get_type_id(field_key: FieldKey) -> Result<[u8; 32], Error> {
    let config_main = Config::get_instance().main()
        .map_err(|err| {
            warn!("Error: load data of ConfigCellMain failed: {:?}", err);

            Error::LoadConfigCellError
        })?;

    config_main.get_type_id_of(field_key)
        .map_err(|err| {
            warn!(
                "Error: get type id of {:?} failed, {:?}",
                &field_key, err
            );

            Error::LoadConfigCellError
        })
}

#[allow(dead_code)]
fn checksum(s: &str) -> u32 {
    s.as_bytes().iter().map(|&b| b as u32).sum()
}

//test only
// const TYPE_ID_TABLE_TYPE_NUMS: usize = 5;
// #[allow(dead_code)]
// #[cfg(feature = "mainnet")]
// pub const TYPE_ID_TABLE_TYPE: [&str; TYPE_ID_TABLE_TYPE_NUMS] = [
//     "c9fc9f3dc050f8bf11019842a2426f48420f79da511dd169ee243f455e9f84ed", //account cell
//     "991bcf61b6d7a26e6c27bda87d5468313d99ef0cd37113eee9e16c2680fa4532", //sub account cell
//     "",                                                                 //dp account cell
//     "",
//     ""
// ];
// #[allow(dead_code)]
// #[cfg(feature = "testnet2")]
// pub const TYPE_ID_TABLE_TYPE: [&str; TYPE_ID_TABLE_TYPE_NUMS] = [
//     "1106d9eaccde0995a7e07e80dd0ce7509f21752538dfdd1ee2526d24574846b1", //account cell
//     "8bb0413701cdd2e3a661cc8914e6790e16d619ce674930671e695807274bd14c", //sub account cell
//     "5988ce37f185904477f120742b191a0730da0d5de9418a8bdf644e6bb3bd8c12", //dp                                                            //dp account cell
//     "4fd085557b4ef857b0577723bbf0a2e94081bbe3114de847cd9db01abaeb4f4e", //eip712
//     "4ff58f2c76b4ac26fdf675aa82541e02e4cf896279c6d6982d17b959788b2f0c", //balance cell
//
// ];
