use crate::constants::MAX_WITNESS_SIZE;
use crate::debug_log;
use crate::error::Error;
use crate::structures::AlgId;
use alloc::vec::Vec;
use das_core::constants::get_config_cell_main;
//use das_core::constants::get_config_cell_main;
use das_core::util::{hex_string, load_witnesses};
use das_core::witness_parser::general_witness_parser::get_witness_parser;
use das_core::witness_parser::WitnessesParser;
use das_dynamic_libs::constants::DynLibName;
use das_types::constants::DataType;
use das_types::packed::{ConfigCellMain, Data, DataEntity, DeviceKeyListCellData};
use das_types::prelude::Entity;

pub(crate) fn get_type_id(alg_id: AlgId) -> Result<Vec<u8>, Error> {

    debug_log!("get_type_id of alg {:?}", alg_id);
    let config = get_witness_parser()
        .find_unique::<ConfigCellMain>()
        .unwrap()
        .result;

    let dynamic_name: DynLibName = alg_id.into();
    let das_lock_type_id_table = config.das_lock_type_id_table();
    let reader = das_lock_type_id_table.as_reader();
    Ok(dynamic_name.get_code_hash(reader).to_vec())
}
//
pub fn get_balance_type_id() -> Result<Vec<u8>, Error> {
    debug_log!("get_balance_type_id");

    let a = get_witness_parser();
    debug_log!("file-{} line-{}", file!(), line!());
    let b = a.find_unique::<ConfigCellMain>();
    debug_log!("file-{} line-{}", file!(), line!());

    debug_log!("b");

    let c = match b {
        Err(e) => {
            debug_log!(
                "get_balance_type_id find_unique::<ConfigCellMain> None {:?}",
                e
            );
            return Err(Error::InvalidWitness);
        }
        Ok(v) => {
            debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some");
            let config_main = v.result;
            debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some config_main");
            let type_id_table = config_main.type_id_table();
            debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some type_id_table");
            let balance = type_id_table.balance_cell().raw_data().to_vec();
            debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some balance");
            balance
        }
    };

    debug_log!("get_balance_type_id result {}", hex_string(c.as_slice()));

    let a = get_config_cell_main();
    debug_log!("file-{} line-{}", file!(), line!());

    debug_log!("a");
    let b = a.type_id_table();
    debug_log!("file-{} line-{}", file!(), line!());

    debug_log!("b");

    let c = b.as_reader();
    debug_log!("file-{} line-{}", file!(), line!());

    debug_log!("c");

    let d = c.balance_cell().raw_data().to_vec();
    debug_log!("file-{} line-{}", file!(), line!());

    debug_log!("d");

    let e = hex_string(d.as_slice());
    debug_log!("file-{} line-{}", file!(), line!());

    debug_log!("e");

    // let c = match b {
    //     Err(e) => {
    //         debug_log!(
    //             "get_balance_type_id find_unique::<ConfigCellMain> None {:?}",
    //             e
    //         );
    //         return Err(Error::InvalidWitness);
    //     }
    //     Ok(v) => {
    //         debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some");
    //         let config_main = v.result;
    //         debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some config_main");
    //         let type_id_table = config_main.type_id_table();
    //         debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some type_id_table");
    //         let balance = type_id_table.balance_cell().raw_data().to_vec();
    //         debug_log!("get_balance_type_id find_unique::<ConfigCellMain> Some balance");
    //         balance
    //     }
    // };
    //
    // debug_log!("get_balance_type_id result {:?}", c);
    //
    // let config_main = get_witness_parser()
    //     .find_unique::<ConfigCellMain>()
    //     .unwrap()
    //     .result;
    //
    // let type_id_table = config_main.type_id_table();
    // let balance = type_id_table.balance_cell().raw_data().to_vec();
    Ok(d)
}
pub fn get_sub_account_type_id() -> Result<Vec<u8>, Error> {
    debug_log!("get_sub_account_type_id");
    let config_main = get_witness_parser()
        .find_unique::<ConfigCellMain>()
        .unwrap()
        .result;

    let type_id_table = config_main.type_id_table();
    let sub_account = type_id_table.sub_account_cell().raw_data().to_vec();
    Ok(sub_account)
}

pub fn get_account_type_id() -> Result<Vec<u8>, Error> {
    //todo replace get_type_id
    debug_log!("get_account_type_id");
    let config_main = get_witness_parser()
        .find_unique::<ConfigCellMain>()
        .unwrap()
        .result;

    let type_id_table = config_main.type_id_table();
    let account = type_id_table.account_cell().raw_data().to_vec();
    Ok(account)
}

pub fn get_dp_cell_type_id() -> Result<Vec<u8>, Error> {
    debug_log!("get_dp_cell_type_id");
    let config_main = get_witness_parser()
        .find_unique::<ConfigCellMain>()
        .unwrap()
        .result;

    let type_id_table = config_main.type_id_table();
    //need
    //let account = type_id_table.dp_cell().raw_data().to_vec();
    let account = type_id_table.account_cell().raw_data().to_vec();

    Ok(account)
}

//
// #[allow(dead_code)]
// pub fn get_pk_by_id_in_key_list(data: &[u8], pk_idx: usize) -> Result<Vec<u8>, Error> {
//     //Warning: if there are differences between from_slice and from_compatible_slice
//     let key_list = match DeviceKeyListCellData::from_slice(data){
//         Ok(v) => v,
//         Err(e) => {
//             debug_log!("DeviceKeyListCellData::from_slice error: {:?}", e);
//             return Err(Error::InvalidWitness);
//         },
//     };
//     let mut payload = Vec::new();
//     let keys_num = key_list.keys().len();
//     if pk_idx >= keys_num {
//         return Err(Error::InvalidWitness);
//     }
//     match key_list.keys().get(pk_idx) {
//         None => {
//             return Err(Error::InvalidWitness);
//         }
//         Some(k) => { payload.extend_from_slice(k.as_slice())}
//     }
//     Ok(payload)
// }
// //DeviceKeyListConfigCell parse
// #[allow(dead_code)]
// pub fn get_payload_by_pk_idx(pk_idx: usize) -> Result<Vec<u8>, Error> {
//     //check if device key list cell exists in inputs
//     //todo2: need hash to check if the
//     //todo2 add check if device key list cell exists in outputs
//     let in_inputs = false;
//
//     if in_inputs { //data_type_1 DeviceKeyListEntityData
//         let witness = get_witness(&DataType::DeviceKeyListEntityData)?;
//         let data = match Data::from_slice(&witness) {
//             Ok(v) => v,
//             Err(e) => {
//                 debug_log!("Data::from_slice error: {:?}", e);
//                 return Err(Error::InvalidWitness);
//             },
//         };
//         //let mut payload = Vec::new();
//         let data_entity_opt = data.old();
//         if data_entity_opt.is_none() {
//            return Err(Error::InvalidWitness);
//         }
//         let data_entity = match DataEntity::from_slice(&data_entity_opt.as_slice()){
//             Ok(v) => v,
//             Err(e) => {
//                 debug_log!("DataEntity::from_slice error: {:?}", e);
//                 return Err(Error::InvalidWitness);
//             },
//         };
//         get_pk_by_id_in_key_list(&data_entity.entity().raw_data(), pk_idx)
//
//     }else { //data_type_2 DeviceKeyListCellData
//         let witness = get_witness(&DataType::DeviceKeyListCellData)?;
//         get_pk_by_id_in_key_list(&witness, pk_idx)
//
//     }
//     // let witness = get_witness(&DataType::DeviceKeyListCellData)?;
//     // let mut payload = Vec::new();
//     // let mut offset = 0;
//     // while offset < witness.len() {
//     //     let pk_len = witness[offset] as usize;
//     //     offset += 1;
//     //     if pk_len == 0 {
//     //         return Err(Error::InvalidWitness);
//     //     }
//     //     if offset + pk_len > witness.len() {
//     //         return Err(Error::InvalidWitness);
//     //     }
//     //     if pk_idx == 0 {
//     //         payload.extend_from_slice(&witness[offset..offset + pk_len]);
//     //         break;
//     //     }
//     //     offset += pk_len;
//     // }
//     // Ok(payload)
// }

//todo2 add subaccount support
