use crate::error::Error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_constants::Source::Input;
use ckb_std::debug;
use witness_parser::WitnessesParserV1;

use das_core::constants::ScriptType;
use das_core::util;
use das_core::util::{find_only_cell_by_type_id, hex_string};
use das_types::constants::TypeScript;
use das_types::mixer::AccountCellDataMixer;
use das_types::packed::{AccountApprovalTransfer, Hash};
use das_types::prelude::Entity;
use witness_parser::traits::WitnessQueryable;

pub fn get_type_id_by_type_script(type_script: TypeScript) -> Result<Vec<u8>, Error> {
    debug!("get type id of {:?}", &type_script);
    let parser = WitnessesParserV1::get_instance();
    if !parser.is_inited() {
        parser
            .init()
            .map_err(|err| {
                debug!("Error: witness parser init failed, {:?}", err);
                das_core::error::ErrorCode::WitnessDataDecodingError
            })
            .unwrap();
        debug!("WitnessesParserV1::init() success");
    } else {
        debug!("WitnessesParserV1::init() already initialized");
    }
    debug!("WitnessesParserV1::get_instance() success");

    let type_id = parser
        .get_type_id(type_script.clone())
        .map_err(|err| {
            debug!(
                "Error: witness parser get type id of {:?} failed, {:?}",
                &type_script, err
            );
            das_core::error::ErrorCode::WitnessDataDecodingError
        })
        .unwrap();

    debug!("{:?} type id is {:?}", &type_script, hex_string(&type_id));

    // let idx = match type_script {
    //     TypeScript::AccountCellType => {0}
    //     TypeScript::SubAccountCellType => {1}
    //     TypeScript::DPointCellType => {2}
    //     TypeScript::EIP712Lib => {3}
    //     TypeScript::BalanceCellType => {4}
    //     _ => {
    //         unreachable!();
    //     }
    // };
    // let type_id = crate::constants::decode_hex("type id", TYPE_ID_TABLE_TYPE[idx]);
    //
    let type_id_vec = type_id.to_vec();
    Ok(type_id_vec)
}
//Some wrappers for get_type_id_by_type_script
//todo: remove these wrappers
pub fn get_balance_cell_type_id() -> Result<Vec<u8>, Error> {
    get_type_id_by_type_script(TypeScript::BalanceCellType)
}
pub fn get_sub_account_cell_type_id() -> Result<Vec<u8>, Error> {
    get_type_id_by_type_script(TypeScript::SubAccountCellType)
}

pub fn get_account_cell_type_id() -> Result<Vec<u8>, Error> {
    get_type_id_by_type_script(TypeScript::AccountCellType)
}

pub fn get_dpoint_cell_type_id() -> Result<Vec<u8>, Error> {
    get_type_id_by_type_script(TypeScript::DPointCellType)
}
pub fn get_reverse_record_root_cell_type_id() -> Result<Vec<u8>, Error> {
    get_type_id_by_type_script(TypeScript::ReverseRecordRootCellType)
}
pub fn get_first_account_cell_index() -> Result<usize, Error> {
    let account_cell_type_id = get_account_cell_type_id()?;
    let index = find_only_cell_by_type_id(
        ScriptType::Type,
        Hash::from_slice(account_cell_type_id.as_slice()).unwrap().as_reader(),
        Source::Input,
    )?;
    Ok(index)
}

pub fn get_input_approval() -> Result<AccountApprovalTransfer, Error> {
    let account_cell_witness = get_account_cell_witness()?;
    let account_cell_witness_reader = match account_cell_witness.as_reader().try_into_latest() {
        Ok(reader) => reader,
        Err(err) => {
            debug!("Decoding AccountCell.witness failed: {}", err);
            return Err(Error::WitnessError);
        }
    };

    let input_approval_params =
        AccountApprovalTransfer::from_compatible_slice(account_cell_witness_reader.approval().params().raw_data())
            .map_err(|e| {
                debug!("Decoding AccountCell.witness.approval.params failed: {}", e);
                return Error::WitnessError;
            })
            .unwrap();
    //let input_approval_reader = input_approval_params.as_reader();
    Ok(input_approval_params)
}

pub fn get_account_cell_witness() -> Result<Box<dyn AccountCellDataMixer>, Error> {
    debug!("get_account_cell_witness");
    let account_cell_index = 0;
    let account_cell_source = Input;

    Ok(
        match util::parse_account_cell_witness(account_cell_index, account_cell_source) {
            Ok(witness) => witness,
            Err(err) => {
                debug!("WitnessParserV1 get_entity_by_cell_meta error: {:?}", err);
                return Err(Error::WitnessError);
            }
        },
    )
}

pub fn init_witness_parser() -> Result<(), Error> {
    let parser = WitnessesParserV1::get_instance();
    if !parser.is_inited() {
        parser
            .init()
            .map_err(|err| {
                debug!("Error: witness parser init failed, {:?}", err);
                das_core::error::ErrorCode::WitnessDataDecodingError
            })
            .unwrap();
        debug!("WitnessesParser initialization successful.");
    }
    Ok(())
}
