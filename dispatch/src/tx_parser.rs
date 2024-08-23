use crate::constants::get_type_id;
use crate::error::Error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_constants::Source::{CellDep, Input};
use ckb_std::ckb_types::prelude::Reader;
use ckb_std::debug;
use config::constants::FieldKey;
use witness_parser::WitnessesParserV1;

use crate::structures::{AlgId, LockArgs, SignInfo};
use das_core::constants::ScriptType;
use das_core::traits::Blake2BHash;
use das_core::util;
use das_core::util::{find_only_cell_by_type_id, hex_string};
use das_core::witness_parser::device_key_list::get_device_key_list_cells;
use das_types::constants::{DataType};
use das_types::mixer::AccountCellDataMixer;
use das_types::packed::{self as das_packed};
use das_types::packed::{AccountApprovalTransfer};
use das_types::prelude::Entity;
use witness_parser::traits::WitnessQueryable;
use witness_parser::types::CellMeta;

pub fn get_first_account_cell_index() -> Result<usize, Error> {
    let index = find_only_cell_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs)?,
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

fn find_device_key_list_cells() -> (Option<Vec<usize>>, bool) {
    let device_key_list_type_id = get_type_id(FieldKey::DeviceKeyListCellTypeArgs)
        .map_err(|e| {
            debug!("Error: get_type_id_by_type_script failed, {:?}", e);
            return (Option::<Vec<usize>>::None, false);
        })
        .unwrap();

    debug!(
        "device_key_list_type_id = {:?}",
        hex_string(device_key_list_type_id.as_slice())
    );

    let find_cell_in_inputs;
    let cells = {
        let cells_inputs = get_device_key_list_cells(device_key_list_type_id.as_slice(), Input);
        if cells_inputs.is_empty() {
            debug!("No DeviceKeyListCell in inputs.");
            find_cell_in_inputs = false;
            let cells_deps = get_device_key_list_cells(device_key_list_type_id.as_slice(), CellDep);
            if cells_deps.is_empty() {
                debug!("No DeviceKeyListCell in cell_deps.");
                return (None, false);
            } else {
                debug!("Found DeviceKeyListCell in cell_deps");
                cells_deps
            }
        } else {
            debug!("Found DeviceKeyListCell in inputs");
            find_cell_in_inputs = true;
            cells_inputs
        }
    };
    #[cfg(debug_assertions)]
    {
        debug!("device key list cell index list:");
        for i in 0..cells.len() {
            debug!("   cell index = {}", cells[i]);
        }
    }
    (Some(cells), find_cell_in_inputs)
}
pub fn get_webauthn_lock_args_from_cell(lock_args: &LockArgs, sign_info: &SignInfo) -> Result<LockArgs, Error> {
    if lock_args.alg_id != AlgId::WebAuthn {
        return Ok(lock_args.clone());
    }

    let pk_idx = sign_info.signature[1];
    debug!("pk_idx = {}", pk_idx);
    match pk_idx {
        255 => {
            return Ok(lock_args.clone());
        }
        0..=9 => {}
        _ => {
            return Err(Error::InvalidPubkeyIndex);
        }
    }
    //get DeviceKeyList cell from inputs, if you cannot find, get it from cell_deps
    let (cells, find_cell_in_inputs) = find_device_key_list_cells();
    let cells = match cells {
        Some(cells) => cells,
        None => {
            debug!("Cannot find DeviceKeyListCell neither in inputs nor in cell_deps.");
            return Err(Error::InvalidTransactionStructure);
        }
    };

    let witness_parser = WitnessesParserV1::get_instance();

    //it can be found in inputs or cell_deps, but we only use the first one
    let dk_cell_meta = CellMeta {
        index: cells[0],
        source: if find_cell_in_inputs {
            das_types::constants::Source::Input
        } else {
            das_types::constants::Source::CellDep
        },
    };

    let dk_list = if find_cell_in_inputs {
        let device_key_list_cell_data = witness_parser
            .get_entity_by_cell_meta::<das_packed::DeviceKeyListCellData>(dk_cell_meta)
            .map_err(|e| {
                debug!("Error: parse DeviceKeyListEntityData failed, {:?}", e);
                return Error::WitnessStructureError;
            })?;
        debug!("dk_list_cell_data = {:?}", device_key_list_cell_data);
        let device_key_list = device_key_list_cell_data.keys();
        device_key_list
    } else {
        let mut witness_idx = 0;
        for i in 0.. {
            match witness_parser.get_witness_meta_by_index(i) {
                Ok(witness_meta) => {
                    debug!(
                        "witness_meta DataType = {:?}, index = {}",
                        witness_meta.data_type, witness_meta.index
                    );
                    if witness_meta.data_type == DataType::DeviceKeyListCellData {
                        witness_idx = i;
                        break;
                    }
                }
                Err(e) => {
                    debug!("Error: parse DeviceKeyListCellData failed, {:?}", e);
                    return Err(Error::WitnessStructureError);
                }
            };
        }

        let witness = witness_parser.get_raw_by_index(witness_idx).map_err(|e| {
            debug!("Error: parse DeviceKeyListCellData failed, {:?}", e);
            return Error::WitnessStructureError;
        })?;
        debug!("witness = {}", hex_string(witness.as_slice()));

        let entity = &witness.as_slice()[7..];
        let device_key_list_cell_data = das_types::packed::DeviceKeyListCellData::from_slice(entity).map_err(|e| {
            debug!("Error: parse DeviceKeyListCellData failed, {:?}", e);
            return Error::WitnessStructureError;
        })?;
        let device_key_list = device_key_list_cell_data.keys();
        let dk_list_hash = device_key_list_cell_data.blake2b_256();

        debug!("dk_cell_meta = {:?}", dk_cell_meta);
        let cell_data_hash =
            witness_parser::util::load_cell_data(dk_cell_meta.index, dk_cell_meta.source).map_err(|e| {
                debug!("Error: load cell data failed, {:?}", e);
                return Error::WitnessStructureError;
            })?;

        if cell_data_hash.len() != 32 {
            debug!("Error: cell data hash length is not 32, {:?}", cell_data_hash.len());
            return Err(Error::WitnessStructureError);
        }

        //dk list hash should equal to the cell data
        if dk_list_hash != cell_data_hash[0..32] {
            debug!("Error: DeviceKeyListCellData hash not equal to the cell data hash");
            return Err(Error::WitnessStructureError);
        }
        device_key_list
    };

    let device_key = dk_list.get(pk_idx as usize).ok_or(Error::WitnessStructureError)?;
    debug!("device_key = {:?}", device_key);

    debug!(
        "payload(include sub_alg_id) = {}",
        hex_string(&device_key.as_reader().as_slice()[1..])
    );

    let mut lock_args = lock_args.clone();
    lock_args.payload = (device_key.as_reader().as_slice()[1..]).to_vec();
    Ok(lock_args)
}
