use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::convert::{TryFrom, TryInto};
use core::mem::size_of_val;

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::{Unpack};
use ckb_std::error::SysError;
use ckb_std::high_level;
use das_core::constants::{LockScript, ScriptHashType, ScriptType};
use das_core::error::{Error, ErrorCode, ScriptError};
use das_core::types::LockScriptTypeIdTable;
use das_core::{data_parser, debug, sign_util, util};
use das_core::data_parser::das_lock_args::get_manager_lock_args;
use das_core::util::hex_string;
use das_dynamic_libs::{load_2_methods, new_context};
use das_dynamic_libs::sign_lib::SignLib;
use das_types::constants::{always_success_lock, das_lock, multisign_lock, signhash_lock, Action, DasLockType, DataType, LockRole, TypeScript, ActionParams};
use das_types::data_parser::das_lock_args::get_owner_lock_args;
use das_types::packed as das_packed;
use das_types::packed::{Bytes, HashReader, Reader};
use eip712::eip712::{TypedDataV4, Value};
use eip712::util::{
    to_doge_address, to_full_address, to_semantic_capacity, to_short_address, to_tron_address,
};
use eip712::{hash_data, typed_data_v4};
use witness_parser::parsers::v1::witness_parser::WitnessesParser;
use witness_parser::traits::WitnessQueryable;
const DATA_OMIT_SIZE: usize = 20;
const PARAM_OMIT_SIZE: usize = 10;

pub fn verify_eip712_hashes(
    parser: &mut WitnessesParser,
    tx_to_das_message: fn(parser: &mut WitnessesParser) -> Result<String, Box<dyn ScriptError>>,
) -> Result<(), Box<dyn ScriptError>> {
    let das_action = parser.action;
    let required_role_opt = util::get_action_required_role(das_action);
    let das_lock = das_lock();
    let das_lock_reader = das_lock.as_reader();
    let mut i = match das_action {
        // In buy_account transaction, the inputs[0] and inputs[1] is belong to sellers, because buyers have paid enough, so we do not need
        // their signature here.
        Action::BuyAccount => 2,
        // In accept_offer transaction, the inputs[0] is belong to buyer, because it is seller to send this transaction for accepting offer,
        // so we do not need the buyer's signature here.
        Action::AcceptOffer => 1,
        Action::BidExpiredAccountDutchAuction => {
            //todo: Maybe replace it with an all-0 check
            let dp_cell_type_id = get_type_id(TypeScript::DPointCellType);
            let dp_cell_type_id_reader = HashReader::from_slice(dp_cell_type_id.as_slice())
                .expect("HashReader::from_slice failed");

            let input_dp_cells = util::find_cells_by_type_id(
                ScriptType::Type,
                dp_cell_type_id_reader,
                Source::Input,
            )?;

            //get first input dpcell lock args
            let input_first_dp_cell = input_dp_cells[0];
            let first_dp_cell_lock_args =
                high_level::load_cell_lock_hash(input_first_dp_cell, Source::Input)?;
            let account_cell_lock_args = high_level::load_cell_lock_hash(0, Source::Input)?;
            if first_dp_cell_lock_args == account_cell_lock_args {
                0
            } else {
                1
            }
            //get account cell lock args
        }
        _ => 0,
    };
    let mut input_groups_idxs: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    let mut payload_map: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    loop {
        let ret = high_level::load_cell_lock(i, Source::Input);
        match ret {
            Ok(lock) => {
                let lock_reader = lock.as_reader();
                // Only take care of inputs with das-lock
                if util::is_type_id_equal(das_lock_reader.into(), lock_reader) {
                    let args = lock_reader.args().raw_data().to_vec();
                    let type_of_args = if required_role_opt.is_some()
                        && required_role_opt == Some(LockRole::Manager)
                    {
                        data_parser::das_lock_args::get_manager_type(lock_reader.args().raw_data())
                    } else {
                        data_parser::das_lock_args::get_owner_type(lock_reader.args().raw_data())
                    };
                    if type_of_args != DasLockType::ETHTypedData as u8 {
                        debug!(
                            "Inputs[{}] is not the address type supporting EIP712, skip verification for hash.",
                            i
                        );
                    } else {
                        input_groups_idxs.entry(args.to_vec()).or_default().push(i);

                        let payload = match parser.action_params {
                            ActionParams::Role(r) => {
                                match r {
                                    LockRole::Owner => {
                                        get_owner_lock_args(args.as_slice()).expect("get_owner_lock_args failed").to_vec()

                                    },
                                    LockRole::Manager => {
                                        get_manager_lock_args(args.as_slice()).to_vec()

                                    }
                                }
                            }
                            _ => {
                                get_owner_lock_args(args.as_slice()).expect("get_owner_lock_args failed").to_vec()
                            }
                        };
                        payload_map.entry(payload).or_default().push(i);

                    }
                }
            }
            Err(SysError::IndexOutOfBound) => {
                break;
            }
            Err(err) => {
                return Err(Error::<ErrorCode>::from(err).into());
            }
        }

        i += 1;
    }

    debug!("input_groups_idxs = {:?}", input_groups_idxs);
    if input_groups_idxs.is_empty() {
        debug!("There is no cell in inputs has das-lock with correct type byte, skip checking hashes in witnesses ...");
    } else {
        debug!("Check if hashes of typed data in witnesses is correct ...");

        #[cfg(debug_assertions)]
        {
            for (k,v ) in input_groups_idxs.clone() {
                debug!("input_groups_idxs key = {}, value = {:?}", hex_string(k.as_slice()), v);
            }
        }

        let (digest_and_hash, eip712_chain_id) = tx_to_digest(input_groups_idxs)?;

        let mut typed_data = tx_to_eip712_typed_data(parser, eip712_chain_id, tx_to_das_message)?;
        let mut sign_lib = SignLib::new();
        let mut eth_context = new_context!();

        let code_hash = if cfg!(feature = "testnet"){
            decode_hex("eth testnet type id", "6d0f4c38ae82383c619b9752ed8140019aa49128e39d48b271239a668c40a174")
        }else {
            decode_hex("eth mainnet type id", "6bbd5ca9bbdbe9a03f51329b2c6d06017ee2ae20546f724f70f79b8922a7d5b1")
        };

        let hash_type = ScriptHashType::Type;
        let size = size_of_val(&eth_context);
        let lib = eth_context.load_with_offset(code_hash.as_slice(), hash_type, 0, size)
            .map_err(|_| ErrorCode::EIP712SignatureError)?;
        sign_lib.eth = load_2_methods!(lib);

        for index in digest_and_hash.keys() {
            let item = digest_and_hash.get(index).unwrap();
            let digest = util::hex_string(&item.digest);

            typed_data.digest(digest.clone());
            let expected_hash = hash_data(&typed_data).unwrap(); //expected_hash is calculated from json

            debug!(
                "Calculated hash of EIP712 typed data with digest.(digest: 0x{}, hash: 0x{})",
                digest,
                hex_string(&expected_hash)
            );

            //call sign lib to verify signature
            let signature_copy = item.signature.as_ref().to_vec();
            let payload_copy = get_payload_by_index(payload_map.clone(), index)?;

            let signature = util::hex_string(&item.signature);
            let typed_data_hash = util::hex_string(&item.typed_data_hash);

            debug!("Prepare to validate signature, signature: 0x{}, typed_data_hash: 0x{}, payload: 0x{}",
                signature, typed_data_hash, util::hex_string(&payload_copy));

            let type_ = 1;
            match sign_lib.validate(
                DasLockType::ETHTypedData,
                type_,
                expected_hash,
                signature_copy,
                payload_copy,
            ) {
                Ok(_) => {
                    debug!("SignLib::validate success");
                }
                Err(err) => {
                    debug!("SignLib::validate failed, err: {:?}", err);
                    return Err(Box::from(ErrorCode::EIP712SignatureError));
                }
            }

            // CAREFUL We need to skip the final verification here because transactions are often change when developing, that will break all tests contains EIP712 verification.
            // if cfg!(not(feature = "dev")) {
            //     das_assert!(
            //         &item.typed_data_hash == expected_hash.as_slice(),
            //         ErrorCode::EIP712SignatureError,
            //         "Inputs[{}] The hash of EIP712 typed data is mismatched.(current: 0x{}, expected: 0x{})",
            //         index,
            //         util::hex_string(&item.typed_data_hash),
            //         util::hex_string(&expected_hash)
            //     );
            // }
        }
    }

    Ok(())
}
fn get_payload_by_index(payload_map: BTreeMap<Vec<u8>, Vec<usize>>, idx: &usize) -> Result<Vec<u8>, Box<dyn ScriptError>> {
    payload_map.into_iter()
        .find(|(_, v)| v.get(0) == Some(idx))
        .map(|(k, _)| k)
        .ok_or(Box::from(ErrorCode::EIP712SignatureError))
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

pub fn verify_eip712_hashes_if_has_das_lock(
    parser: &mut WitnessesParser,
    tx_to_das_message: fn(parser: &mut WitnessesParser) -> Result<String, Box<dyn ScriptError>>,
) -> Result<(), Box<dyn ScriptError>> {
    let das_lock = das_lock();
    let input_cells = util::find_cells_by_type_id(
        ScriptType::Lock,
        das_lock.as_reader().code_hash().into(),
        Source::Input,
    )?;
    debug!("input_cells that use das-lock = {:?}", input_cells);

    if input_cells.len() > 0 {
        verify_eip712_hashes(parser, tx_to_das_message)
    } else {
        Ok(())
    }
}

struct DigestAndHash {
    digest: [u8; 32],
    signature: [u8; 65],
    typed_data_hash: [u8; 32],
}
fn tx_to_digest(
    input_groups_idxs: BTreeMap<Vec<u8>, Vec<usize>>,
) -> Result<(BTreeMap<usize, DigestAndHash>, Vec<u8>), Box<dyn ScriptError>> {
    let mut ret: BTreeMap<usize, DigestAndHash> = BTreeMap::new();

    let mut eip712_chain_id = Vec::new();
    for (_key, input_group_idxs) in input_groups_idxs {
        let init_witness_idx = input_group_idxs[0];
        let (digest, signature, typed_data_hash, chain_id, _) =
            sign_util::get_eip712_digest(input_group_idxs)?;
        ret.insert(
            init_witness_idx,
            DigestAndHash {
                digest,
                signature,
                typed_data_hash,
            },
        );

        if eip712_chain_id.is_empty() {
            eip712_chain_id = chain_id;
        }
    }

    Ok((ret, eip712_chain_id))
}

pub fn tx_to_eip712_typed_data(
    parser: &mut WitnessesParser,
    chain_id: Vec<u8>,
    tx_to_das_message: fn(parser: &mut WitnessesParser) -> Result<String, Box<dyn ScriptError>>,
) -> Result<TypedDataV4, Box<dyn ScriptError>> {
   
    let plain_text = tx_to_das_message(parser)?;
    let tx_action = to_typed_action(parser)?;

    let (inputs_capacity, inputs) = to_typed_cells(parser, Source::Input)?;
    let (outputs_capacity, outputs) = to_typed_cells(parser, Source::Output)?;

    let inputs_capacity_str = to_semantic_capacity(inputs_capacity);
    let outputs_capacity_str = to_semantic_capacity(outputs_capacity);

    let fee_str = if outputs_capacity <= inputs_capacity {
        to_semantic_capacity(inputs_capacity - outputs_capacity)
    } else {
        format!(
            "-{}",
            to_semantic_capacity(outputs_capacity - inputs_capacity)
        )
    };

    let chain_id_num = u64::from_be_bytes(chain_id.try_into().unwrap()).to_string();

    let typed_data = typed_data_v4!({
        types: {
            EIP712Domain: {
                chainId: "uint256",
                name: "string",
                verifyingContract: "address",
                version: "string"
            },
            Action: {
                action: "string",
                params: "string"
            },
            Cell: {
                capacity: "string",
                lock: "string",
                type: "string",
                data: "string",
                extraData: "string"
            },
            Transaction: {
                DAS_MESSAGE: "string",
                inputsCapacity: "string",
                outputsCapacity: "string",
                fee: "string",
                action: "Action",
                inputs: "Cell[]",
                outputs: "Cell[]",
                digest: "bytes32"
            }
        },
        primaryType: "Transaction",
        domain: {
            chainId: chain_id_num,
            name: "da.systems",
            verifyingContract: "0x0000000000000000000000000000000020210722",
            version: "1"
        },
        message: {
            DAS_MESSAGE: plain_text,
            inputsCapacity: inputs_capacity_str,
            outputsCapacity: outputs_capacity_str,
            fee: fee_str,
            action: tx_action,
            inputs: inputs,
            outputs: outputs,
            digest: ""
        }
    });

    #[cfg(debug_assertions)]
    // WARNING The keys in output may be in wrong camelcase, it is OK, it is just cause by the `debug!` macro
    // print all keys base on the struct in Rust.
    debug!("Extracted typed data: {}", typed_data);

    Ok(typed_data)
}

pub fn to_semantic_address(
    lock_reader: das_packed::ScriptReader,
    role: LockRole,
) -> Result<String, Box<dyn ScriptError>> {
    let address;
    let hash_type: Vec<u8> = lock_reader.hash_type().as_slice().to_vec();
    let code_hash = lock_reader.code_hash().raw_data().to_vec();
    let args = lock_reader.args().raw_data().to_vec();

    match get_lock_script_type(lock_reader) {
        Some(LockScript::DasLock) => {
            // If this is a das-lock, convert it to address base on args.
            let args_in_bytes = lock_reader.args().raw_data();
            let das_lock_type = DasLockType::try_from(args_in_bytes[0])
                .map_err(|_| ErrorCode::EIP712SerializationError)?;
            match das_lock_type {
                DasLockType::CKBSingle => {
                    let pubkey_hash = if role == LockRole::Owner {
                        data_parser::das_lock_args::get_owner_lock_args(args_in_bytes).to_vec()
                    } else {
                        data_parser::das_lock_args::get_manager_lock_args(args_in_bytes).to_vec()
                    };

                    address = format!(
                        "{}",
                        to_short_address(vec![0], pubkey_hash).map_err(|_| Error::new(
                            ErrorCode::EIP712SematicError,
                            String::new()
                        ))?
                    )
                }
                DasLockType::ETH | DasLockType::ETHTypedData => {
                    let pubkey_hash = if role == LockRole::Owner {
                        data_parser::das_lock_args::get_owner_lock_args(args_in_bytes).to_vec()
                    } else {
                        data_parser::das_lock_args::get_manager_lock_args(args_in_bytes).to_vec()
                    };
                    address = format!("0x{}", util::hex_string(&pubkey_hash));
                }
                DasLockType::TRON | DasLockType::Doge => {
                    let pubkey_hash = if role == LockRole::Owner {
                        data_parser::das_lock_args::get_owner_lock_args(args_in_bytes)
                    } else {
                        data_parser::das_lock_args::get_manager_lock_args(args_in_bytes)
                    };

                    address = match das_lock_type {
                        DasLockType::TRON => format!("{}", to_tron_address(pubkey_hash)),
                        DasLockType::Doge => format!("{}", to_doge_address(pubkey_hash)),
                        _ => unreachable!(),
                    };
                }
                _ => {
                    address = format!(
                        "{}",
                        to_full_address(code_hash, hash_type, args).map_err(|_| Error::new(
                            ErrorCode::EIP712SematicError,
                            String::new()
                        ))?
                    );
                }
            }
        }
        Some(LockScript::Secp256k1Blake160SignhashLock) => {
            // If this is a secp256k1_blake160_signhash_all lock, convert it to short address.
            let args = lock_reader.args().raw_data().to_vec();
            address = format!(
                "{}",
                to_short_address(vec![0], args)
                    .map_err(|_| Error::new(ErrorCode::EIP712SematicError, String::new()))?
            )
        }
        _ => {
            // If this is a other lock, convert it to full address.
            address = format!(
                "{}",
                to_full_address(code_hash, hash_type, args)
                    .map_err(|_| Error::new(ErrorCode::EIP712SematicError, String::new()))?
            );
        }
    }

    // debug!("lock: {} => address: {}", lock_reader, address);
    Ok(address)
}

fn to_typed_action(parser: &WitnessesParser) -> Result<Value, Box<dyn ScriptError>> {
    let action = String::from_utf8(parser.get_action_data().action().raw_data().to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;
    let mut params = Vec::new();
    let action_params = parser.action_data.params();

    //todo: replace with parser.action_params
    if action_params.len() > 10 {
        params.push(format!(
            "0x{}...",
            util::hex_string(&action_params.raw_data()[..PARAM_OMIT_SIZE])
        ));
    } else if action_params.raw_data() != Bytes::default().raw_data() {
        params.push(format!("0x{}", util::hex_string(&action_params.raw_data())));
    }

    Ok(typed_data_v4!(@object {
        action: action,
        params: params.join(",")
    }))
}


pub fn get_type_id(type_script: TypeScript) -> Vec<u8> {
    let parser = WitnessesParser::get_instance();
    parser
        .get_type_id(type_script.clone())
        .map_err(|err| {
            debug!(
                "Error: witness parser get type id of {:?} failed, {:?}",
                &type_script, err
            );
            das_core::error::ErrorCode::WitnessDataDecodingError
        })
        .unwrap()
        .to_vec()
    //HashReader::from_slice(type_id.as_slice()).expect("HashReader::from_slice failed")
}
fn to_typed_cells(
    parser: &mut WitnessesParser,
    source: Source,
) -> Result<(u64, Value), Box<dyn ScriptError>> {
    let mut i = 0;
    let mut cells: Vec<Value> = Vec::new();
    let mut total_capacity = 0;
    loop {
        let ret = high_level::load_cell(i, source);
        match ret {
            Ok(cell) => {
                let type_opt = cell.type_().to_opt();
                let data_in_bytes = util::load_cell_data(i, source)?;
                let capacity_in_shannon = cell.capacity().unpack();

                total_capacity += capacity_in_shannon;

                // Skip NormalCells which has no type script.
                if type_opt.is_none() {
                    i += 1;
                    continue;
                }

                let capacity = to_semantic_capacity(capacity_in_shannon);
                let lock = to_typed_script(
                    ScriptType::Lock,
                    das_packed::ScriptReader::from(cell.lock().as_reader()),
                );

                macro_rules! extract_and_push {
                    ($cell_data_to_str:ident, $cell_witness_to_str:ident, $data_type:expr, $type_:expr) => {
                        let data = $cell_data_to_str(&data_in_bytes)?;
                        let extra_data = $cell_witness_to_str(parser, &data_in_bytes[..32], $data_type, i, source)?;
                        cells.push(
                            typed_data_v4!(@object {
                                capacity: capacity,
                                lock: lock,
                                type: $type_,
                                data: data,
                                extraData: extra_data
                            })
                        )
                    };
                }

                match type_opt {
                    Some(type_script) => {
                        let type_script_reader =
                            das_packed::ScriptReader::from(type_script.as_reader());
                        // Skip BalanceCells which has the type script named balance-cell-type.
                        let balance_cell_type_id = get_type_id(TypeScript::BalanceCellType);
                        let balance_cell_type_id_reader =
                            HashReader::from_slice(balance_cell_type_id.as_slice())
                                .expect("HashReader::from_slice failed");
                        if util::is_reader_eq(
                            type_script_reader.code_hash(),
                            balance_cell_type_id_reader,
                        ) {
                            i += 1;
                            continue;
                        }

                        let type_ = to_typed_script(
                            ScriptType::Type,
                            das_packed::ScriptReader::from(type_script.as_reader()),
                        );
                        let account_cell_type_id = get_type_id(TypeScript::AccountCellType);
                        let account_cell_type_id_reader =
                            HashReader::from_slice(account_cell_type_id.as_slice())
                                .expect("HashReader::from_slice failed");

                        match type_script_reader.code_hash() {
                            // Handle cells which with DAS type script.
                            x if util::is_reader_eq(x, account_cell_type_id_reader) => {
                                extract_and_push!(
                                    to_semantic_account_cell_data,
                                    to_semantic_account_witness,
                                    DataType::AccountCellData,
                                    type_
                                );
                            }
                            // Handle cells which with unknown type script.
                            _ => {
                                let data = to_typed_common_data(&data_in_bytes);
                                cells.push(typed_data_v4!(@object {
                                    capacity: capacity,
                                    lock: lock,
                                    type: type_,
                                    data: data,
                                    extraData: ""
                                }));
                            }
                        }
                    }
                    // Handle cells which has no type script.
                    _ => {
                        let data = to_typed_common_data(&data_in_bytes);
                        cells.push(typed_data_v4!(@object {
                            capacity: capacity,
                            lock: lock,
                            type: "",
                            data: data,
                            extraData: ""
                        }));
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => {
                break;
            }
            Err(err) => {
                return Err(Error::<ErrorCode>::from(err).into());
            }
        }

        i += 1;
    }

    Ok((total_capacity, Value::Array(cells)))
}
fn get_lock_script_type(script_reader: das_packed::ScriptReader) -> Option<LockScript> {
    let lock_type_id_table = LockScriptTypeIdTable {
        always_success: always_success_lock().clone(),
        das_lock: das_lock().clone(),
        secp256k1_blake160_signhash_all: signhash_lock().clone(),
        secp256k1_blake160_multisig_all: multisign_lock().clone(),
    };
    match script_reader {
        x if util::is_type_id_equal(
            lock_type_id_table.always_success.as_reader().into(),
            x.into(),
        ) =>
        {
            Some(LockScript::AlwaysSuccessLock)
        }
        x if util::is_type_id_equal(lock_type_id_table.das_lock.as_reader().into(), x.into()) => {
            Some(LockScript::DasLock)
        }
        x if util::is_type_id_equal(
            lock_type_id_table
                .secp256k1_blake160_signhash_all
                .as_reader()
                .into(),
            x.into(),
        ) =>
        {
            Some(LockScript::Secp256k1Blake160SignhashLock)
        }
        x if util::is_type_id_equal(
            lock_type_id_table
                .secp256k1_blake160_multisig_all
                .as_reader()
                .into(),
            x.into(),
        ) =>
        {
            Some(LockScript::Secp256k1Blake160MultisigLock)
        }
        _ => None,
    }
}
fn get_type_script_type(script_reader: das_packed::ScriptReader) -> Option<TypeScript> {
    let apply_register_cell_type_id = get_type_id(TypeScript::ApplyRegisterCellType);
    let account_cell_type_id = get_type_id(TypeScript::AccountCellType);
    let account_sale_cell_type_id = get_type_id(TypeScript::AccountSaleCellType);
    let account_auction_cell_type_id = get_type_id(TypeScript::AccountAuctionCellType);
    let balance_cell_type_id = get_type_id(TypeScript::BalanceCellType);
    let income_cell_type_id = get_type_id(TypeScript::IncomeCellType);
    let offer_cell_type_id = get_type_id(TypeScript::OfferCellType);
    let pre_account_cell_type_id = get_type_id(TypeScript::PreAccountCellType);
    let proposal_cell_type_id = get_type_id(TypeScript::ProposalCellType);
    let reverse_record_cell_type_id = get_type_id(TypeScript::ReverseRecordCellType);
    let sub_account_cell_type_id = get_type_id(TypeScript::SubAccountCellType);
    let reverse_record_root_cell_type_id = get_type_id(TypeScript::ReverseRecordRootCellType);
    let dpoint_cell_type_id = get_type_id(TypeScript::DPointCellType);
    let config_cell_type_id = get_type_id(TypeScript::ConfigCellType);

    let apply_register_cell_type_id_reader =
        HashReader::from_slice(apply_register_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let account_cell_type_id_reader = HashReader::from_slice(account_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");
    let account_sale_cell_type_id_reader =
        HashReader::from_slice(account_sale_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let account_auction_cell_type_id_reader =
        HashReader::from_slice(account_auction_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let balance_cell_type_id_reader = HashReader::from_slice(balance_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");
    let income_cell_type_id_reader = HashReader::from_slice(income_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");
    let offer_cell_type_id_reader = HashReader::from_slice(offer_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");
    let pre_account_cell_type_id_reader =
        HashReader::from_slice(pre_account_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let proposal_cell_type_id_reader = HashReader::from_slice(proposal_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");
    let reverse_record_cell_type_id_reader =
        HashReader::from_slice(reverse_record_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let sub_account_cell_type_id_reader =
        HashReader::from_slice(sub_account_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let reverse_record_root_cell_type_id_reader =
        HashReader::from_slice(reverse_record_root_cell_type_id.as_slice())
            .expect("HashReader::from_slice failed");
    let dpoint_cell_type_id_reader = HashReader::from_slice(dpoint_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");
    let config_cell_type_id_reader = HashReader::from_slice(config_cell_type_id.as_slice())
        .expect("HashReader::from_slice failed");

    match script_reader.code_hash() {
        x if util::is_reader_eq(x, apply_register_cell_type_id_reader) => {
            Some(TypeScript::ApplyRegisterCellType)
        }
        x if util::is_reader_eq(x, account_cell_type_id_reader) => {
            Some(TypeScript::AccountCellType)
        }
        x if util::is_reader_eq(x, account_sale_cell_type_id_reader) => {
            Some(TypeScript::AccountSaleCellType)
        }
        x if util::is_reader_eq(x, account_auction_cell_type_id_reader) => {
            Some(TypeScript::AccountAuctionCellType)
        }
        x if util::is_reader_eq(x, balance_cell_type_id_reader) => {
            Some(TypeScript::BalanceCellType)
        }
        x if util::is_reader_eq(x, income_cell_type_id_reader) => Some(TypeScript::IncomeCellType),
        x if util::is_reader_eq(x, offer_cell_type_id_reader) => Some(TypeScript::OfferCellType),
        x if util::is_reader_eq(x, pre_account_cell_type_id_reader) => {
            Some(TypeScript::PreAccountCellType)
        }

        x if util::is_reader_eq(x, proposal_cell_type_id_reader) => {
            Some(TypeScript::ProposalCellType)
        }

        x if util::is_reader_eq(x, reverse_record_cell_type_id_reader) => {
            Some(TypeScript::ReverseRecordCellType)
        }
        x if util::is_reader_eq(x, sub_account_cell_type_id_reader) => {
            Some(TypeScript::SubAccountCellType)
        }
        x if util::is_reader_eq(x, reverse_record_root_cell_type_id_reader) => {
            Some(TypeScript::ReverseRecordRootCellType)
        }
        x if util::is_reader_eq(x, dpoint_cell_type_id_reader) => Some(TypeScript::DPointCellType),
        x if util::is_reader_eq(x, config_cell_type_id_reader) => Some(TypeScript::ConfigCellType),

        _ => None,
    }
}
fn to_typed_script(script_type: ScriptType, script: das_packed::ScriptReader) -> String {
    let code_hash = if script_type == ScriptType::Lock {
        match get_lock_script_type(script) {
            Some(LockScript::AlwaysSuccessLock) => String::from("always-success"),
            Some(LockScript::DasLock) => String::from("das-lock"),
            Some(LockScript::Secp256k1Blake160SignhashLock) => String::from("account-cell-type"),
            Some(LockScript::Secp256k1Blake160MultisigLock) => {
                String::from("account-sale-cell-type")
            }
            _ => format!(
                "0x{}...",
                util::hex_string(&script.code_hash().raw_data().as_ref()[0..DATA_OMIT_SIZE])
            ),
        }
    } else {
        match get_type_script_type(script) {
            Some(TypeScript::ApplyRegisterCellType) => String::from("apply-register-cell-type"),
            Some(TypeScript::AccountCellType) => String::from("account-cell-type"),
            Some(TypeScript::AccountSaleCellType) => String::from("account-sale-cell-type"),
            Some(TypeScript::AccountAuctionCellType) => String::from("account-auction-cell-type"),
            Some(TypeScript::BalanceCellType) => String::from("balance-cell-type"),
            Some(TypeScript::ConfigCellType) => String::from("config-cell-type"),
            Some(TypeScript::IncomeCellType) => String::from("income-cell-type"),
            Some(TypeScript::OfferCellType) => String::from("offer-cell-type"),
            Some(TypeScript::PreAccountCellType) => String::from("pre-account-cell-type"),
            Some(TypeScript::ProposalCellType) => String::from("proposal-cell-type"),
            Some(TypeScript::ReverseRecordCellType) => String::from("reverse-record-cell-type"),
            Some(TypeScript::SubAccountCellType) => String::from("sub-account-cell-type"),
            Some(TypeScript::DPointCellType) => String::from("dpoint-cell-type"),
            _ => format!(
                "0x{}...",
                util::hex_string(&script.code_hash().raw_data().as_ref()[0..DATA_OMIT_SIZE])
            ),
        }
    };

    let hash_type = util::hex_string(script.hash_type().as_slice());
    let args_in_bytes = script.args().raw_data();
    let args = if args_in_bytes.len() > DATA_OMIT_SIZE {
        util::hex_string(&args_in_bytes[0..DATA_OMIT_SIZE]) + "..."
    } else {
        util::hex_string(args_in_bytes.as_ref())
    };

    String::new() + &code_hash + ",0x" + &hash_type + ",0x" + &args
}

fn to_typed_common_data(data_in_bytes: &[u8]) -> String {
    if data_in_bytes.len() > DATA_OMIT_SIZE {
        format!(
            "0x{}",
            util::hex_string(&data_in_bytes[0..DATA_OMIT_SIZE]) + "..."
        )
    } else if !data_in_bytes.is_empty() {
        format!("0x{}", util::hex_string(data_in_bytes))
    } else {
        String::new()
    }
}

fn to_semantic_account_cell_data(data_in_bytes: &[u8]) -> Result<String, Box<dyn ScriptError>> {
    let account_in_bytes = data_parser::account_cell::get_account(data_in_bytes);
    let expired_at = data_parser::account_cell::get_expired_at(data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;
    Ok(format!(
        "{{ account: {}, expired_at: {} }}",
        account,
        &expired_at.to_string()
    ))
}

fn to_semantic_account_witness(
    _parser: &mut WitnessesParser,
    _expected_hash: &[u8],
    _data_type: DataType,
    index: usize,
    source: Source,
) -> Result<String, Box<dyn ScriptError>> {
    let account_witness = util::parse_account_cell_witness(index, source)?;
    let account_witness_reader = account_witness.as_reader();
    let status = u8::from(account_witness_reader.status());

    //let record_hash = a.as_reader().records().raw_data();
    let records_hash = util::blake2b_256(account_witness_reader.records().as_slice());

    Ok(format!(
        "{{ status: {}, records_hash: 0x{} }}",
        status,
        util::hex_string(&records_hash)
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    // #[test]
    // fn test_eip712_to_typed_script() {
    //     let account_cell_type_id = das_packed::Hash::from([1u8; 32]);
    //     let table_id_table = das_packed::TypeIdTable::new_builder()
    //         .account_cell(account_cell_type_id.clone())
    //         .build();
    //     let das_lock = das_packed::Script::from(das_lock());
    //     let always_success_lock = das_packed::Script::from(always_success_lock());
    //     let config_cell_type = das_packed::Script::from(config_cell_type());
    //
    //     let account_type_script = das_packed::Script::new_builder()
    //         .code_hash(account_cell_type_id)
    //         .hash_type(das_packed::Byte::new(1))
    //         .args(das_packed::Bytes::default())
    //         .build();
    //
    //     let expected = "account-cell-type,0x01,0x";
    //     let result = to_typed_script(
    //         table_id_table.as_reader(),
    //         config_cell_type.as_reader().code_hash(),
    //         das_lock.as_reader().code_hash(),
    //         always_success_lock.as_reader().code_hash(),
    //         account_type_script.as_reader(),
    //     );
    //     assert_eq!(result, expected);
    //
    //     let other_type_script = das_packed::Script::new_builder()
    //         .code_hash(das_packed::Hash::from([9u8; 32]))
    //         .hash_type(das_packed::Byte::new(1))
    //         .args(das_packed::Bytes::from(vec![10u8; 21]))
    //         .build();
    //
    //     let expected =
    //         "0x0909090909090909090909090909090909090909...,0x01,0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a...";
    //     let result = to_typed_script(
    //         table_id_table.as_reader(),
    //         config_cell_type.as_reader().code_hash(),
    //         das_lock.as_reader().code_hash(),
    //         always_success_lock.as_reader().code_hash(),
    //         other_type_script.as_reader(),
    //     );
    //     assert_eq!(result, expected);
    //
    //     let other_type_script = das_packed::Script::new_builder()
    //         .code_hash(das_packed::Hash::from([9u8; 32]))
    //         .hash_type(das_packed::Byte::new(1))
    //         .args(das_packed::Bytes::from(vec![10u8; 20]))
    //         .build();
    //
    //     let expected = "0x0909090909090909090909090909090909090909...,0x01,0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    //     let result = to_typed_script(
    //         table_id_table.as_reader(),
    //         ScriptType::Type,
    //         other_type_script.as_reader(),
    //     );
    //     assert_eq!(result, expected);
    // }
}
