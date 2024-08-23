use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use ckb_std::ckb_constants::Source;
use ckb_std::{debug, high_level};
use core::ops::Index;
use das_core::constants::{OracleCellType, ScriptType, ACCOUNT_SUFFIX};
use das_core::error::{ErrorCode, ReverseRecordRootCellErrorCode, ScriptError};
use das_core::util::{find_only_cell_by_type_id, hex_string};
use das_core::witness_parser::reverse_record::{ReverseRecordWitness, ReverseRecordWitnessesParser};
use das_core::witness_parser::sub_account::{SubAccountMintSignWitness, SubAccountWitnessesParser};
use das_core::witness_parser::webauthn_signature::WebAuthnSignature;
use das_core::{code_to_error, data_parser, sign_util, util, verifiers};
use das_dynamic_libs::error::Error as DasDynamicLibError;
use das_dynamic_libs::sign_lib::SignLib;
use das_dynamic_libs::{
    load_2_methods, load_3_methods, load_and_configure_lib, load_lib, log_loading, new_context,
};
use das_types::constants::{das_lock};
use das_types::constants::{DasLockType, LockRole};
use das_types::packed::{Reader, ScriptReader};
use config::constants::FieldKey;

use crate::constants::{get_type_id};
use crate::dlopen::{dispatch, exec_eip712_lib};
use crate::entry::check_no_other_cell_except_specified;
use crate::error::Error;
use crate::structures::CmdMatchStatus::DasNotPureLockCell;
use crate::sub_account::SubAction;
use crate::tx_parser::{get_first_account_cell_index, get_input_approval};

pub fn validate_for_update_reverse_record_root() -> Result<i8, Error> {
    debug!("Verify the signatures of ReverseRecordRootCell ...");

    let mut sign_lib = SignLib::new();
    let eth_so_type_id = get_type_id(FieldKey::EthSignSoTypeArgs)?;
    let tron_so_type_id = get_type_id(FieldKey::TronSignSoTypeArgs)?;
    let doge_so_type_id = get_type_id(FieldKey::DogeSignSoTypeArgs)?;
    let webauthn_so_type_id = get_type_id(FieldKey::WebauthnSignSoTypeArgs)?;
    let btc_so_type_id = get_type_id(FieldKey::BtcSignSoTypeArgs)?;
    load_and_configure_lib!(sign_lib, "ETH", eth_so_type_id, eth, load_2_methods);
    load_and_configure_lib!(sign_lib, "TRON", tron_so_type_id, tron, load_2_methods);
    load_and_configure_lib!(sign_lib, "DOGE", doge_so_type_id, doge, load_2_methods);
    load_and_configure_lib!(sign_lib, "WebAuthn", webauthn_so_type_id, web_authn, load_3_methods);
    load_and_configure_lib!(sign_lib, "BTC", btc_so_type_id, btc, load_2_methods);

    let reverse_witness_parser = ReverseRecordWitnessesParser::new()
        .map_err(|e| {
            debug!("ReverseRecordWitnessesParser error: {:?}", e);
            return Error::WitnessError;
        })
        .unwrap();
    for witness_ret in reverse_witness_parser.iter() {
        match witness_ret {
            Ok(witness) => {
                reverse_record_root_cell_verify_sign(&sign_lib, &witness, &reverse_witness_parser)
                    .map_err(|e| {
                        debug!("reverse_record_root_cell_verify_sign error: {:?}", e);
                        return Error::ValidationFailure;
                    })
                    .unwrap();
            }
            Err(_e) => {
                return Err(Error::InvalidWitnessArgsLock);
            }
        }
    }
    Ok(0)
}
pub fn reverse_record_root_cell_verify_sign(
    sign_lib: &SignLib, witness: &ReverseRecordWitness, witness_parser: &ReverseRecordWitnessesParser,
) -> Result<(), Box<dyn ScriptError>> {
    if cfg!(feature = "dev") {
        // CAREFUL Proof verification has been skipped in development mode.
        debug!(
            "  witnesses[{:>2}] Skip verifying the witness.reverse_record.signature is valid.",
            witness.index
        );
        return Ok(());
    }

    debug!(
        "  witnesses[{:>2}] Verify if the witness.reverse_record.signature is valid.",
        witness.index
    );
    //Determine the signature algorithm based on the sign_type of the witness. ETHTypedData is equivalent to ETH
    let das_lock_type = match witness.sign_type {
        DasLockType::ETH
        | DasLockType::ETHTypedData
        | DasLockType::TRON
        | DasLockType::Doge
        | DasLockType::WebAuthn
        | DasLockType::BTC => witness.sign_type,
        _ => {
            debug!(
                "  witnesses[{:>2}] Parsing das-lock(witness.reverse_record.lock.args) algorithm failed (maybe not supported for now), but it is required in this transaction.",
                witness.index
            );
            return Err(code_to_error!(ErrorCode::InvalidTransactionStructure));
        }
    };

    let nonce = if let Some(prev_nonce) = witness.prev_nonce {
        prev_nonce + 1
    } else {
        1
    };
    let account = witness.next_account.as_bytes().to_vec();
    let data = [nonce.to_le_bytes().to_vec(), account].concat();
    let signature = witness.signature.as_slice().to_vec();
    let args = witness.address_payload.as_slice().to_vec();

    let message = sign_lib.gen_digest(das_lock_type, data).map_err(|_| {
        debug!(
            "  witnesses[{:>2}] The lock type {} is still not supported.",
            witness.index,
            das_lock_type.to_string()
        );
        code_to_error!(ReverseRecordRootCellErrorCode::SignatureVerifyError)
    })?;

    // TODO: currently we cannot find sub_alg_id in witness. fix sub_alg_id to 7
    let args = if das_lock_type == DasLockType::WebAuthn {
        [vec![7], args].concat()
    } else {
        args
    };

    let ret = if das_lock_type == DasLockType::WebAuthn
        && u8::from_le_bytes(
            WebAuthnSignature::try_from(signature.as_slice())?
                .pubkey_index()
                .try_into()
                .unwrap(),
        ) != 255
    {
        let device_key_list = witness_parser
            .device_key_lists
            .get(args.index(..))
            .ok_or(code_to_error!(ErrorCode::WitnessStructureError))?;
        let key_list = device_key_list.keys().as_reader().as_slice()[4..].to_vec();
        sign_lib.validate_device(
            das_lock_type,
            0i32,
            &signature,
            &message,
            key_list.as_slice(),
            Default::default(),
        )
    } else {
        sign_lib.validate_str(das_lock_type, 0i32, message.clone(), message.len(), signature, args)
    };

    match ret {
        Err(_error_code) if _error_code == DasDynamicLibError::UndefinedDasLockType as i32 => {
            debug!(
                "  witnesses[{:>2}] The signature algorithm has not been supported",
                witness.index
            );
            Err(code_to_error!(ErrorCode::HardCodedError))
        }
        Err(_error_code) => {
            debug!(
                "  witnesses[{:>2}] The witness.signature is invalid, the error_code returned by dynamic library is: {}",
                witness.index, _error_code
            );
            Err(code_to_error!(ReverseRecordRootCellErrorCode::SignatureVerifyError))
        }
        _ => {
            debug!("  witnesses[{:>2}] The witness.signature is valid.", witness.index);
            Ok(())
        }
    }
}
pub fn validate_if_has_other_cell_in_inputs_except_specified(cell_type: FieldKey) -> Result<i8, Error> {
    debug!(
        "Verify if there are other cells in inputs except the {:?}",
        cell_type
    );
    return if check_no_other_cell_except_specified(cell_type) == DasNotPureLockCell {
        debug!("There are some cells with the same lock, besides the account cell. Then verify the signature.");
        let (das_action, role) = crate::entry::get_action_and_role()?;
        dispatch(role, das_action)
    } else {
        Ok(0)
    };
}
pub fn validate_for_fulfill_approval() -> Result<i8, Error> {
    let account_cell_index = get_first_account_cell_index()?;

    let input_approval = get_input_approval()?;
    let input_approval_reader = input_approval.as_reader();
    let sealed_until = u64::from(input_approval_reader.sealed_until());

    let timestamp = util::load_oracle_data(OracleCellType::Time)?;
    if timestamp > sealed_until {
        debug!("The approval is already released, so anyone can fulfill it.");
    } else {
        let owner_lock = high_level::load_cell_lock(account_cell_index, Source::Input)
            .map_err(|_| {
                debug!("{:?}[{}] Loading lock field failed.", Source::Input, account_cell_index);
                return Error::InvalidWitnessArgsLock;
            })
            .unwrap();

        approval_verify_sign(
            "owner_lock",
            owner_lock.as_reader().into(),
            account_cell_index,
        )?;

        //WARNING: There was no algorithm type checking before.
        exec_eip712_lib().expect("exec_eip712_lib failed");
    }

    validate_if_has_other_cell_in_inputs_except_specified(FieldKey::AccountCellTypeArgs)
}
pub fn validate_for_revoke_approval() -> Result<i8, Error> {
    let input_approval = get_input_approval()?;
    let input_approval_reader = input_approval.as_reader();

    let platform_lock = input_approval_reader.platform_lock().to_entity();
    let input_account_cell_index = get_first_account_cell_index()?;

    approval_verify_sign(
        "platform_lock",
        platform_lock.as_reader(),
        input_account_cell_index,
    )
    .map_err(|e| {
        debug!("revoke_approval_verify_sign error: {:?}", e);
        return Error::ValidationFailure;
    })
    .unwrap();

    validate_if_has_other_cell_in_inputs_except_specified(FieldKey::AccountCellTypeArgs)
}
pub fn approval_verify_sign(
    lock_name: &str, sign_lock: ScriptReader, input_account_index: usize,
) -> Result<(), Error> {
    debug!("Verify the signatures of {} ...", lock_name);

    let sign_type_int = data_parser::das_lock_args::get_owner_type(sign_lock.args().raw_data());
    let args = data_parser::das_lock_args::get_owner_lock_args(sign_lock.args().raw_data());
    let sign_type = DasLockType::try_from(sign_type_int).map_err(|_| {
        debug!("inputs[{}] Invalid sign type: {}", input_account_index, sign_type_int);
        Error::InvalidTransactionStructure
    })?;

    let type_no = if sign_type == DasLockType::ETHTypedData {
        1i32
    } else {
        0i32
    };

    let mut sign_lib = SignLib::new();

    if cfg!(not(feature = "dev")) {
        let eth_so_type_id = get_type_id(FieldKey::EthSignSoTypeArgs)?;
        let tron_so_type_id = get_type_id(FieldKey::TronSignSoTypeArgs)?;
        let doge_so_type_id = get_type_id(FieldKey::DogeSignSoTypeArgs)?;
        let webauthn_so_type_id = get_type_id(FieldKey::WebauthnSignSoTypeArgs)?;
        load_and_configure_lib!(sign_lib, "ETH", eth_so_type_id, eth, load_2_methods);
        load_and_configure_lib!(sign_lib, "TRON", tron_so_type_id, tron, load_2_methods);
        load_and_configure_lib!(sign_lib, "DOGE", doge_so_type_id, doge, load_2_methods);
        load_and_configure_lib!(sign_lib, "WebAuthn", webauthn_so_type_id, web_authn, load_3_methods);

        let (digest, witness_args_lock) = if sign_type == DasLockType::ETHTypedData {
            let (_, _, digest, _, witness_args_lock) = sign_util::get_eip712_digest(vec![input_account_index])?;
            (digest, witness_args_lock)
        } else {
            sign_util::calc_digest_by_input_group(sign_type, vec![input_account_index])?
        };

        sign_lib
            .validate_str(
                sign_type,
                type_no,
                digest.to_vec(),
                digest.len(),
                witness_args_lock,
                args.to_vec(),
            )
            .map_err(|err_code| {
                debug!(
                    "inputs[{}] Verify signature failed, error code: {}",
                    input_account_index, err_code
                );
                return Error::EIP712SignatureError;
            })?;
    }

    Ok(())
}


pub fn validate_for_update_sub_account() -> Result<i8, Error> {
    debug!("Verify the signatures of SubAccountCell ...");

    let mut sign_lib = SignLib::new();
    let eth_so_type_id = get_type_id(FieldKey::EthSignSoTypeArgs)?;
    let tron_so_type_id = get_type_id(FieldKey::TronSignSoTypeArgs)?;
    let doge_so_type_id = get_type_id(FieldKey::DogeSignSoTypeArgs)?;
    let webauthn_so_type_id = get_type_id(FieldKey::WebauthnSignSoTypeArgs)?;
    load_and_configure_lib!(sign_lib, "ETH", eth_so_type_id, eth, load_2_methods);
    load_and_configure_lib!(sign_lib, "TRON", tron_so_type_id, tron, load_2_methods);
    load_and_configure_lib!(sign_lib, "DOGE", doge_so_type_id, doge, load_2_methods);
    load_and_configure_lib!(sign_lib, "WebAuthn", webauthn_so_type_id, web_authn, load_3_methods);

    let sub_account_type_id = get_type_id(FieldKey::SubAccountCellTypeArgs)?;
    debug!(
        "The type_id of SubAccountCell is {}.",
        hex_string(sub_account_type_id.as_slice())
    );

    //note: use "only" to ensure that only one sub-account-cell exists.
    debug!("Check if there is only one SubAccountCell in inputs.");
    let sub_account_cell_index = find_only_cell_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::SubAccountCellTypeArgs)?,
        Source::Input,
    )?;

    debug!("Found SubAccountCell in inputs[{}].", sub_account_cell_index);

    let input_sub_account_data = high_level::load_cell_data(sub_account_cell_index, Source::Input)?;

    let flag = match data_parser::sub_account_cell::get_flag(&input_sub_account_data) {
        Some(val) => val,
        None => {
            debug!("The flag should always be some for now.");
            return Err(Error::ArgsError);
        }
    };
    debug!("The flag of SubAccountCell is {:?}.", flag);

    let sub_account_parser = SubAccountWitnessesParser::new(flag)?;

    let account_cell_source = Source::CellDep;
    let dep_account_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs)?,
        account_cell_source,
    )?;

    if dep_account_cells.len() == 0 {
        debug!("There should be only one AccountCell in cell_deps.");
        return Err(Error::InvalidTransactionStructure);
    }

    let account_cell_index = dep_account_cells[0];
    let account_cell_witness = util::parse_account_cell_witness(dep_account_cells[0], Source::CellDep)?;
    let account_cell_reader = account_cell_witness.as_reader();
    let parent_account_name = account_cell_reader.account().as_readable();
    let account_lock = high_level::load_cell_lock(account_cell_index, account_cell_source)?;
    let account_lock_args = account_lock.as_reader().args().raw_data();

    debug!("The parent account name is {:02x?}.", parent_account_name);
    let account_cell_data = util::load_cell_data(account_cell_index, account_cell_source)?;

    //following three values are used in closure
    let parent_expired_at = data_parser::account_cell::get_expired_at(&account_cell_data);
    let header = util::load_header(sub_account_cell_index, Source::Input)?;
    let sub_account_last_updated_at = util::get_timestamp_from_header(header.as_reader());

    let mut sender_lock = ckb_std::ckb_types::packed::Script::default();

    let mut sign_verified = false;
    if sub_account_parser.contains_creation || sub_account_parser.contains_renew {
        let verify_and_init_some_vars =
            |_name: &str,
             witness: &SubAccountMintSignWitness|
             -> Result<(Option<LockRole>, ckb_std::ckb_types::packed::Script), Box<dyn ScriptError>> {
                debug!("The {} is exist, verifying the signature for manual mint ...", _name);

                //this to show that the signature has a validity period, usually the validity period is verified before the signature is verified.
                verifiers::sub_account_cell::verify_sub_account_mint_sign_not_expired(
                    &sub_account_parser,
                    &witness,
                    parent_expired_at,
                    sub_account_last_updated_at,
                )?;
                verifiers::sub_account_cell::verify_sub_account_mint_sign(&witness, &sign_lib, &sub_account_parser)?;

                // let mut tmp = [0u8; 32];
                // //tmp.copy_from_slice(&witness.account_list_smt_root);
                // let account_list_smt_root = Some(tmp);

                let sender_lock = if witness.sign_role == Some(LockRole::Manager) {
                    debug!("Found SubAccountWitness.sign_role is manager, use manager lock as sender_lock.");
                    util::derive_manager_lock_from_cell(account_cell_index, account_cell_source)?
                } else {
                    debug!("Found SubAccountWitness.sign_role is owner, use owner lock as sender_lock.");
                    util::derive_owner_lock_from_cell(account_cell_index, account_cell_source)?
                };

                Ok((witness.sign_role.clone(), sender_lock))
            };
        let mut mint_sign_role: Option<LockRole> = None;

        if sub_account_parser.contains_creation {
            match sub_account_parser.get_mint_sign(account_lock_args) {
                Some(Ok(witness)) => {
                    sign_verified = true;
                    (mint_sign_role, sender_lock) = verify_and_init_some_vars("SubAccountMintWitness", &witness)?;
                }
                Some(Err(err)) => {
                    debug!("Error: witness parser mint sign err, {:?}", err);
                    return Err(Error::WitnessError);
                }
                None => {
                    debug!("There is no SubAccountMintSign found.");
                }
            }
        }

        if sub_account_parser.contains_renew {
            match sub_account_parser.get_renew_sign(account_lock_args) {
                Some(Ok(witness)) => {
                    let renew_sender_lock;
                    let renew_sign_role;
                    sign_verified = true;
                    (renew_sign_role, renew_sender_lock) =
                        verify_and_init_some_vars("SubAccountRenewWitness", &witness)?;

                    if mint_sign_role.is_some() {
                        if mint_sign_role != renew_sign_role {
                            debug!(
                                "The sign_role of SubAccountMintSignWitness and SubAccountRenewSignWitness should be the same in the same transaction."
                            );
                            return Err(Error::WitnessError);
                        }
                    } else {
                        sender_lock = renew_sender_lock;
                    }
                }
                Some(Err(err)) => {
                    debug!("Error: witness parser mint sign err, {:?}", err);
                    return Err(Error::WitnessError);
                }
                None => {
                    debug!("There is no SubAccountRenewSign found.");
                }
            }
        } else {
            if sub_account_parser.get_renew_sign(account_lock_args).is_some() {
                debug!("The SubAccountRenewSignWitness is not allowed if there if no renew action exists.");
                return Err(Error::WitnessError);
            }
        }
    }

    let das_lock = das_lock();
    let all_inputs_with_das_lock =
        util::find_cells_by_type_id(ScriptType::Lock, das_lock.code_hash().as_reader().into(), Source::Input)?;

    //This verification is both in type and lock
    if sign_verified {
        let input_sender_balance_cells =
            util::find_balance_cells(get_type_id(FieldKey::BalanceCellTypeArgs)?, sender_lock.as_reader(), Source::Input)?;

        //It is allowed to use dp to pay fees, and other assets of das-lock are not allowed to appear in the input.
        verifiers::misc::verify_no_more_cells_with_same_lock_except_type(
            sender_lock.as_reader(),
            &input_sender_balance_cells,
            Source::Input,
            get_type_id(FieldKey::DpointCellTypeArgs)?,
        )?;

        let input_sender_cells = util::find_cells_by_script(ScriptType::Lock, sender_lock.as_reader(), Source::Input)?;

        //Ensure that all cells in inputs that use das-lock use sender_lock as the lock.
        if all_inputs_with_das_lock != input_sender_cells {
            debug!(
                "Some cells with das-lock have may be abused.(invalid_inputs: {:?})",
                all_inputs_with_das_lock
                    .iter()
                    .filter(|item| !input_sender_cells.contains(item))
                    .map(|item| item.to_owned())
                    .collect::<Vec<usize>>()
            );
            return Err(Error::WitnessError);
        }
    } else {
        debug!("Verify if there is no BalanceCells are spent.");
        if all_inputs_with_das_lock.len() != 0 {
            debug!(
                "Some cells with das-lock have may be abused.(invalid_inputs: {:?})",
                all_inputs_with_das_lock
            );
            return Err(Error::WitnessError);
        }
    }
    let timestamp = util::load_oracle_data(OracleCellType::Time)?;
    let mut parent_account = parent_account_name;
    parent_account.extend(ACCOUNT_SUFFIX.as_bytes());

    let sub_action = SubAction::new(
        sign_lib,
        timestamp,
        //quote,
        sub_account_last_updated_at,
        &parent_account,
        parent_expired_at,
    );
    for (_i, witness_ret) in sub_account_parser.iter().enumerate() {
        let witness = match witness_ret {
            Ok(val) => val,
            Err(_e) => return Err(Error::SubAccountParseFailed),
        };

        sub_action.dispatch(&witness, &sub_account_parser)?;
    }

    Ok(0)
}
