extern crate alloc;
use crate::error::Error;
use alloc::string::String;
use alloc::vec::Vec;
use ckb_std::high_level::load_cell_type;
use ckb_std::{
    ckb_constants::{CellField, Source},
    ckb_types::{
        bytes::Bytes,
        packed::Script,
        prelude::{Entity, Unpack},
    },
    high_level::{load_cell_lock_hash, load_script, load_script_hash, load_tx_hash},
    syscalls::{load_cell_by_field, load_witness, SysError},
};
use core::convert::TryFrom;
use core::result::Result;
use das_core::util::hex_string;

use crate::constants::{
    BLAKE160_SIZE, FLAGS_SIZE, HASH_SIZE, MAX_WITNESS_SIZE, ONE_BATCH_SIZE, RIPEMD160_HASH_SIZE,
    SCRIPT_SIZE, SIGNATURE_SIZE, SIZE_UINT64, WEBAUTHN_SIZE, WITNESS_ARGS_HEADER_LEN,
    WITNESS_ARGS_LOCK_LEN,
};
use crate::debug_log;
use crate::dlopen::{
    dispatch_do_dyn_lib_and_then_exec_eip712_lib, dispatch_to_dyn_lib,
};
use crate::structures::CmdMatchStatus::{DasNotPureLockCell, DasPureLockCell};
use crate::structures::MatchStatus::{Match, NotMatch};
use crate::structures::{AlgId, CmdMatchStatus, LockArgs, MatchStatus, SignInfo, SkipSignOrNot};
use crate::utils::generate_sighash_all::{calculate_inputs_len, load_and_hash_witness};
use crate::utils::{bytes_to_u32_le, check_num_boundary, new_blake2b};
use das_types::constants::{Action as DasAction, LockRole as Role};
//use das_types::packed::Reader;

#[cfg(test)]
use crate::test_framework::Testable;
use crate::tx_parser::{
    get_account_cell_type_id, get_balance_cell_type_id, get_dpoint_cell_type_id,
    get_sub_account_cell_type_id,
};
use crate::validators::{
    validate_for_fulfill_approval, validate_for_revoke_approval,
    validate_for_unlock_account_for_cross_chain, validate_for_update_reverse_record_root,
    validate_for_update_sub_account,
};

// fn check_cmd_match(action: &DasAction) -> MatchStatus {
//     match action {
//         DasAction::ConfirmProposal
//         | DasAction::RenewAccount
//         | DasAction::UnlockAccountForCrossChain
//         | DasAction::ForceRecoverAccountStatus
//         | DasAction::RecycleExpiredAccount
//         | DasAction::RevokeApproval
//         | DasAction::FulfillApproval => MatchStatus::Match,
//         _ => MatchStatus::NotMatch,
//     }
// }

fn check_witness_das_header(data: &[u8]) -> Result<(), Error> {
    if !data.starts_with(b"das") {
        return Err(Error::InvalidDasWitness);
    }

    //it should be equal to witness.len() - 7
    let witness_len = data.len();
    if !bytes_to_u32_le(&data[7..11]).is_some_and(|x| x as usize + 7 == witness_len) {
        debug_log!(
            "witness_len = {:?}, data[7..11] = {:02x?}",
            witness_len,
            &data[7..11]
        );
        return Err(Error::InvalidDasWitness);
    }

    Ok(())
}
fn get_witness_action(temp: &[u8]) -> Result<(DasAction, Role), Error> {
    //check if the header is action witness
    check_witness_das_header(temp)?;

    //the action data map
    //[0..3] = "das"
    //[3..7] = das type
    //[7..11] = molecule total len
    //[11..15] = action offset
    //[15..19] = params offset
    //[19..23] = action len
    //[23..23+action_len] = action
    //[23+action_len..23+action_len+4] = params len
    //[23+action_len+4..23+action_len+4+params_len] = params
    //[data.len()-1] = is owner or manager

    //get action len
    let action_len_index = 19;
    let action_start = action_len_index + 4;

    let action_len = bytes_to_u32_le(&temp[action_len_index..action_start]).unwrap();
    check_num_boundary(action_len, 1, 255)?;
    let action_end = action_start + action_len as usize;

    let action_string = String::from_utf8(temp[action_start..action_end].to_vec())
        .map_err(|_| Error::InvalidString)?;
    debug_log!("action_string = {:?}", action_string);

    let action = DasAction::new(action_string.as_str());
    debug_log!("action = {:?}", action);

    //the last bytes of this witness is the params to distinguish owner and manager
    let params_index = temp.len() - 1;
    let params = temp[params_index];

    let role = match Role::try_from(params) {
        Ok(r) => r,
        Err(e) => {
            debug_log!("role try from error: params = {:?}, err = {:?}", params, e);
            return Err(Error::InvalidRole);
        }
    };

    Ok((action, role))
}

fn get_payload_len(alg_id: u8) -> Result<usize, Error> {
    let alg = AlgId::try_from(alg_id).map_err(|_| Error::InvalidAlgId)?;
    match alg {
        AlgId::CkbMultiSig => Ok(BLAKE160_SIZE + SIZE_UINT64),
        AlgId::Ed25519 => Ok(HASH_SIZE),
        AlgId::DogeCoin => Ok(RIPEMD160_HASH_SIZE),
        AlgId::WebAuthn => Ok(WEBAUTHN_SIZE),
        _ => Ok(BLAKE160_SIZE),
    }
}
fn check_and_downgrade_alg_id(action: &DasAction, alg_id: AlgId) -> AlgId {
    if alg_id != AlgId::Eip712 {
        //if not Eip712, then return alg_id;
        return alg_id;
    }
    //if match the downgrade list, then downgrade to Eth
    match action {
        DasAction::EnableSubAccount | DasAction::ConfigSubAccount => AlgId::Eth, //3
        _ => AlgId::Eip712,
    }
}
fn get_lock_args(action: &DasAction, role: Role) -> Result<LockArgs, Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    let args_slice = args.as_ref();
    let alg_id_owner = args_slice[0];

    let payload1_len = get_payload_len(alg_id_owner)?;

    // let payload = args_slice[1..args_len].to_vec();
    let (payload_start_idx, payload_end_index, alg_id) = {
        match role {
            Role::Owner => {
                let start = 1;
                let end = start + payload1_len;
                (start, end, alg_id_owner)
            }
            Role::Manager => {
                let manager_alg_idx = 1 + payload1_len;
                let manager_alg_id = args_slice[manager_alg_idx];
                let payload2_len = get_payload_len(manager_alg_id)?;
                let start = manager_alg_idx + 1;
                let end = start + payload2_len;
                (start, end, manager_alg_id)
            }
        }
    };
    let payload = args_slice[payload_start_idx..payload_end_index].to_vec();

    let alg = check_and_downgrade_alg_id(
        action,
        AlgId::try_from(alg_id).map_err(|_| Error::InvalidAlgId)?,
    );

    let ret = LockArgs::new(alg, payload);
    Ok(ret)
}

// #[allow(unused_assignments)]
// warning: if there are some cells with same lock script?
fn get_self_index_in_inputs() -> Result<usize, Error> {
    let script_hash = load_script_hash()?;
    debug_log!("self script_hash = {:02x?}", script_hash);

    let mut i = 0;
    #[allow(unused_assignments)]
    let mut match_result = false;
    loop {
        let lock_hash = load_cell_lock_hash(i, Source::Input)?;
        debug_log!("loaded {} : lock_hash = {:02x?}", i, lock_hash);
        //if script_hash == lock_hash {
        if script_hash == lock_hash {
            match_result = true;
            break;
        }
        i += 1;
    }
    if !match_result {
        debug_log!("self not found in inputs");
        return Err(Error::SelfNotFound);
    }
    debug_log!("self index = {:?}", i);
    Ok(i)
}

fn get_first_dp_cell_lock_hash() -> Result<Vec<u8>, Error> {
    let dp_cell_type_id = get_dpoint_cell_type_id()?;
    debug_log!("dp_cell_type_id = {:02x?}", dp_cell_type_id);

    for i in 0..100 {
        match load_cell_type(i, Source::Input) {
            Ok(type_script) => {
                if type_script.is_some() {
                    let type_args = type_script.unwrap().code_hash().raw_data().to_vec();
                    debug_log!("{} type_args = {:02x?}", i, type_args);
                    if type_args == dp_cell_type_id {
                        return Ok(load_cell_lock_hash(i, Source::Input)?.to_vec());
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => {
                debug_log!("load_cell_type_hash error: {:?}", SysError::IndexOutOfBound);
                break;
            }
            Err(e) => {
                debug_log!("load_cell_type_hash error: {:?}", e);
                return Err(Error::LoadCellTypeHashError);
            }
        }
    }
    Err(Error::DpCellNotFound)
}

fn check_skip_dynamic_library_signature_verification_for_bid_expired_auction(
) -> Result<SkipSignOrNot, Error> {
    //todo maybe have risks when skip by cell out of the group
    //Warning: AccountCell is always inputs[0], guarantee it through the account-cell-type.
    let script_index = get_self_index_in_inputs()?;
    debug_log!("get_self_index_in_inputs self index = {:?}", script_index);

    let current_type_script =
        load_cell_type(script_index, Source::Input)?.expect("type script should exist");
    let current_type_script_args = current_type_script.code_hash().raw_data().to_vec();
    let current_lock_script_hash = load_cell_lock_hash(script_index, Source::Input)?.to_vec();

    //dp-cell-type ensures that the locks of all dp cells in inputs are the same.
    let account_cell_type_id = get_account_cell_type_id()?;
    let dp_cell_lock_hash = get_first_dp_cell_lock_hash()?; //

    debug_log!(
        "current_lock_script_hash = {}",
        hex_string(current_lock_script_hash.as_slice())
    );
    debug_log!(
        "dp_cell_lock_hash = {}",
        hex_string(dp_cell_lock_hash.as_slice())
    );
    debug_log!(
        "current_type_script_args = {}",
        hex_string(current_type_script_args.as_slice())
    );
    debug_log!(
        "account_cell_type_id = {}",
        hex_string(account_cell_type_id.as_slice())
    );

    //Signature verification can be skipped only if the following two conditions are met.
    //1. The current lock is not equal to the lock of dp cell
    //2. The current type is account-cell-type
    if current_lock_script_hash != dp_cell_lock_hash
        && current_type_script_args == account_cell_type_id
    {
        debug_log!("jump over the signature verification of the Dutch auction");
        return Ok(SkipSignOrNot::Skip);
    }

    Ok(SkipSignOrNot::NotSkip)
}

fn check_the_first_input_cell_must_be_sub_account_type_script() -> Result<MatchStatus, Error> {
    //debug_log!("Enter check_the_first_input_cell_must_be_sub_account_type_script");

    //get sub account type id
    let sub_account_type_id = get_sub_account_cell_type_id()?;

    let mut temp = [0u8; SCRIPT_SIZE];
    let read_len = load_cell_by_field(&mut temp, 0, 0, Source::Input, CellField::Type)?;

    let script = match Script::from_slice(&temp[..read_len]) {
        Ok(s) => s,
        Err(e) => {
            debug_log!("script verify failed : {:?}", e);
            return Err(Error::InvalidMolecule);
        }
    };

    let code_hash = script.code_hash().unpack();

    if sub_account_type_id == code_hash {
        return Ok(Match);
    }

    Ok(NotMatch)
}

fn check_skip_dynamic_library_signature_verification_for_update_sub_account(
) -> Result<SkipSignOrNot, Error> {
    debug_log!("Enter check_skip_sign_for_update_sub_account");

    match check_the_first_input_cell_must_be_sub_account_type_script() {
        Ok(Match) => Ok(SkipSignOrNot::Skip),
        Ok(NotMatch) => Err(Error::CheckFailSubAccFirstInputCell),
        Err(e) => Err(e),
    }
}

pub(crate) fn get_plain_and_cipher(alg_id: AlgId) -> Result<SignInfo, Error> {
    debug_log!("Enter get_plain_and_cipher");
    let mut temp = [0u8; MAX_WITNESS_SIZE];

    // Load witness of first input.
    let mut read_len = load_witness(&mut temp, 0, 0, Source::GroupInput)?;
    let witness_len = read_len;
    if read_len > MAX_WITNESS_SIZE {
        read_len = MAX_WITNESS_SIZE;
    }

    //check the witness length, it's the molecule witness_args, at least 16 bytes
    if read_len < WITNESS_ARGS_HEADER_LEN {
        return Err(Error::Encoding);
    }

    debug_log!("load witness success, read_len = {:?}", read_len);
    //check the length
    //todo1: ckb syscall high level
    let lock_length = bytes_to_u32_le(&temp[16..20]).unwrap() as usize;
    let lock_field_start_index = WITNESS_ARGS_HEADER_LEN + 4;
    let lock_field_end_index = lock_field_start_index + lock_length;

    //u32::from_le_bytes(temp[16..20].try_into().unwrap()) as usize;
    if read_len < lock_field_end_index {
        debug_log!(
            "err read_len = {:?}, lock_field_end_index = {:?}",
            read_len,
            lock_field_end_index
        );
        return Err(Error::Encoding);
    }

    if alg_id == AlgId::Eip712 {
        if lock_length != WITNESS_ARGS_LOCK_LEN {
            debug_log!(
                "Eip712's signature in witness has wrong length = {:?} != {}",
                lock_length,
                WITNESS_ARGS_LOCK_LEN
            );
            return Err(Error::InvalidWitnessArgsLock);
        }

        //copy signature
        let mut cursor = lock_field_start_index;
        let signature = temp[cursor..cursor + SIGNATURE_SIZE].to_vec();

        //copy message
        cursor += SIGNATURE_SIZE;
        let message = temp[cursor..cursor + HASH_SIZE].to_vec();

        return Ok(SignInfo { signature, message });
    }

    //copy signature before clear
    let signature = temp[lock_field_start_index..lock_field_end_index].to_vec();

    // Clear lock field to zero, then digest the first witness
    // lock_bytes_seg.ptr actually points to the memory in temp buffer.
    if alg_id == AlgId::CkbMultiSig {
        //todo2: need more test about this, unimple
        let threshold = temp[lock_field_start_index + 2];
        let public_key_count = temp[lock_field_start_index + 3];

        let multi_script_len = FLAGS_SIZE + BLAKE160_SIZE * public_key_count as usize;
        let multi_sig_len = SIGNATURE_SIZE * threshold as usize;
        let required_lock_len = multi_script_len + multi_sig_len;
        if required_lock_len != lock_length {
            return Err(Error::InvalidWitnessArgsLock);
        }
        let clear_start = lock_field_start_index + multi_script_len;
        let clear_end = lock_field_end_index;
        temp[clear_start..clear_end].fill(0);
    } else {
        temp[lock_field_start_index..lock_field_end_index].fill(0);
    }

    // Load tx hash.
    //todo: replace these code with function in type contract.
    let tx_hash = load_tx_hash()?;
    debug_log!("tx_hash = {:02x?}", tx_hash);

    // Prepare sign message.
    let mut blake2b_ctx = new_blake2b();
    blake2b_ctx.update(&tx_hash);
    blake2b_ctx.update(&(witness_len as u64).to_le_bytes());
    blake2b_ctx.update(&temp[..read_len]);

    // Remaining of first witness.
    if read_len < witness_len {
        load_and_hash_witness(&mut blake2b_ctx, read_len, 0, Source::GroupInput, false)?;
    }

    // Digest same group witnesses.
    let mut i = 1;
    loop {
        let sysret = load_and_hash_witness(&mut blake2b_ctx, 0, i, Source::GroupInput, true);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }

    // Digest witnesses that not covered by inputs.
    let mut i = calculate_inputs_len()?;

    loop {
        let sysret = load_and_hash_witness(&mut blake2b_ctx, 0, i, Source::Input, true);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }
    let mut msg = [0u8; 32];
    blake2b_ctx.finalize(&mut msg);
    let message = msg.to_vec();

    Ok(SignInfo { signature, message })
}

fn check_has_pure_type_script() -> CmdMatchStatus {
    //todo: replace with find_one
    let balance_type_id = get_balance_cell_type_id().unwrap();
    let mut buf = [0u8; 100];
    for i in 0.. {
        let _len = match load_cell_by_field(&mut buf, 0, i, Source::GroupInput, CellField::Type) {
            Ok(len) => len,
            Err(SysError::IndexOutOfBound) => break,
            Err(SysError::ItemMissing) => continue,
            Err(err) => {
                debug_log!("load_cell_by_field error: {:?}", err);
                return DasNotPureLockCell;
            }
        };
        //debug_assert_eq!(len, buf.len());
        if balance_type_id == &buf[16..] {
            continue;
        } else {
            return DasNotPureLockCell;
        }
    }
    DasPureLockCell
}

fn check_skip_sign(action: &DasAction) -> SkipSignOrNot {
    if DasPureLockCell == check_has_pure_type_script() {
        return SkipSignOrNot::NotSkip;
    }
    match action {
        DasAction::ConfirmProposal
        | DasAction::RenewAccount
        | DasAction::ForceRecoverAccountStatus
        | DasAction::RecycleExpiredAccount => SkipSignOrNot::Skip,
        _ => SkipSignOrNot::NotSkip,
    }
}

//return true if manager has permission
fn check_manager_has_permission(action: &DasAction, role: Role) -> bool {
    if role != Role::Manager {
        return true;
    }
    match action {
        DasAction::EditRecords
        // | DasAction::CreateSubAccount //note: this action is abandoned before, just das-lock does not remove it.
        | DasAction::UpdateSubAccount
        | DasAction::ConfigSubAccount => true,
        _ => false,
    }
}
fn get_action_and_role() -> Result<(DasAction, Role), Error> {
    //get the number of cells in inputs
    let action_witness_index = calculate_inputs_len()?;

    let mut temp = [0u8; ONE_BATCH_SIZE]; //note: allocating memory does not take cycles
    let read_len = load_witness(&mut temp, 0, action_witness_index, Source::Input)?;
    if read_len > MAX_WITNESS_SIZE {
        debug_log!(
            "Action witness's length is overflow! read len = {:?}, MAX_WITNESS_SIZE = {:?}",
            read_len,
            MAX_WITNESS_SIZE
        );
        return Err(Error::LengthNotEnough);
    }
    let (das_action, role) = get_witness_action(&temp[..read_len])?;
    Ok((das_action, role))
}

pub fn main() -> Result<(), Error> {
    debug_log!("Enter das lock main.");

    //Get action from witness.
    let (das_action, role) = get_action_and_role()?;
    debug_log!("Action = {:?}, role = {:?}", das_action, role);

    //Decide whether to skip signature verification based on action.
    if SkipSignOrNot::Skip == check_skip_sign(&das_action) {
        debug_log!("Skip this action, {:?}", das_action);
        return Ok(());
    }

    //Check whether the manager has permission to execute the corresponding action.
    if !check_manager_has_permission(&das_action, role) {
        debug_log!("Manager does not have permission to execute this action.");
        return Err(Error::ManagerNotAllowed);
    }

    //Get lock args.
    let lock_args = get_lock_args(&das_action, role)?;
    debug_log!("Lock args = {}", lock_args);

    let ret = match das_action {
        DasAction::BidExpiredAccountDutchAuction => {
            match check_skip_dynamic_library_signature_verification_for_bid_expired_auction()? {
                SkipSignOrNot::Skip => {
                    debug_log!("Skip check sign for bid expired account dutch auction.");
                    return Ok(());
                }
                SkipSignOrNot::NotSkip => {
                    dispatch_do_dyn_lib_and_then_exec_eip712_lib(role, &lock_args)
                }
            }
        }

        DasAction::FulfillApproval => validate_for_fulfill_approval(),
        DasAction::RevokeApproval => validate_for_revoke_approval(),
        DasAction::UnlockAccountForCrossChain => validate_for_unlock_account_for_cross_chain(),
        DasAction::UpdateReverseRecordRoot => validate_for_update_reverse_record_root(),

        DasAction::UpdateSubAccount => {
            match check_skip_dynamic_library_signature_verification_for_update_sub_account()? {
                SkipSignOrNot::Skip => {
                    debug_log!("Skip check sign for update sub account.");
                    validate_for_update_sub_account()
                }
                SkipSignOrNot::NotSkip => {
                    dispatch_to_dyn_lib(role, &lock_args) //maybe redundant
                }
            }
        }

        DasAction::TransferAccount
        | DasAction::EditManager
        | DasAction::EditRecords
        | DasAction::CreateApproval
        | DasAction::DelayApproval
        | DasAction::CancelAccountSale
        | DasAction::BurnDP
        | DasAction::TransferDP
        | DasAction::CancelOffer
        | DasAction::EnableSubAccount => {
            dispatch_do_dyn_lib_and_then_exec_eip712_lib(role, &lock_args)
        }
        _ => {
            //func normal validation
            dispatch_to_dyn_lib(role, &lock_args)
        }
    };
    match ret {
        Ok(x) => {
            return if x != 0 {
                debug_log!("general_verification error, return {}", x);
                Err(Error::ValidationFailure)
            } else {
                Ok(())
            }
        }
        Err(e) => {
            debug_log!("general_verification error: {:?}", e);
            Err(e)
        }
    }
}

