extern crate alloc;

use crate::error::Error;
use alloc::string::String;
use alloc::vec::Vec;
use ckb_std::high_level::{load_cell_type, load_cell_type_hash, load_witness_args};
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
use crate::dlopen::ckb_auth_dl;
use crate::structures::CmdMatchStatus::{DasNotPureLockCell, DasPureLockCell};
use crate::structures::MatchStatus::{Match, NotMatch};
use crate::structures::{
    AlgId, CmdMatchStatus, DasAction, LockArgs, MatchStatus, SignInfo, SkipSignOrNot,
};
use crate::utils::generate_sighash_all::{calculate_inputs_len, load_and_hash_witness};
use crate::utils::{bytes_to_u32_le, check_num_boundary, new_blake2b};
use crate::constants::{
    get_account_type_id, get_balance_type_id, get_dp_cell_type_id, get_sub_account_type_id,
    get_type_id,
};
use das_types::constants::LockRole as Role;
use das_proc_macro::{test_level};

#[cfg(test)]
use crate::test_framework::Testable;

fn check_cmd_match(action: &DasAction) -> MatchStatus {
    match action {
        DasAction::ConfirmProposal
        | DasAction::RenewAccount
        | DasAction::AcceptOffer
        | DasAction::UnlockAccountForCrossChain
        | DasAction::ForceRecoverAccountStatus
        | DasAction::RecycleExpiredAccount
        | DasAction::RevokeApproval
        | DasAction::FulfillApproval => MatchStatus::Match,
        _ => MatchStatus::NotMatch,
    }
}


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
        DasAction::EnableSubAccount
        | DasAction::CreateSubAccount
        | DasAction::ConfigSubAccount
        | DasAction::ConfigSubAccountCustomScript => AlgId::Eth, //3
        _ => AlgId::Eip712,
    }
}
fn get_lock_args(action: &DasAction, role: Role) -> Result<LockArgs, Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    //let args_len = args.len();
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
    let mut match_result;
    loop {
        let lock_hash = load_cell_lock_hash(i, Source::Input)?;
        debug_log!("loaded {} : lock_hash = {:02x?}", i, lock_hash);
        //if script_hash == lock_hash {
        if script_hash == lock_hash {
            match_result = true;
            break;
        } else {
            match_result = false;
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
    let dp_cell_type_id = get_dp_cell_type_id()?;
    debug_log!("dp_cell_type_id = {:02x?}", dp_cell_type_id);

    for i in 0..100 {
        match load_cell_type(i, Source::Input) {
            Ok(type_script) => {

                if type_script.is_some()  {
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

fn check_skip_sign_for_buy_account(
    action: &DasAction,
    alg_id: AlgId,
) -> Result<SkipSignOrNot, Error> {
    debug_log!("Enter check_skip_sign_for_buy_account");
    if alg_id != AlgId::Eip712 {
        return Ok(SkipSignOrNot::NotSkip);
    }
    //get self index in inputs
    let script_index = get_self_index_in_inputs()?;

    //if is 0 or 1, then skip
    if script_index != 0 && script_index != 1 {
        return Ok(SkipSignOrNot::NotSkip);
    }
    //if is buy_account, then skip
    if *action == DasAction::BuyAccount {
        return Ok(SkipSignOrNot::Skip);
    }

    Ok(SkipSignOrNot::NotSkip)
}
fn check_skip_sign_for_bid_expired_auction(action: &DasAction) -> Result<SkipSignOrNot, Error> {
    debug_log!("Enter check_skip_sign_for_bid_expired_auction");
    if *action != DasAction::BidExpiredAccountAuction {
        return Ok(SkipSignOrNot::NotSkip);
    }

    //AccountCell is always inputs[0], guarantee it through the account-cell-type.
    let script_index = get_self_index_in_inputs()?;
    debug_log!("get_self_index_in_inputs self index = {:?}", script_index);

    let current_type_script = load_cell_type(script_index, Source::Input)?
        .expect("type script should exist");
    let current_type_script_args = current_type_script.code_hash().raw_data().to_vec();
    //debug_log!("current_type_script_args = {}", hex_string(current_type_script_args.as_slice()));

    let account_cell_type_id = get_account_type_id()?;
    let current_lock_script_hash = load_cell_lock_hash(script_index, Source::Input)?.to_vec();
    //debug_log!("current_lock_script_hash = {}", hex_string(current_lock_script_hash.as_slice()));

    //dp-cell-type ensures that the locks of all dp cells in inputs are the same.
    let dp_cell_lock_hash = get_first_dp_cell_lock_hash()?; //
    //debug_log!("dp_cell_lock_hash = {}", hex_string(dp_cell_lock_hash.as_slice()));

    debug_log!("current_lock_script_hash = {}", hex_string(current_lock_script_hash.as_slice()));
    debug_log!("dp_cell_lock_hash = {}", hex_string(dp_cell_lock_hash.as_slice()));
    debug_log!("current_type_script_args = {}", hex_string(current_type_script_args.as_slice()));
    debug_log!("account_cell_type_id = {}", hex_string(account_cell_type_id.as_slice()));

    //Signature verification can be skipped only if the following two conditions are met.
    //1. The current lock is not equal to the lock of dp cell
    //2. The current type is account-cell-type
    if current_lock_script_hash != dp_cell_lock_hash &&  current_type_script_args == account_cell_type_id {
        debug_log!("jump over the signature verification of the Dutch auction");
        return Ok(SkipSignOrNot::Skip);
    }

    Ok(SkipSignOrNot::NotSkip)
}

fn check_the_first_input_cell_must_be_sub_account_type_script() -> Result<MatchStatus, Error> {
    //debug_log!("Enter check_the_first_input_cell_must_be_sub_account_type_script");

    //get sub account type id
    let sub_account_type_id = get_sub_account_type_id()?;

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

fn check_skip_sign_for_update_sub_account(action: &DasAction) -> Result<SkipSignOrNot, Error> {
    debug_log!("Enter check_skip_sign_for_update_sub_account");
    if *action != DasAction::UpdateSubAccount {
        return Ok(SkipSignOrNot::NotSkip);
    }

    match check_the_first_input_cell_must_be_sub_account_type_script() {
        Ok(Match) => Ok(SkipSignOrNot::Skip),
        Ok(NotMatch) => Err(Error::CheckFailSubAccFirstInputCell),
        Err(e) => Err(e),
    }
}
#[allow(dead_code)]
fn get_witness_args_lock() -> Result<Vec<u8>, Error> {
    let witness_args =
        match load_witness_args(0, Source::GroupInput).map_err(|_| Error::WitnessError) {
            Ok(v) => v,
            Err(e) => {
                debug_log!("load_witness_args error: {:?}", e);
                return Err(Error::WitnessError);
            }
        };
    Ok(witness_args.as_slice()[20..].to_vec())
}
fn get_plain_and_cipher(alg_id: AlgId) -> Result<SignInfo, Error> {
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

// pub fn find_cell_by_type_id(type_id: &[u8], source: Source) -> Result<Option<usize>, SysError> {
//     let mut buf = [0u8; 100];
//     for i in 0.. {
//         let _len = match syscalls::load_cell_by_field(&mut buf, 0, i, source, CellField::Type) {
//             Ok(len) => len,
//             Err(SysError::IndexOutOfBound) => break,
//             Err(err) => return Err(err),
//         };
//
//         //debug_assert_eq!(len, buf.len());
//         if type_id == &buf[16..] {
//             return Ok(Some(i));
//         }
//     }
//     Ok(None)
// }

fn check_has_pure_type_script() -> CmdMatchStatus {
    let balance_type_id = get_balance_type_id().unwrap();
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

    match check_cmd_match(action) {
        Match => SkipSignOrNot::Skip,
        NotMatch => SkipSignOrNot::NotSkip,
    }
}
//return true if has permission
fn check_manager_has_permission(action: &DasAction, role: Role) -> bool {
    if role != Role::Manager {
        return true;
    }
    match action {
        DasAction::EditRecords
        | DasAction::CreateSubAccount
        | DasAction::UpdateSubAccount
        | DasAction::ConfigSubAccount
        | DasAction::ConfigSubAccountCustomScript => true,
        _ => false,
    }
}

pub fn main() -> Result<(), Error> {
    debug_log!("Enter das-lock main.");

    //get witness action
    let action_witness_index = calculate_inputs_len()?;

    let mut temp = [0u8; ONE_BATCH_SIZE];
    debug_log!("Loading witness[{}] to get action", action_witness_index);
    let read_len = load_witness(&mut temp, 0, action_witness_index, Source::Input)?;

    //action should not bigger than MaxWitnessSize
    if read_len > MAX_WITNESS_SIZE {
        debug_log!(
            "Action witness's length is overflow! read len = {:?}, MAX_WITNESS_SIZE = {:?}",
            read_len,
            MAX_WITNESS_SIZE
        );
        return Err(Error::LengthNotEnough);
    }

    //get action from witness
    let (das_action, role) = get_witness_action(&temp[..read_len])?;
    debug_log!("Action = {:?}, role = {:?}", das_action, role);

    //check action to decide continue or not
    if SkipSignOrNot::Skip == check_skip_sign(&das_action) {
        debug_log!("Skip this action, {:?}", das_action);
        return Ok(());
    }

    //check if manager has permission to do this action
    if !check_manager_has_permission(&das_action, role) {
        debug_log!("Manager does not have permission to execute this action.");
        return Err(Error::ManagerNotAllowed);
    }

    //get lock args
    let lock_args = get_lock_args(&das_action, role)?;
    debug_log!("Lock args = {}", lock_args);

    //check skip sign for buy account
    let ret = check_skip_sign_for_buy_account(&das_action, lock_args.alg_id)?;
    if ret == SkipSignOrNot::Skip {
        debug_log!("Skip check sign for buy account.");
        return Ok(());
    }

    let ret = check_skip_sign_for_update_sub_account(&das_action)?;
    if ret == SkipSignOrNot::Skip {
        debug_log!("Skip check sign for update sub account.");
        return Ok(());
    }

    //add for dutch auction
    if SkipSignOrNot::Skip == check_skip_sign_for_bid_expired_auction(&das_action)? {
        debug_log!("Skip this action, {:?}", das_action);
        return Ok(());
    }
    //get sign info
    let sign_info = get_plain_and_cipher(lock_args.alg_id)?;
    debug_log!("Got signature and message : {}", sign_info);

    if lock_args.alg_id == AlgId::WebAuthn {
        let pk_idx = sign_info.signature[1];

        if pk_idx != 255 && pk_idx > 9 {
            debug_log!("Invalid pk_idx = {}", pk_idx);
            return Err(Error::InvalidPubkeyIndex);
        }
    }

    //get type id
    let code_hash = get_type_id(lock_args.alg_id)?;
    debug_log!(
        "alg{} code hash = {}",
        lock_args.alg_id as u8,
        hex::encode(&code_hash)
    );

    //call dynamic linking and run auth
    let ret = match ckb_auth_dl(
        role as u8,
        lock_args.alg_id,
        <&[u8; 32]>::try_from(code_hash.as_slice()).unwrap(),
        <&[u8; 32]>::try_from(sign_info.message.as_slice()).unwrap(),
        sign_info.signature.as_slice(),
        lock_args.payload.as_slice(),
    ) {
        Ok(x) => x,
        Err(e) => {
            debug_log!("auth dl error : {:?}", e);
            return Err(Error::ValidationFailure);
        }
    };
    if ret != 0 {
        debug_log!("Auth failed, ret = {}", ret);
        return Err(Error::ValidationFailure);
    }

    Ok(())
}

//unit tests

#[test_level(1)]
fn test_get_payload_len() {
    let expected_payload_len = [
        20, //0, ckb
        28, //1, ckb multi
        20, //2, always success
        20, //3, eth
        20, //4, tron
        20, //5, eip712
        32, //6, ed25519
        20, //7, doge
        21, //8, webauthn
    ];
    for i in 0..expected_payload_len.len() {
        let alg_id = i as u8;
        let ret = get_payload_len(alg_id);
        match ret {
            Ok(x) => {
                assert_eq!(x, expected_payload_len[i]);
            }
            Err(e) => {
                panic!("get_payload_len error: {:?}", e);
            }
        }
    }
}

#[test_level(1)]
fn test_check_and_downgrade_alg_id() {
    //alg != eip712
    let action = DasAction::EnableSubAccount;
    let alg_id = AlgId::Ckb;
    let ret = check_and_downgrade_alg_id(&action, alg_id);
    assert_eq!(ret, AlgId::Ckb);

    //action match downgrade list
    let action = DasAction::EnableSubAccount;
    let alg_id = AlgId::Eip712;
    let ret = check_and_downgrade_alg_id(&action, alg_id);
    assert_eq!(ret, AlgId::Eth);
}

//test get_lock_args
#[test_level(2)]
fn test_get_lock_args() {
    //note here, the payload is not the real payload, just for test
    //how to run all test case in on tx? sandbox only
    let ret = load_script();
    match ret {
        Ok(s) => {
            debug_log!("load_script success: {:?}", s);
        }
        Err(e) => {
            panic!("load_script error: {:?}", e);
        }
    }
}

//tx should map with test case
