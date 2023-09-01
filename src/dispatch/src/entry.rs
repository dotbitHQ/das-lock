extern crate alloc;

use alloc::string::String;
use crate::error::Error;
use ckb_std::{
    ckb_constants::{CellField, Source},

    ckb_types::{bytes::Bytes, packed::Script, prelude::{Unpack, Entity}},
    high_level::{load_script, load_cell_lock_hash, load_script_hash, load_tx_hash},
    syscalls::{self, load_cell_by_field, load_witness, SysError},
};
use core::convert::TryFrom;
use core::result::Result;

use crate::constants::{BLAKE160_SIZE, FLAGS_SIZE, get_balance_type_id, get_sub_account_type_id, get_type_id, HASH_SIZE, MAX_WITNESS_SIZE, ONE_BATCH_SIZE, RIPEMD160_HASH_SIZE, SCRIPT_SIZE, SIGNATURE_SIZE, SIZE_UINT64, WEBAUTHN_SIZE, WITNESS_ARGS_HEADER_LEN, WITNESS_ARGS_LOCK_LEN};
use crate::dlopen::{ckb_auth_dl};
use crate::structures::CmdMatchStatus::{DasNotPureLockCell, DasPureLockCell};
use crate::structures::MatchStatus::{Match, NotMatch};
use crate::structures::SkipSignOrNot::{NotSkip, Skip};
use crate::structures::{DasAction, MatchStatus, Role, AlgId, LockArgs, SkipSignOrNot, SignInfo, CmdMatchStatus};
use crate::utils::{bytes_to_u32_le, check_num_boundary, new_blake2b};
use crate::debug_log;
use crate::utils::generate_sighash_all::{calculate_inputs_len, load_and_hash_witness};


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
    //[0..3] = "das"
    if !data.starts_with(b"das") {
        return Err(Error::InvalidDasWitness);
    }
    //[3..7] is das type, not check here
    // //todo: change the match from u32 to enum
    // let das_type = bytes_to_u32_le(&data[3..7]).unwrap();
    // if das_type != 0 { //only action is 0, others are the enum value
    //     return Err(Error::InvalidDasWitness);
    // }
    //[7..11] is the length of molecule, 4 bytes
    //it should be equal to witness.len() - 7
    let witness_len = data.len();
    if !bytes_to_u32_le(&data[7..11]).is_some_and(|x| x as usize + 7 == witness_len) {
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

    let action = DasAction::from(action_string.as_str());

    //the last bytes of this witness is the params to distinguish owner and manager
    let params_index = temp.len() - 1;
    let params = temp[params_index];

    let role = match Role::try_from(params) {
        Ok(r) => r,
        Err(e) => {
            debug_log!("Role::try_from error: params = {:?}", params);
            return Err(e);
        }
    };

    Ok((action, role))
}

fn get_payload_len(alg_id: u8) -> Result<usize, Error> {
    let alg = AlgId::try_from(alg_id)?;
    match alg {
        AlgId::CkbMultiSig => { Ok(BLAKE160_SIZE + SIZE_UINT64)}
        AlgId::Ed25519 => {Ok(HASH_SIZE)}
        AlgId::DogeCoin => {Ok(RIPEMD160_HASH_SIZE)}
        AlgId::WebAuthn => {Ok(WEBAUTHN_SIZE)}
        _ => {Ok(BLAKE160_SIZE)}
    }
}
fn check_and_downgrade_alg_id(action: &DasAction, alg_id: AlgId) -> AlgId {
    if alg_id != AlgId::Eip712 { //if not Eip712, then return alg_id;
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

    let alg = check_and_downgrade_alg_id(action, AlgId::try_from(alg_id)?);

    let ret = LockArgs::new(alg, payload);
    Ok(ret)
}

#[allow(unused_assignments)]
fn get_self_index_in_inputs() -> Result<usize, Error> {

    let script_hash = load_script_hash()?;
    debug_log!("script_hash = {:02x?}", script_hash);

    let mut i = 0;
    let mut match_result = false;
    loop {
        let lock_hash = load_cell_lock_hash(i, Source::Input)?;
        //if script_hash == lock_hash {
        if script_hash == lock_hash {
            match_result = true;
            break;
        }
        i += 1;
    }
    if !match_result {
        return Err(Error::SelfNotFound);
    }
    Ok(i)
}

fn check_skip_sign_for_buy_account(action: &DasAction, alg_id: AlgId) -> Result<SkipSignOrNot, Error> {
    if alg_id != AlgId::Eip712 {
        return Ok(NotSkip);
    }
    //get self index in inputs
    let script_index = get_self_index_in_inputs()?;

    //if is 0 or 1, then skip
    if script_index != 0 && script_index != 1 {
        return Ok(NotSkip);
    }
    //if is buy_account, then skip
    if *action == DasAction::BuyAccount {
        return Ok(Skip);
    }

    Ok(NotSkip)
}

fn check_the_first_input_cell_must_be_sub_account_type_script() -> Result<MatchStatus, Error> {
    //debug_log!("Enter check_the_first_input_cell_must_be_sub_account_type_script");

    //get sub account type id
    let sub_account_type_id = get_sub_account_type_id();

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
    if *action != DasAction::UpdateSubAccount {
        return Ok(NotSkip);
    }

    match check_the_first_input_cell_must_be_sub_account_type_script() {
        Ok(MatchStatus::Match) => Ok(Skip),
        Ok(MatchStatus::NotMatch) => Err(Error::CheckFailSubAccFirstInputCell),
        Err(e) => Err(e),
    }
}

fn get_plain_and_cipher(alg_id: AlgId) -> Result<SignInfo, Error> {
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

    //check the length
    let lock_length = bytes_to_u32_le(&temp[16..20]).unwrap() as usize;
    let lock_field_start_index = WITNESS_ARGS_HEADER_LEN + 4;
    let lock_field_end_index = lock_field_start_index + lock_length;

    //u32::from_le_bytes(temp[16..20].try_into().unwrap()) as usize;
    if read_len < lock_field_end_index {
        return Err(Error::Encoding);
    }


    if alg_id == AlgId::Eip712 {

        if lock_length != WITNESS_ARGS_LOCK_LEN {
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
    let tx_hash = load_tx_hash()?;

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
    let balance_type_id = get_balance_type_id();
    let mut buf = [0u8; 100];
    for i in 0.. {
        let _len =
            match syscalls::load_cell_by_field(&mut buf, 0, i, Source::GroupInput, CellField::Type)
            {
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
// fn get_payload_from_cell() {
//     //todo here, need witness parser to get payload
// }
pub fn main() -> Result<(), Error> {
    debug_log!("Enter das-lock main.");

    //get witness action
    let action_witness_index = calculate_inputs_len()?;

    let mut temp = [0u8; ONE_BATCH_SIZE];
    debug_log!("Loading witness[{}] to get action", action_witness_index);
    let read_len = load_witness(&mut temp, 0, action_witness_index, Source::Input)?;

    //action should not bigger than MaxWitnessSize
    if read_len > MAX_WITNESS_SIZE {
        return Err(Error::Encoding);
    }

    //get action from witness
    let (das_action, role) = get_witness_action(&temp[..read_len])?;
    debug_log!("Action = {:?}", das_action);

    //check action to decide continue or not
    if SkipSignOrNot::Skip == check_skip_sign(&das_action) {
        debug_log!("skip this action");
        return Ok(());
    }

    //get lock args
    let lock_args = get_lock_args(&das_action, role)?;
    //debug_log!("lock_args = {:02x?}", lock_args);

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

    let sign_info = get_plain_and_cipher(lock_args.alg_id)?;
    debug_log!("Got signature and message : {}", sign_info);

    if lock_args.alg_id == AlgId::WebAuthn {
        let pk_idx = sign_info.signature[1];

        if pk_idx != 255 && pk_idx > 9 {
                return Err(Error::InvalidPubkeyIndex);
        }
    }

    let code_hash = get_type_id(lock_args.alg_id)?;
    debug_log!("code_hash = {:02x?}", code_hash);

    let ret = match ckb_auth_dl(
        u8::from(role),
        lock_args.alg_id,
        <&[u8; 32]>::try_from(code_hash.as_slice()).unwrap(),
        <&[u8; 32]>::try_from(sign_info.message.as_slice()).unwrap(),
        sign_info.signature.as_slice(),
        lock_args.payload.as_slice(),
    ) {
        Ok(x) => x,
        Err(e) => {
            debug_log!("ckb_auth_dl error : {:?}", e);
            return Err(Error::ValidationFailure);
        }
    };
    if ret != 0 {
        debug_log!("Auth failed, ret = {}", ret);
        return Err(Error::ValidationFailure);
    }

    Ok(())
}
// #[cfg(test)]
// fn test_hello_world() {
//     debug_log!("Hello world!");
// }
