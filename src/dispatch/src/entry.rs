extern crate alloc;

use alloc::string::String;
use alloc::{fmt, format, vec};
use alloc::vec::Vec;
use core::mem::size_of;
//use das_core::{code_to_error, debug, util};
use crate::error::Error;
use blake2b_rs::Blake2b;
use ckb_std::ckb_constants::{CellField, InputField, Source};
use ckb_std::ckb_types::packed::{Script, Uint64};
use ckb_std::high_level::{load_cell_lock_hash, load_script_hash, load_tx_hash};
use ckb_std::syscalls::{debug, load_cell, load_cell_by_field, load_input_by_field, load_witness, SysError};
use ckb_std::{
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    high_level::{load_script, load_witness_args},
    syscalls,
};
use core::result::Result;
use das_types::VerificationError;
use core::convert::TryFrom;
const SIZE_UINT64: usize = core::mem::size_of::<u64>();

use crate::constants::{get_balance_type_id, get_sub_account_type_id, get_type_id};
use crate::dlopen::{ckb_auth_dl, CkbAuthError};
use crate::entry::CmdMatchStatus::{DasNotPureLockCell, DasNotSkipCheckSign, DasPureLockCell};
use crate::entry::MatchStatus::{Match, NotMatch};
use crate::entry::SkipSignOrNot::{NotSkip, Skip};
use crate::utils::new_blake2b;
//use log::{debug, trace};
use crate::debug_log;

//use macros::debug_log;
fn calculate_inputs_len() -> Result<usize, Error> {
    let mut temp = [0u8; 8];
    let mut i = 0;
    loop {
        let sysret = load_input_by_field(&mut temp, 0, i, Source::Input, InputField::Since);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }
    Ok(i)
}

pub const MAX_WITNESS_SIZE: usize = 32768;
pub const ONE_BATCH_SIZE: usize = 32768;

pub const SCRIPT_SIZE: usize = 32768;
//use ckb_std::slice;

#[derive(Debug, PartialEq)]
enum CmdMatchStatus {
    //Jump over das-lock
    Skip,
    //manager is not allowed to call this cmd
    ManagerNotAllow,
    //buy account
    BuyAccount,
    //normal cmd
    Normal,
    //DAS_NOT_SKIP_CHECK_SIGN
    DasNotSkipCheckSign,
    //DAS_SKIP_CHECK_SIGN
    DasSkipCheckSign,
    //update sub account
    UpdateSubAccount,
    DasPureLockCell,
    DasNotPureLockCell,
    DasCmdMatch,
    DasCmdNotMatch,
}

#[derive(Debug, PartialEq)]
enum MatchStatus {
    Match,
    NotMatch,
}

#[derive(Debug, PartialEq)]
enum SkipSignOrNot {
    Skip,
    NotSkip,
}

#[derive(Debug, PartialEq)]
enum CmdType {
    Skip,
    ManagerAllowed,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum Role {
    Owner,
    Manager,
}

impl From<Role> for u8 {
    fn from(role: Role) -> u8 {
        match role {
            Role::Owner => 0,
            Role::Manager => 1,
        }
    }
}

impl TryFrom<u8> for Role {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Role::Owner),
            1 => Ok(Role::Manager),
            _ => Err(Error::InvalidRole),
        }
    }
}
#[derive(Debug, PartialEq)]
struct ActionData {
    action: Vec<u8>,
    role: Role,
}

#[derive(Debug)]
struct SignInfo {
    signature: Vec<u8>,
    message: Vec<u8>,
}

impl fmt::Display for SignInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let signature_hex: String = self.signature
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();

        let message_hex: String = self.message
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();

        write!(
            f,
            "SignInfo {{ signature: 0x{}, message: 0x{} }}",
            signature_hex,
            message_hex
        )
    }
}
#[derive(Debug, PartialEq)]
enum DasAction {
    ConfirmProposal,
    RenewAccount,
    AcceptOffer,
    UnlockAccountForCrossChain,
    ForceRecoverAccountStatus,
    RecycleExpiredAccount,
    EditRecords,
    CreateSubAccount,
    UpdateSubAccount,
    ConfigSubAccount,
    ConfigSubAccountCustomScript,
    BuyAccount,
    EnableSubAccount,
    Others,
}
impl From<&str> for DasAction {
    fn from(s: &str) -> DasAction {
        match s {
            "confirm_proposal" => DasAction::ConfirmProposal,
            "renew_account" => DasAction::RenewAccount,
            "accept_offer" => DasAction::AcceptOffer,
            "unlock_account_for_cross_chain" => DasAction::UnlockAccountForCrossChain,
            "force_recover_account_status" => DasAction::ForceRecoverAccountStatus,
            "recycle_expired_account" => DasAction::RecycleExpiredAccount,
            "edit_records" => DasAction::EditRecords,
            "create_sub_account" => DasAction::CreateSubAccount,
            "update_sub_account" => DasAction::UpdateSubAccount,
            "config_sub_account" => DasAction::ConfigSubAccount,
            "config_sub_account_custom_script" => DasAction::ConfigSubAccountCustomScript,
            "buy_account" => DasAction::BuyAccount,
            "enable_sub_account" => DasAction::EnableSubAccount,
            _ => DasAction::Others,
        }
    }
}
fn check_cmd_match(action: &DasAction) -> MatchStatus {
    match action {
        DasAction::ConfirmProposal
        | DasAction::RenewAccount
        | DasAction::AcceptOffer
        | DasAction::UnlockAccountForCrossChain
        | DasAction::ForceRecoverAccountStatus
        | DasAction::RecycleExpiredAccount => MatchStatus::Match,
        _ => MatchStatus::NotMatch,
    }
}
// let action_buf = &action.action;
// let action_len = action_buf.len();
// let role = &action.role;
//
// //1. check if action is in skip list
// let skip_cmds = vec![
//     "confirm_proposal",
//     "renew_account",
//     "accept_offer",
//     "unlock_account_for_cross_chain",
//     "force_recover_account_status",
//     "recycle_expired_account",
// ];
// //
// // let check_table = |cmd: &Vec<u8>, cmds: Vec<&str> | -> CmdMatchStatus {
// //     for c in cmds {
// //         let skip_str_bytes = skip_str.as_bytes();
// //         let skip_str_len = skip_str_bytes.len();
// //
// //         if skip_str_len == action_len  && action_buf == skip_str_bytes.to_vec() {
// //             //debug_log!("match success");
// //             return CmdMatchStatus::Match;
// //         }
// //     }
// //     CmdMatchStatus::NotMatch
// // };
// for skip_str in skip_cmds {
//     let skip_str_bytes = skip_str.as_bytes();
//     let skip_str_len = skip_str_bytes.len();
//
//     if skip_str_len == action_len  && action_buf == skip_str_bytes.to_vec() {
//         //debug_log!("match success");
//         return CmdMatchStatus::DasCmdMatch;
//     }
// }
//
// //2. if the role is manager, check if action is in manager allowed list
// let manager_allowed_cmds = vec![
//     "edit_records",
//     "create_sub_account",
//     "update_sub_account",
//     "config_sub_account",
//     "config_sub_account_custom_script",
// ];
//
// if role == Role::Manager {
//     let mut manager_allowed = false;
//     for manager_allowed_str in manager_allowed_cmds {
//         let manager_allowed_str_bytes = manager_allowed_str.as_bytes();
//         let manager_allowed_str_len = manager_allowed_str_bytes.len();
//
//         if manager_allowed_str_len == action_len  && action_buf == manager_allowed_str_bytes.to_vec() {
//             //debug_log!("match success");
//             manager_allowed = true;
//             break;
//         }
//     }
//     if !manager_allowed { //manager not allowed to call this cmd
//         return CmdMatchStatus::ManagerNotAllow;
//     }
// }
//
// //3. if eht action  is buy account
// let buy_account_cmds ="buy_account";
// let buy_account_cmds_bytes = buy_account_cmds.as_bytes();
// let buy_account_cmds_len = buy_account_cmds_bytes.len();
// if buy_account_cmds_len == action_len  && action_buf == buy_account_cmds_bytes.to_vec() {
//     //debug_log!("match success");
//     return CmdMatchStatus::BuyAccount;
// }
//
// //4. if the action is update_sub_account
// let update_sub_account_cmds = "update_sub_account";
// let update_sub_account_cmds_bytes = update_sub_account_cmds.as_bytes();
// let update_sub_account_cmds_len = update_sub_account_cmds_bytes.len();
// if update_sub_account_cmds_len == action_len  && action_buf == update_sub_account_cmds_bytes.to_vec() {
//     //debug_log!("match success");
//     return CmdMatchStatus::UpdateSubAccount;
// }
// // let target_cmds = match cmd_type {
// //     CmdType::Skip => &skip_cmds,
// //     CmdType::ManagerAllowed => &manager_allowed_cmds,
// // };
// //
// // for &standard_str in target_cmds {
// //     let standard_str_bytes = standard_str.as_bytes();
// //     let standard_str_len = standard_str_bytes.len();
// //
// //     if standard_str_len == action_len  && action_buf == standard_str_bytes.to_vec() {
// //         //debug_log!("match success");
// //         return CmdMatchStatus::Match;
// //     }
// // }
//
// CmdMatchStatus::DasCmdNotMatch

fn bytes_to_u32_le(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(
        ((bytes[3] as u32) << 24)
            | ((bytes[2] as u32) << 16)
            | ((bytes[1] as u32) << 8)
            | (bytes[0] as u32),
    )
}
fn check_num_boundary(num: u32, min: u32, max: u32) -> Result<(), Error> {
    if num < min || num > max {
        //debug_log!("num not in boundary");
        return Err(Error::NumOutOfBound);
    }
    Ok(())
}
fn check_das_witness(data: &[u8]) -> Result<(), Error> {
    //[0..3] = "das"
    if !data.starts_with(b"das") {
        //debug_log!("witness does not start with das");
        return Err(Error::InvalidDasWitness);
    }
    //[3..7] is das type

    //[7..11] is the length of molecule
    let witness_len = data.len();
    if !bytes_to_u32_le(&data[7..11]).is_some_and(|x| x as usize + 7 == witness_len){
        return Err(Error::InvalidDasWitness);
    }
    //let molecule_len = bytes_to_u32_le(&data[7..11]) as usize;
    // if witness_len != molecule_len + 7 {
    //     //debug_log!("witness len not match molecule len");
    // }
    Ok(())
}
fn get_action_from_witness(temp: &[u8]) -> Result<(DasAction, Role), Error> {
    //debug_log!("Enter get_action_from_witness");
    //check if action witness
    check_das_witness(temp)?;

    //the action data map
    //[0..3] = "das"
    //[3..7] = das type
    //[7..11] = molecule toal len
    //[11..15] = action offset
    //[15..19] = params offset
    //[19..23] = action len
    //[23..23+action_len] = action
    //[23+action_len..23+action_len+4] = params len
    //[23+action_len+4..23+action_len+4+params_len] = params
    //[data.len()-1] = is owner or manager

    //get action len
    let action_len_index = 19;
    let action_len = bytes_to_u32_le(&temp[action_len_index..action_len_index + 4]).unwrap_or(0);
    check_num_boundary(action_len, 1, 255)?;

    let action_start = action_len_index + 4;
    let action_end = action_start + action_len as usize;

    let action_string =
        String::from_utf8(temp[action_start..action_end].to_vec()).map_err(|_| Error::InvalidString)?;
    //let a = action_string.as_str();;
    let action = DasAction::from(action_string.as_str());

    //the last bytes is params to distinguish owner and manager
    let params_index = temp.len() - 1;
    let params = temp[params_index];

    let role = match Role::try_from(params){
        Ok(r) => {r}
        Err(e) => {
            debug_log!("Role::try_from error: params = {:?}", params);
            return Err(e);
        }
    };
    //let role = Role::try_from(params).ok_or(Error::InvalidRole)?;

    Ok((action, role))
}
#[derive(Debug)]
struct LockArgs {
    alg_id: u8,
    payload: Vec<u8>,
}
fn get_payload_len(alg_id: u8) -> Result<usize, Error> {
    match alg_id {
        1 => Ok(20 + SIZE_UINT64),
        6 => Ok(32),
        8 => Ok(21),
        0 | 2 | 3 | 4 | 5 | 7 => Ok(20),
        _ => Err(Error::InvalidAlgId),
    }
}
fn check_and_downgrade_alg_id(action: &DasAction, alg_id: u8) -> u8 {
    if alg_id != 5 {
        return alg_id;
    }
    match action {
        DasAction::EnableSubAccount
        | DasAction::CreateSubAccount
        | DasAction::ConfigSubAccount
        | DasAction::ConfigSubAccountCustomScript => 3,
        _ => 5,
    }
    // let downgrade_algorithm_id = vec![
    //     "enable_sub_account",
    //     "create_sub_account",
    //     "config_sub_account",
    //     "config_sub_account_custom_script"
    // ];
    // //debug_log!("alg_id is 5, downgrade to 3");
    // let action_vec = &action.action;
    // let action_len = action_vec.len();
    // let mut in_list = false;
    // for s in downgrade_algorithm_id {
    //     let s_bytes = s.as_bytes();
    //     let s_len = s_bytes.len();
    //
    //     if s_len == action_len  && action_vec == s_bytes.to_vec() {
    //         //debug_log!("match success");
    //         in_list = true;
    //         break;
    //     }
    // }
    // return if in_list {
    //     3
    // } else {
    //     5
    // }
}
fn get_lock_args(action: &DasAction, role: Role) -> Result<LockArgs, Error> {
    //debug_log!("Enter get_lock_args");
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    let args_len = args.len();
    let args_slice = args.as_ref();
    let alg_id = args_slice[0];

    let payload1_len = get_payload_len(alg_id)?;

    // let payload = args_slice[1..args_len].to_vec();
    let (payload_start_idx, payload_end_index) = {
        match role {
            Role::Owner => {
                let start = 1;
                let end = start + payload1_len;
                (start, end)
            }
            Role::Manager => {
                let manager_alg_idx = 1 + payload1_len;
                let payload2_len = get_payload_len(args_slice[manager_alg_idx])?;
                let start = 1 + payload1_len + 1;
                let end = start + payload2_len;
                (start, end)
            }
        }
    };
    let payload = args_slice[payload_start_idx..payload_end_index].to_vec();

    let alg_id = check_and_downgrade_alg_id(action, alg_id);

    Ok(LockArgs { alg_id, payload })
}

fn get_self_index_in_inputs() -> Result<usize, Error> {
    //debug_print("Enter get_self_index_in_inputs");

    let script_hash = load_script_hash()?;

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
        //debug_print("not match");
        return Err(Error::SelfNotFound);
    }
    Ok(i)
}

fn check_skip_sign_for_buy_account(action: &DasAction, alg_id: u8) -> Result<SkipSignOrNot, Error> {
    if alg_id != 5 {
        return Ok(NotSkip);
    }
    //debug_log!("Enter check_skip_sign_for_buy_account");
    //get self index in inputs
    //check if is 0 or 1
    //if
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

    let script = match Script::from_slice(&temp[..read_len]){
        Ok(s) => {s}
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

fn load_and_hash_witness(
    ctx: &mut Blake2b,
    start: usize,
    index: usize,
    source: Source,
    hash_length: bool,
) -> Result<(), SysError> {
    let mut temp = [0u8; ONE_BATCH_SIZE];
    let len = load_witness(&mut temp, start, index, source)?;
    if hash_length {
        ctx.update(&(len as u64).to_le_bytes());
    }
    let mut offset = if len > ONE_BATCH_SIZE {
        ONE_BATCH_SIZE
    } else {
        len
    };
    ctx.update(&temp[..offset]);
    while offset < len {
        let current_len = load_witness(&mut temp, start + offset, index, source)?;
        let current_read = if current_len > ONE_BATCH_SIZE {
            ONE_BATCH_SIZE
        } else {
            current_len
        };
        ctx.update(&temp[..current_read]);
        offset += current_read;
    }
    Ok(())
}

// fn calculate_inputs_len() -> Result<usize, Error> {
//     let mut temp = [0u8; 8];
//     let mut i = 0;
//     loop {
//         let sysret = load_input_by_field(&mut temp, 0, i, Source::Input, InputField::Since);
//         match sysret {
//             Err(SysError::IndexOutOfBound) => break,
//             Err(x) => return Err(x.into()),
//             Ok(_) => i += 1,
//         }
//     }
//     Ok(i)
// }
fn check_skip_sign_for_updata_sub_account(action: &DasAction) -> Result<SkipSignOrNot, Error> {
    if *action != DasAction::UpdateSubAccount {
        return Ok(NotSkip);
    }

    match check_the_first_input_cell_must_be_sub_account_type_script() {
        Ok(MatchStatus::Match) => Ok(Skip),
        Ok(MatchStatus::NotMatch) => Err(Error::CheckFailSubAccFirstInputCell),
        Err(e) => Err(e),
    }
    // if cms == CmdMatchStatus::UpdateSubAccount {
    //     let ret = match check_the_first_input_cell_must_be_sub_account_type_script()?{
    //         CmdMatchStatus::DasSkipCheckSign => {
    //             Ok(CmdMatchStatus::DasSkipCheckSign)
    //         }
    //         _ => {
    //             Ok(CmdMatchStatus::DasNotSkipCheckSign)
    //         }
    //     };
    //     return ret;
    // }
    //
    // Ok(CmdMatchStatus::DasNotSkipCheckSign)
}
fn get_plain_and_cipher(alg_id: u8) -> Result<SignInfo, Error> {
    let mut temp = [0u8; MAX_WITNESS_SIZE];

    // Load witness of first input.
    let mut read_len = load_witness(&mut temp, 0, 0, Source::GroupInput)?;
    let witness_len = read_len;
    if read_len > MAX_WITNESS_SIZE {
        read_len = MAX_WITNESS_SIZE;
    }

    // Load signature.
    if read_len < 20 {
        return Err(Error::Encoding);
    }
    let lock_length = u32::from_le_bytes(temp[16..20].try_into().unwrap()) as usize;
    if read_len < 20 + lock_length {
        return Err(Error::Encoding);
    }

    let signature = temp[20..20 + lock_length].to_vec();

    if alg_id == 5 {
        //check  length
        if lock_length != 64 + 32 + 8 {
            //debug_log!("witness_args_lock_len != 64 + 32");
            return Err(Error::InvalidWitnessArgsLock);
        }

        //copy signature
        let signature = temp[20..20 + 64].to_vec();

        //copy message
        let message = temp[20 + 64..20 + 64 + 32].to_vec();

        return Ok(SignInfo { signature, message });
    }

    // Clear lock field to zero, then digest the first witness
    // lock_bytes_seg.ptr actually points to the memory in temp buffer.
    if alg_id == 1 {
        let threshold = temp[20 + 2];
        let pubkeys_cnt = temp[20 + 3];
        let multisig_script_len = 4 + 20 * pubkeys_cnt as usize;
        let sig_len = 64 * threshold as usize;
        let required_lock_len = multisig_script_len + sig_len;
        if required_lock_len != lock_length {
            //debug_log!("required_lock_len != lock_length");
            return Err(Error::InvalidWitnessArgsLock);
        }
        let start = 20 + multisig_script_len;
        temp[20 + multisig_script_len..20 + lock_length].fill(0);
    } else {
        temp[20..20 + lock_length].fill(0);
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
//
// fn get_plain_and_cipher(alg_id: u8) -> Result<SignInfo, Error>{
//     //get witness 0
//     //parse to get witness_args.lock
//     let witness_args =
//         load_witness_args(0, Source::GroupInput).map_err(|_| Error::WitnessError)?;
//
//     let witness_args_lock_len_vec = witness_args.as_slice()[16..20].to_vec();
//     let witness_args_lock_len = bytes_to_u32_le(&witness_args_lock_len_vec)? as usize;
//
//     let witness_args_lock = witness_args.as_slice()[20..].to_vec();
//     if witness_args_lock_len != witness_args_lock.len() {
//         //debug_log!("witness_args_lock_len != witness_args_lock.len()");
//         return Err(Error::InvalidWitnessArgsLock);
//     }
//
//     //if alg_id == 5
//         //copy signature
//         //return
//     if alg_id == 5 {
//         //check  length
//         if witness_args_lock_len != 64 + 32  + 8{
//             //debug_log!("witness_args_lock_len != 64 + 32");
//             return Err(Error::InvalidWitnessArgsLock);
//         }
//
//         //copy signature
//         let signature = witness_args_lock[0..64].to_vec();
//
//         //copy message
//         let message = witness_args_lock[64..64+32].to_vec();
//
//         return Ok(SignInfo {
//             signature,
//             message,
//         });
//     }
//
//     let mut multisig_script_len = 0;
//     if alg_id == 1 {
//         let threshold = witness_args_lock[2];
//         let pubkeys_cnt = witness_args_lock[3];
//
//         multisig_script_len = 4 + 20 * pubkeys_cnt as usize;
//         let signature_len = 64 * threshold as usize;
//         let required_lock_len = multisig_script_len + signature_len;
//
//         if required_lock_len != witness_args_lock_len {
//             //debug_log!("required_lock_len != witness_args_lock_len");
//             return Err(Error::InvalidWitnessArgsLock);
//         }
//     }
//     let tx_hash = load_tx_hash()?;
//
//
//
//
//     //copy to lock bytes
//     //if alg_id == 1
//     //get tx_hash
//     //calculate message
//
//     Ok(())
// }
pub fn find_cell_by_type_id(type_id: &[u8], source: Source) -> Result<Option<usize>, SysError> {
    let mut buf = [0u8; 100];
    for i in 0.. {
        let len = match syscalls::load_cell_by_field(&mut buf, 0, i, source, CellField::Type) {
            Ok(len) => len,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err),
        };

        //debug_assert_eq!(len, buf.len());
        if type_id == &buf[16..] {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

fn check_has_pure_type_script() -> CmdMatchStatus {
    let balance_type_id = get_balance_type_id();
    // if DasPureLockCell == check_input_cell_is_pure_type_script(balance_type_id.as_slice()) {
    //         return Ok(CmdMatchStatus::DasNotSkipCheckSign);
    // }
    let mut buf = [0u8; 100];
    for i in 0.. {
        let len =
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
    // match find_cell_by_type_id(balance_type_id.as_slice(), Source::GroupInput)? {
    //     Some(_) => {
    //         //debug_log!("has pure type script");
    //         Ok(CmdMatchStatus::DasSkipCheckSign)
    //     }
    //     None => {
    //         //debug_log!("has no pure type script");
    //         Ok(CmdMatchStatus::DasNotSkipCheckSign)
    //     }
    // }
}
fn check_skip_sign(action: &DasAction) -> SkipSignOrNot {
    if DasPureLockCell == check_has_pure_type_script() {
        return SkipSignOrNot::NotSkip;
    }

    match check_cmd_match(action) {
        Match => SkipSignOrNot::Skip,
        NotMatch => SkipSignOrNot::NotSkip,
    }
    // let ret = match cmd_status {
    //     CmdMatchStatus::DasCmdMatch | CmdMatchStatus::BuyAccount  => {
    //         //debug_log!("skip this action");
    //         Ok(Skip)
    //     },
    //     CmdMatchStatus::ManagerNotAllow => {
    //         Err(Error::ManagerNotAllowed)
    //     }
    //     CmdMatchStatus::UpdateSubAccount => {
    //         if Match == check_the_first_input_cell_must_be_sub_account_type_script()? {
    //             Ok(Skip)
    //         }else {
    //             Ok(NotSkip)
    //         }
    //     }
    //     _ => {Ok(NotSkip)}
    // };
}
fn get_payload_from_cell() {
    //todo here, need witness parser to get payload
}
pub fn main() -> Result<(), Error> {
    //ckb_std::syscalls::debug(alloc::format!("hello, this is new dispatcher, good luck!"));
    debug_log!("hello guy, this is debug_log");
    //debug!("hello guy, this is debug");
    //get witness action
    let action_witness_index = calculate_inputs_len()?;
    debug_log!("action_witness_index = {}", action_witness_index);

    let mut temp = [0u8; ONE_BATCH_SIZE]; //
    let mut read_len = load_witness(&mut temp, 0, action_witness_index, Source::Input)?;
    //let mut read_len = load_witness(&mut temp, 0, action_witness_index, Source::GroupInput)?;
    debug_log!("read_len = {}", read_len);

    let witness_len = read_len;
    if read_len > MAX_WITNESS_SIZE {
        read_len = MAX_WITNESS_SIZE;
    }
    //get action from witness
    let (das_action, role) = get_action_from_witness(&temp[..read_len])?;
    debug_log!("das_action = {:?}", das_action);

    //check action to decide continue or not
    if SkipSignOrNot::Skip == check_skip_sign(&das_action) {
        debug_log!("skip this action");
        return Ok(());
    }

    //
    //
    // let cmd_status = check_cmd_match(&action_data);
    // match cmd_status {
    //     CmdMatchStatus::DasCmdMatch => {
    //         //debug_log!("skip this action");
    //         return Ok(());
    //     },
    //     CmdMatchStatus::ManagerNotAllow => {
    //         //debug_log!("manager not allow to call this action");
    //         return Err(Error::ManagerNotAllowed);
    //     },
    //     // CmdMatchStatus::BuyAccount => {
    //     //     //debug_log!("buy account action");
    //     // },
    //     // CmdMatchStatus::Normal => {
    //     //     //debug_log!("normal action");
    //     // },
    //     _ => {}
    // }
    //get lock args
    let lock_args = get_lock_args(&das_action, role)?;
    //debug_log!("lock_args = {:02x?}", lock_args);

    //check skip sign for buy account
    let das_skip_check_sign = check_skip_sign_for_buy_account(&das_action, lock_args.alg_id)?;
    if das_skip_check_sign == SkipSignOrNot::Skip {
        //debug_log!("skip check sign");
        return Ok(());
    }

    let das_skip_check_sign = check_skip_sign_for_updata_sub_account(&das_action)?;
    if SkipSignOrNot::Skip == das_skip_check_sign {
        //debug_log!("skip check sign");
        return Ok(());
    }

    let sign_info = get_plain_and_cipher(lock_args.alg_id)?;
    //debug_log!("sign_info = {:02x?}", sign_info);

    if lock_args.alg_id == 8 {
        let pk_idx = sign_info.signature[1];

        if pk_idx != 255 {
            if pk_idx > 9 {
                return Err(Error::InvalidPubkeyIndex);
            }
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
    ){
        Ok(x) => {x}
        Err(e) => {
            debug_log!("ckb_auth_dl error : {:?}", e);
            return Err(Error::ValidationFailure);
        }
    };
    if ret != 0 {
        debug_log!("ckb_auth_dl error");
        return Err(Error::ValidationFailure);
    }

    //get alg id
    //if alg_id = 5 , jump over das-lock
    //get plain and cipher
    //if alg == 8
    //get code hash
    //ckb dlopen2
    //try to call validate

    Ok(())
}
