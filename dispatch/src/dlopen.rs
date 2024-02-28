extern crate alloc;

use crate::constants::get_dyn_lib_desc_info;
use crate::error::Error;
use crate::structures::{AlgId, LockArgs, SignInfo};
use crate::tx_parser::get_type_id_by_type_script;
use crate::utils::generate_sighash_all::MAX_WITNESS_SIZE;
use alloc::collections::BTreeMap;
use alloc::ffi::NulError;
use alloc::vec::Vec;
use alloc::{fmt, vec};
use ckb_std::dynamic_loading_c_impl::{CKBDLContext, Library};
use ckb_std::{ckb_types::core::ScriptHashType, debug, dynamic_loading_c_impl::Symbol, high_level, syscalls::SysError};
use core::mem::size_of_val;
use das_core::util::hex_string;
use das_types::constants::Action as DasAction;
use das_types::constants::LockRole as Role;
use das_types::constants::{LockRole, TypeScript};
use hex::encode;
#[allow(dead_code)]
#[derive(Debug)]
pub enum CkbAuthError {
    UnknownAlgorithmID,
    DynamicLinkingUninit,
    LoadDLError,
    LoadDLFuncError,
    RunDLError,
    ExecError(SysError),
    EncodeArgs,
}

impl From<SysError> for CkbAuthError {
    fn from(err: SysError) -> Self {
        debug!("exec error: {:?}", err);
        Self::ExecError(err)
    }
}

impl From<NulError> for CkbAuthError {
    fn from(err: NulError) -> Self {
        debug!("Exec encode args failed: {:?}", err);
        Self::EncodeArgs
    }
}

impl fmt::Display for CkbAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CkbAuthError::UnknownAlgorithmID => write!(f, "Unknown Algorithm ID"),
            CkbAuthError::DynamicLinkingUninit => write!(f, "Dynamic Linking is uninitialized"),
            CkbAuthError::LoadDLError => write!(f, "Error loading dynamic library"),
            CkbAuthError::LoadDLFuncError => {
                write!(f, "Error loading function from dynamic library")
            }
            CkbAuthError::RunDLError => write!(f, "Error running dynamic library code"),
            CkbAuthError::ExecError(err) => write!(f, "Execution error: {:?}", err),
            CkbAuthError::EncodeArgs => write!(f, "Error encoding arguments"),
        }
    }
}

pub enum EntryCategoryType {
    Exec = 0,
    DynamicLinking = 1,
    //Spawn = 2,
}
pub struct DynLibDesc {
    pub dyn_lib_name: &'static str,
    pub code_hash: [u8; 32],
    pub hash_type: ScriptHashType,
    pub entry_category: EntryCategoryType,
    pub entry_name: Vec<&'static str>,
}

impl From<u8> for EntryCategoryType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Exec,
            1 => Self::DynamicLinking,
            //2 => Self::Spawn,
            _ => panic!("invalid entry category type"),
        }
    }
}

impl Into<u8> for EntryCategoryType {
    fn into(self) -> u8 {
        self as u8
    }
}
pub struct CkbEntryType {
    pub code_hash: [u8; 32],
    pub hash_type: ScriptHashType,
    pub entry_category: EntryCategoryType,
}

type DLContext = CKBDLContext<[u8; 256 * 1024]>; //each is 256k
type CkbAuthValidate =
    unsafe extern "C" fn(type_: i32, message: *const u8, lock_bytes: *const u8, lock_args: *const u8) -> i32;

struct CKBDLLoader {
    pub context: DLContext,
    pub context_used: usize,
    pub loaded_lib: BTreeMap<[u8; 33], Library>,
}

static mut G_CKB_DL_LOADER: Option<CKBDLLoader> = None;
impl CKBDLLoader {
    pub fn get() -> &'static mut Self {
        unsafe {
            G_CKB_DL_LOADER.as_mut().unwrap_or_else(|| {
                G_CKB_DL_LOADER = Some(Self::new());
                G_CKB_DL_LOADER.as_mut().unwrap()
            })
        }
    }

    fn new() -> Self {
        Self {
            context: unsafe { DLContext::new() },
            context_used: 0,
            loaded_lib: BTreeMap::new(),
        }
    }

    fn get_lib(&mut self, code_hash: &[u8; 32], hash_type: ScriptHashType) -> Result<&Library, CkbAuthError> {
        let mut lib_key = [0u8; 33];
        lib_key[..32].copy_from_slice(code_hash);
        lib_key[32] = hash_type as u8;

        let has_lib = match self.loaded_lib.get(&lib_key) {
            Some(_) => true,
            None => false,
        };

        if !has_lib {
            debug!("loading library");
            let size = size_of_val(&self.context);
            let lib = self
                .context
                .load_with_offset(code_hash, hash_type, self.context_used, size)
                .map_err(|_| {
                    debug!("load library error");
                    CkbAuthError::LoadDLError
                })?;
            self.context_used += lib.consumed_size();
            self.loaded_lib.insert(lib_key.clone(), lib);
        };
        Ok(self.loaded_lib.get(&lib_key).unwrap())
    }

    pub fn get_validate_func<T>(
        &mut self, code_hash: &[u8; 32], hash_type: ScriptHashType, func_name: &str,
    ) -> Result<Symbol<T>, CkbAuthError> {
        debug!("Prepare to load function {} from dynamic linking.", func_name);

        let lib = self.get_lib(code_hash, hash_type)?;
        debug!("Load function {} from dynamic linking success.", func_name);

        let func: Option<Symbol<T>> = unsafe { lib.get(func_name.as_bytes()) };
        if func.is_none() {
            debug!("Load function {} from dynamic linking failed.", func_name);
            return Err(CkbAuthError::LoadDLFuncError);
        }

        Ok(func.unwrap())
    }
}
pub fn ckb_auth_dl(
    role: Role, alg_id: AlgId, message: &[u8], signature: &[u8], payload: &[u8], entry_func_name: &str,
) -> Result<i8, CkbAuthError> {
    debug!("Prepare to run auth in dynamic linking.");
    debug!("role: {:?}", role);
    debug!("alg_id: {}", alg_id);
    debug!("message: {}", encode(message));
    debug!("signature: {}", encode(signature));
    debug!("payload: {}", encode(payload));
    debug!("entry_func_name: {}", entry_func_name);

    let (alg_id, type_) = match alg_id {
        AlgId::Eip712 => (AlgId::Eth, 1), //eip712 use eth lib
        AlgId::WebAuthn => {
            //todo: not elegant design, maybe move the logic for parsing witnesses from C to Rust.
            let r = match role {
                LockRole::Owner => 0,
                LockRole::Manager => 1,
            };
            (AlgId::WebAuthn, r)
        }
        _ => (alg_id, 0),
    };
    //todo: every time get desc info, may be cache it
    let dyn_lib_desc = match get_dyn_lib_desc_info(alg_id) {
        Ok(v) => v,
        Err(e) => {
            debug!("cannot found dyn_lib_desc for alg_id: {:?}, err: {:?}", alg_id, e);
            return Err(CkbAuthError::EncodeArgs);
        }
    };
    if !dyn_lib_desc.entry_name.contains(&entry_func_name) {
        debug!("entry_func_name: {}, cannot found in dyn_lib_desc", entry_func_name);
        return Err(CkbAuthError::EncodeArgs);
    }

    let entry = CkbEntryType {
        code_hash: dyn_lib_desc.code_hash.clone(),
        hash_type: dyn_lib_desc.hash_type,
        entry_category: dyn_lib_desc.entry_category,
    };

    //must before get_validate_func or will set to all 0
    let mut message_copy = [0u8; 32];
    let mut signature_copy = [0u8; MAX_WITNESS_SIZE];
    let mut payload_copy = [0u8; 128];

    message_copy[0..message.len()].copy_from_slice(message);
    signature_copy[0..signature.len()].copy_from_slice(signature);
    payload_copy[0..payload.len()].copy_from_slice(payload);

    debug!("ckb entry code_hash: {:02x?}", entry.code_hash);
    debug!("ckb entry hash_type: {:?}", entry.hash_type as u8);
    debug!("ckb entry entry_category: {:?}", entry.entry_category as u8);

    //todo: if there is validate device, func param should be changed
    let rc_code = match entry_func_name {
        "validate" => {
            let func: Symbol<CkbAuthValidate> =
                CKBDLLoader::get().get_validate_func(&entry.code_hash, entry.hash_type, "validate")?;
            debug!("load function success.");
            unsafe {
                func(
                    type_,
                    message_copy.as_ptr(),
                    signature_copy.as_ptr(),
                    payload_copy.as_ptr(),
                )
            }
        }
        //note: not support for now
        // "validate_str" => {
        //     let func: Symbol<CkbAuthValidateStr> = CKBDLLoader::get().get_validate_func(
        //         &entry.code_hash,
        //         entry.hash_type,
        //         "validate_str",
        //     )?;
        //     debug!("load function success.");
        //     //todo: may check the type_ , when different action
        //     let type_ = 1;
        //     let message_len = payload.len();
        //     unsafe {
        //         func(
        //             type_,
        //             message.as_ptr(),
        //             message_len,
        //             signature.as_ptr(),
        //             payload.as_ptr(),
        //         )
        //     }
        // }
        // "validate_device" => {
        //     let func: Symbol<CkbAuthValidateDevice> = CKBDLLoader::get().get_validate_func(
        //         &entry.code_hash,
        //         entry.hash_type,
        //         "validate_device",
        //     )?;
        //     debug!("load function success.");
        //     let version = 0;
        //     let signature = signature;
        //     let signature_len = signature.len();
        //     let message = message;
        //     let message_len = message.len();
        //     //todo: decode sig to device key list
        //     let device_key_list = [0u8; 128];
        //     let device_key_list_len = device_key_list.len();
        //     let reserved_data = [0u8; 16];
        //     let reserved_data_len = reserved_data.len();
        //
        //     unsafe {
        //         func(
        //             version,
        //             signature.as_ptr(),
        //             signature_len,
        //             message.as_ptr(),
        //             message_len,
        //             device_key_list.as_ptr(),
        //             device_key_list_len,
        //             reserved_data.as_ptr(),
        //             reserved_data_len,
        //         )
        //     }
        // }
        _ => {
            debug!("entry_func_name: {}, cannot found in dyn_lib_desc", entry_func_name);
            -1
        }
    };

    match rc_code {
        0 => {
            debug!("Run auth success in dynamic linking.");
            Ok(0)
        }
        _ => {
            debug!("Run auth error({}) in dynamic linking", rc_code);
            Err(CkbAuthError::RunDLError)
        }
    }
}

pub fn exec_eip712_lib() -> Result<i8, Error> {
    debug!("enter exec_eip712_lib");
    let type_id = get_type_id_by_type_script(TypeScript::EIP712Lib)?;

    debug!("EIP712Lib type_id = {:?}", hex_string(type_id.as_slice()));

    let argv = vec![]; //not needed for now
    let _ = high_level::exec_cell(type_id.as_slice(), ScriptHashType::Type, 0, 0, &*argv)
        .map_err(|err| {
            //note: exec_cell never returns
            let e: Error = err.into();
            debug!("exec eip712 lib error: {:?}", e);
        })
        .map(|_| ());
    Err(Error::RunExecError)
}
fn check_webauthn_public_key_index(alg_id: &AlgId, sign_info: &SignInfo) -> Result<(), Error> {
    if *alg_id != AlgId::WebAuthn {
        return Ok(());
    }
    let pk_idx = sign_info.signature[1];
    if pk_idx != 255 && pk_idx > 9 {
        debug!("Invalid pk_idx = {}", pk_idx);
        return Err(Error::InvalidPubkeyIndex);
    }
    Ok(())
}
//normal validation
pub fn dispatch_to_dyn_lib(role: Role, lock_args: &LockArgs) -> Result<i8, Error> {
    //get plain and cipher
    let sign_info = crate::entry::get_plain_and_cipher(lock_args.alg_id)?;

    //check for webauthn, the pk_idx should be 0-9 or 255.
    check_webauthn_public_key_index(&lock_args.alg_id, &sign_info)?;

    //call auth lib
    let ret = ckb_auth(
        lock_args.alg_id,
        role,
        sign_info.message.as_slice(),
        sign_info.signature.as_slice(),
        lock_args.payload.as_slice(),
        "validate",
    )?;

    Ok(ret)
}
pub fn dispatch(role: Role, das_action: DasAction) -> Result<i8, Error> {
    debug!("Enter dispatch");
    let lock_args = crate::entry::get_lock_args(&das_action, role)?;

    if lock_args.alg_id == AlgId::Eip712 {
        match exec_eip712_lib() {
            Ok(x) => {
                if x != 0 {
                    debug!("execute eip712-lib error, return {}", x);
                    return Err(Error::ValidationFailure);
                }
            }
            Err(e) => {
                debug!("call eip712-lib error: {:?}", e);
                return Err(e);
            }
        };
    };

    match dispatch_to_dyn_lib(role, &lock_args) {
        Ok(x) => {
            if x != 0 {
                debug!("general_verification failed, return {}", x);
                return Err(Error::ValidationFailure);
            }
        }
        Err(e) => {
            debug!("general_verification error: {:?}", e);
            return Err(e);
        }
    }
    Ok(0)
}

fn ckb_auth(
    alg_id: AlgId, role: Role, message: &[u8], signature: &[u8], payload: &[u8], entry_func_name: &str,
) -> Result<i8, Error> {
    let ret = match ckb_auth_dl(role, alg_id, message, signature, payload, entry_func_name) {
        Ok(x) => x,
        Err(e) => {
            debug!("auth dl error : {:?}", e);
            return Err(Error::ValidationFailure);
        }
    };

    if ret != 0 {
        //todo: error code
        debug!("Auth failed, ret = {}", ret);
        return Err(Error::ValidationFailure);
    }
    debug!("Dyn lib Auth success");

    Ok(0)
}
