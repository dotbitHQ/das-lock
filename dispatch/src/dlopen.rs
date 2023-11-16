extern crate alloc;

use crate::debug_log;
use crate::structures::AlgId;
use crate::utils::generate_sighash_all::MAX_WITNESS_SIZE;
use alloc::collections::BTreeMap;
use alloc::ffi::NulError;
use alloc::fmt;
use ckb_std::{
    ckb_types::core::ScriptHashType,
    dynamic_loading_c_impl::{CKBDLContext, Library, Symbol},
    syscalls::SysError,
};
use core::mem::size_of_val;
use hex::encode;

#[allow(dead_code)]
#[derive(Debug)]
pub enum CkbAuthError {
    UnknowAlgorithmID,
    DynamicLinkingUninit,
    LoadDLError,
    LoadDLFuncError,
    RunDLError,
    ExecError(SysError),
    EncodeArgs,
}

impl From<SysError> for CkbAuthError {
    fn from(err: SysError) -> Self {
        debug_log!("exec error: {:?}", err);
        Self::ExecError(err)
    }
}

impl From<NulError> for CkbAuthError {
    fn from(err: NulError) -> Self {
        debug_log!("Exec encode args failed: {:?}", err);
        Self::EncodeArgs
    }
}

impl fmt::Display for CkbAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CkbAuthError::UnknowAlgorithmID => write!(f, "Unknown Algorithm ID"),
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
    // Exec = 0,
    DynamicLinking = 1,
    //Spawn = 2,
}

impl TryFrom<u8> for EntryCategoryType {
    type Error = CkbAuthError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            // 0 => Ok(Self::Exec),
            1 => Ok(Self::DynamicLinking),
            //2 => Ok(Self::Spawn),
            _ => Err(CkbAuthError::EncodeArgs),
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

// pub fn ckb_auth(
//     entry: &CkbEntryType,
//     id: &CkbAuthType,
//     signature: &[u8],
//     message: &[u8; 32],
// ) -> Result<(), CkbAuthError> {
//     match entry.entry_category {
//         // EntryCategoryType::Exec => ckb_auth_exec(entry, id, signature, message),
//         EntryCategoryType::DynamicLinking => ckb_auth_dl(entry, id, signature, message),
//         //EntryCategoryType::Spawn => ckb_auth_spawn(entry, id, signature, message),
//     }
// }

// fn ckb_auth_spawn(
//     entry: &CkbEntryType,
//     id: &CkbAuthType,
//     signature: &[u8],
//     message: &[u8; 32],
// ) -> Result<(), CkbAuthError> {
//     let algorithm_id_str = CString::new(format!("{:02X?}", id.algorithm_id.clone() as u8,))?;
//     let signature_str = CString::new(format!("{}", encode(signature)))?;
//     let message_str = CString::new(format!("{}", encode(message)))?;
//     let pubkey_hash_str = CString::new(format!("{}", encode(id.pubkey_hash)))?;
//
//     let args = [
//         algorithm_id_str.as_c_str(),
//         signature_str.as_c_str(),
//         message_str.as_c_str(),
//         pubkey_hash_str.as_c_str(),
//     ];
//
//     spawn_cell(&entry.code_hash, entry.hash_type, &args, 8, &mut Vec::new())?;
//     Ok(())
// }

type DLContext = CKBDLContext<[u8; 192 * 1024]>;
type CkbAuthValidate = unsafe extern "C" fn(
    type_: i32,
    message: *const u8,
    lock_bytes: *const u8,
    lock_args: *const u8,
) -> i32;

const EXPORTED_FUNC_NAME: &str = "validate";

struct CKBDLLoader {
    pub context: DLContext,
    pub context_used: usize,
    pub loaded_lib: BTreeMap<[u8; 33], Library>,
}

static mut G_CKB_DL_LOADER: Option<CKBDLLoader> = None;
impl CKBDLLoader {
    pub fn get() -> &'static mut Self {
        unsafe {
            match G_CKB_DL_LOADER.as_mut() {
                Some(v) => v,
                None => {
                    G_CKB_DL_LOADER = Some(Self::new());
                    G_CKB_DL_LOADER.as_mut().unwrap()
                }
            }
        }
    }

    fn new() -> Self {
        Self {
            context: unsafe { DLContext::new() },
            context_used: 0,
            loaded_lib: BTreeMap::new(),
        }
    }

    fn get_lib(
        &mut self,
        code_hash: &[u8; 32],
        hash_type: ScriptHashType,
    ) -> Result<&Library, CkbAuthError> {
        let mut lib_key = [0u8; 33];
        lib_key[..32].copy_from_slice(code_hash);
        lib_key[32] = hash_type as u8;

        let has_lib = match self.loaded_lib.get(&lib_key) {
            Some(_) => true,
            None => false,
        };

        if !has_lib {
            debug_log!("loading library");
            let size = size_of_val(&self.context);
            let lib = self
                .context
                .load_with_offset(code_hash, hash_type, self.context_used, size)
                .map_err(|_| {
                    debug_log!("load library error");
                    CkbAuthError::LoadDLError
                })?;
            self.context_used += lib.consumed_size();
            self.loaded_lib.insert(lib_key.clone(), lib);
        };
        Ok(self.loaded_lib.get(&lib_key).unwrap())
    }

    pub fn get_validate_func<T>(
        &mut self,
        code_hash: &[u8; 32],
        hash_type: ScriptHashType,
        func_name: &str,
    ) -> Result<Symbol<T>, CkbAuthError> {
        debug_log!(
            "Prepare to load function {} from dynamic linking.",
            func_name
        );

        let lib = self.get_lib(code_hash, hash_type)?;
        debug_log!("Load function {} from dynamic linking success.", func_name);

        let func: Option<Symbol<T>> = unsafe { lib.get(func_name.as_bytes()) };
        if func.is_none() {
            debug_log!("Load function {} from dynamic linking failed.", func_name);
            return Err(CkbAuthError::LoadDLFuncError);
        }

        Ok(func.unwrap())
    }
}

// fn copy_from_slice_diy(dst: &mut [u8], src: &[u8]) {
//     let len = src.len();
//     for i in 0..len {
//         if i < 30 {
//             debug_log!("copy {}: {}-{}", i, src[i], dst[i]);
//         }
//         dst[i] = src[i];
//     }
// }
pub fn ckb_auth_dl(
    role: u8,
    alg_id: AlgId,
    code_hash: &[u8; 32],
    message: &[u8; 32],
    lock_bytes: &[u8],
    lock_args: &[u8],
) -> Result<i32, CkbAuthError> {
    debug_log!("Prepare to run auth in dynamic linking.");
    debug_log!("role: {}", role);
    debug_log!("alg_id: {}", alg_id);
    debug_log!("code_hash: {}", encode(code_hash));
    debug_log!("message: {}", encode(message));
    debug_log!("lock_bytes: {}", encode(lock_bytes));
    debug_log!("lock_args: {}", encode(lock_args));

    let entry = CkbEntryType {
        code_hash: code_hash.clone(),
        hash_type: ScriptHashType::Type,
        entry_category: EntryCategoryType::DynamicLinking,
    };

    //must before get_validate_func
    let mut message_copy = [0u8; 32];
    let mut lock_bytes_copy = [0u8; MAX_WITNESS_SIZE];
    let mut lock_args_copy = [0u8; 128];

    message_copy[0..message.len()].copy_from_slice(message);
    lock_bytes_copy[0..lock_bytes.len()].copy_from_slice(lock_bytes);
    lock_args_copy[0..lock_args.len()].copy_from_slice(lock_args);

    //debug_log!("ckb entry code_hash: {:02x?}", entry.code_hash);
    //debug_log!("ckb entry hash_type: {:?}", entry.hash_type as u8);
    //debug_log!("ckb entry entry_category: {:?}", entry.entry_category as u8);

    let func: Symbol<CkbAuthValidate> = CKBDLLoader::get().get_validate_func(
        &entry.code_hash,
        entry.hash_type,
        EXPORTED_FUNC_NAME,
    )?;
    debug_log!("load function success.");


    // for i in 0..18 {
    //     let a = lock_args[i];
    //     debug_log!("5lock_args[{}]: {}", i, lock_args[i]);
    //     //lock_args_copy[i] = lock_args[i];
    // }

    let type_ = {
        if alg_id == AlgId::Eip712 {
            1
        } else if alg_id == AlgId::WebAuthn {
            //todo2 not good design
            role as i32
        } else {
            0
        }
    };

    let rc_code = unsafe {
        func(
            type_,
            message_copy.as_ptr(),
            lock_bytes_copy.as_ptr(),
            lock_args_copy.as_ptr(),
        )
    };

    match rc_code {
        0 => {
            debug_log!("Run auth success in dynamic linking.");
            Ok(0)
        }
        _ => {
            debug_log!("Run auth error({}) in dynamic linking", rc_code);
            Err(CkbAuthError::RunDLError)
        }
    }
}
