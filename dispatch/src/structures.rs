use alloc::fmt;
use alloc::vec::Vec;

use das_types::constants::LockRole as Role;
use num_enum::TryFromPrimitive;
use strum_macros::Display;

#[derive(Debug, PartialEq)]
pub enum CmdMatchStatus {
    DasPureLockCell = 10000,
    DasNotPureLockCell = 10001,
}

#[derive(Debug, PartialEq)]
pub(crate) enum MatchStatus {
    Match,
    MisMatch,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SignatureCheck {
    Skip,
    Required,
}

#[derive(Debug, PartialEq)]
pub struct ActionData {
    action: Vec<u8>,
    role: Role,
}

#[derive(Debug)]
pub struct SignInfo {
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
}

impl fmt::Display for SignInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let signature_hex = hex::encode(&self.signature);
        let message_hex = hex::encode(&self.message);

        write!(
            f,
            "SignInfo {{ signature: 0x{}, message: 0x{} }}",
            signature_hex, message_hex
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive, Display)]
#[repr(u8)]
pub enum AlgId {
    Ckb = 0,
    CkbMultiSig = 1,
    AlwaysSuccess = 2,
    Eth = 3,
    Tron = 4,
    Eip712 = 5,
    Ed25519 = 6,
    DogeCoin = 7,
    WebAuthn = 8,
}

impl Into<&'static str> for AlgId {
    fn into(self) -> &'static str {
        match self {
            AlgId::Ckb => "CKB",
            AlgId::CkbMultiSig => "CKBMultiSig",
            AlgId::AlwaysSuccess => "AlwaysSuccess",
            AlgId::Eth => "Ethereum",
            AlgId::Tron => "TRON",
            AlgId::Eip712 => "EIP712",
            AlgId::Ed25519 => "ED25519",
            AlgId::DogeCoin => "DOGE",
            AlgId::WebAuthn => "WebAuthn",
        }
    }
}

//todo maybe do the parsing here, instead of putting it in the code, use the enum type,
// let each algorithm contain its payload
#[derive(Debug)]
pub struct LockArgs {
    pub alg_id: AlgId,
    pub payload: Vec<u8>,
}

impl LockArgs {
    pub fn new(alg_id: AlgId, payload: Vec<u8>) -> Self {
        LockArgs { alg_id, payload }
    }
}
impl fmt::Display for LockArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "alg_id: {:?}, payload: 0x{}",
            self.alg_id,
            hex::encode(&self.payload)
        )
    }
}
impl Clone for LockArgs {
    fn clone(&self) -> Self {
        LockArgs {
            alg_id: self.alg_id,
            payload: self.payload.clone(),
        }
    }
}
