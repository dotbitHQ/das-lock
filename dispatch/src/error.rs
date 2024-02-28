use alloc::boxed::Box;
use ckb_std::error::SysError;
use das_core::error::ScriptError;

/// Error
#[repr(i8)]
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum Error {
    //System Error
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    ArgsError,
    CannotFindEip712InCellDeps,
    CellNotFound,
    CheckFailSubAccFirstInputCell,
    ConfigMainNotFound,
    DataIsAllZero,
    DpCellNotFound,
    GeneratedMsgError,
    InvalidAction,
    InvalidAlgId,
    InvalidDasWitness,
    InvalidMolecule,
    InvalidPubkeyIndex,
    InvalidRole,
    InvalidString,
    InvalidTypeId,
    InvalidWitness,
    InvalidWitnessArgsLock,
    LoadCellTypeHashError,
    LoadDLError,
    LoadWitnessError,
    ManagerNotAllowed,
    NumOutOfBound,
    RunAuthError,
    RunDLLError,
    RunExecError,
    SelfNotFound,
    SubAccountParseFailed,
    UnknownAlgorithmID,
    ValidationFailure,
    WitnessError,
    WitnessNotFound,
    WitnessParserInitFailed,
    WitnessStructureError,
    WitnessTooLarge,
    InvalidTransactionStructure,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

impl From<Box<dyn ScriptError>> for Error {
    fn from(err: Box<dyn ScriptError>) -> Self {
        match err.as_i8() {
            1 => Error::IndexOutOfBound,
            2 => Error::ItemMissing,
            3 => Error::LengthNotEnough,
            _ => Error::Encoding, // Default case if the i8 value doesn't match any known errors
        }
    }
}
