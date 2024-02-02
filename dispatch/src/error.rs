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

    // Add customized errors here...
    ArgsError = 5,
    WitnessError,
    GeneratedMsgError,
    LoadDLError,
    RunAuthError,
    InvalidDasWitness = 10,

    NumOutOfBound,
    InvalidRole,
    ManagerNotAllowed,
    InvalidAlgId,
    SelfNotFound = 15,

    InvalidWitnessArgsLock,
    ValidationFailure,
    InvalidAction,
    InvalidString,
    CheckFailSubAccFirstInputCell = 20,

    InvalidPubkeyIndex,
    InvalidMolecule,
    UnknownAlgorithmID,
    WitnessNotFound,
    LoadWitnessError = 25,

    WitnessTooLarge,
    WitnessStructureError,
    InvalidWitness,
    ConfigMainNotFound,
    LoadCellTypeHashError = 30,

    DpCellNotFound,
    DataIsAllZero,
    InvalidTypeId,
    RunDLLError,
    RunExecError, // 35

    SubAccountParseFailed,
    CellNotFound,
    CannotFindEip712InCellDeps,
    WitnessParserInitFailed,
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
