use alloc::vec::Vec;
use alloc::{fmt};
use das_types::constants::LockRole as Role;
use num_enum::{TryFromPrimitive};

#[cfg(test)]
use crate::test_framework::Testable;

use das_proc_macro::{test_level};
use strum_macros::{Display, EnumString};
use das_dynamic_libs::constants::DynLibName;
use crate::debug_log;

#[derive(Debug, PartialEq)]
pub(crate) enum CmdMatchStatus {
    DasPureLockCell = 10000,
    DasNotPureLockCell = 10001,
}

#[derive(Debug, PartialEq)]
pub(crate) enum MatchStatus {
    Match,
    NotMatch,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SkipSignOrNot {
    Skip,
    NotSkip,
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
        let signature_hex =  hex::encode(&self.signature);
        let message_hex = hex::encode(&self.message);
        // let signature_hex: String = self
        //     .signature
        //     .iter()
        //     .map(|byte| format!("{:02x}", byte))
        //     .collect();
        //
        // let message_hex: String = self
        //     .message
        //     .iter()
        //     .map(|byte| format!("{:02x}", byte))
        //     .collect();

        write!(
            f,
            "SignInfo {{ signature: 0x{}, message: 0x{} }}",
            signature_hex, message_hex
        )
    }
}

#[derive(Debug, PartialEq, EnumString, Display)]
pub enum DasAction {
    #[strum(serialize = "confirm_proposal")]
    ConfirmProposal,
    #[strum(serialize = "renew_account")]
    RenewAccount,
    #[strum(serialize = "accept_offer")]
    AcceptOffer,
    #[strum(serialize = "unlock_account_for_cross_chain")]
    UnlockAccountForCrossChain,
    #[strum(serialize = "force_recover_account_status")]
    ForceRecoverAccountStatus,
    #[strum(serialize = "recycle_expired_account")]
    RecycleExpiredAccount,
    #[strum(serialize = "edit_records")]
    EditRecords,
    #[strum(serialize = "create_sub_account")]
    CreateSubAccount,
    #[strum(serialize = "update_sub_account")]
    UpdateSubAccount,
    #[strum(serialize = "config_sub_account")]
    ConfigSubAccount,
    #[strum(serialize = "config_sub_account_custom_script")]
    ConfigSubAccountCustomScript,
    #[strum(serialize = "buy_account")]
    BuyAccount,
    #[strum(serialize = "enable_sub_account")]
    EnableSubAccount,
    #[strum(serialize = "revoke_approval")]
    RevokeApproval,
    #[strum(serialize = "fulfill_approval")]
    FulfillApproval,

    Others,
}

impl DasAction {
    //use new to replace from_str
    pub fn new(action_str: &str) -> Self {
        match action_str.parse::<DasAction>() {
            Ok(v) => v,
            Err(e) => {
                debug_log!("DasAction::from_string warning: {:?}", e);
                DasAction::Others
            },
        }

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

impl Into<DynLibName> for AlgId {
    fn into(self) -> DynLibName {
        match self {
            AlgId::Ckb => DynLibName::CKBSignhash,
            AlgId::CkbMultiSig => DynLibName::CKBMultisig,
            AlgId::AlwaysSuccess => DynLibName::CKBSignhash,
            AlgId::Eth => DynLibName::ETH,
            AlgId::Tron => DynLibName::TRON,
            AlgId::Eip712 => DynLibName::ETH,
            AlgId::Ed25519 => DynLibName::ED25519,
            AlgId::DogeCoin => DynLibName::DOGE,
            AlgId::WebAuthn => DynLibName::WebAuthn,
        }
    }
}

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
#[test_level(1)]
fn test_alg_id() {
    //from u8 to AlgId
    assert_eq!(AlgId::Ckb, AlgId::try_from(0).unwrap());
    assert_eq!(AlgId::CkbMultiSig, AlgId::try_from(1).unwrap());
    assert_eq!(AlgId::AlwaysSuccess, AlgId::try_from(2).unwrap());
    assert_eq!(AlgId::Eth, AlgId::try_from(3).unwrap());
    assert_eq!(AlgId::Tron, AlgId::try_from(4).unwrap());
    assert_eq!(AlgId::Eip712, AlgId::try_from(5).unwrap());
    assert_eq!(AlgId::Ed25519, AlgId::try_from(6).unwrap());
    assert_eq!(AlgId::DogeCoin, AlgId::try_from(7).unwrap());
    assert_eq!(AlgId::WebAuthn, AlgId::try_from(8).unwrap());
    match AlgId::try_from(9) {
        //TryFromPrimitiveError
        Err(e) => {
            debug_log!("AlgId::try_from error: {:?}", e);

        },
        _ => panic!("should not be here"),
    }
    //from AlgId to u8
    assert_eq!(AlgId::Ckb as u8, 0);
    assert_eq!(AlgId::CkbMultiSig as u8, 1);
    assert_eq!(AlgId::AlwaysSuccess as u8, 2);
    assert_eq!(AlgId::Eth as u8, 3);
    assert_eq!(AlgId::Tron as u8, 4);
    assert_eq!(AlgId::Eip712 as u8, 5);
    assert_eq!(AlgId::Ed25519 as u8, 6);
    assert_eq!(AlgId::DogeCoin as u8, 7);
    assert_eq!(AlgId::WebAuthn as u8, 8);
}
#[test_level(1)]
//#[test_case]
fn test_from_string_into_das_action() {
assert_eq!(
        DasAction::new("confirm_proposal"),
        DasAction::ConfirmProposal
    );
    assert_eq!(DasAction::new("renew_account"), DasAction::RenewAccount);
    assert_eq!(DasAction::new("accept_offer"), DasAction::AcceptOffer);
    assert_eq!(
        DasAction::new("unlock_account_for_cross_chain"),
        DasAction::UnlockAccountForCrossChain
    );
    assert_eq!(
        DasAction::new("force_recover_account_status"),
        DasAction::ForceRecoverAccountStatus
    );
    assert_eq!(
        DasAction::new("recycle_expired_account"),
        DasAction::RecycleExpiredAccount
    );
    assert_eq!(DasAction::new("edit_records"), DasAction::EditRecords);
    assert_eq!(
        DasAction::new("create_sub_account"),
        DasAction::CreateSubAccount
    );
    assert_eq!(
        DasAction::new("update_sub_account"),
        DasAction::UpdateSubAccount
    );
    assert_eq!(
        DasAction::new("config_sub_account"),
        DasAction::ConfigSubAccount
    );
    assert_eq!(
        DasAction::new("config_sub_account_custom_script"),
        DasAction::ConfigSubAccountCustomScript
    );
    assert_eq!(DasAction::new("buy_account"), DasAction::BuyAccount);
    assert_eq!(
        DasAction::new("enable_sub_account"),
        DasAction::EnableSubAccount
    );
    assert_eq!(
        DasAction::new("revoke_approval"),
        DasAction::RevokeApproval
    );
    assert_eq!(
        DasAction::new("fulfill_approval"),
        DasAction::FulfillApproval
    );
    assert_eq!(DasAction::new("asgagahdfgadfasdf"), DasAction::Others);
    assert_eq!(DasAction::new("others"), DasAction::Others);

}
