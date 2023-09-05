use crate::error::Error;
use alloc::string::{String};
use alloc::vec::Vec;
use alloc::{fmt, format};
use core::mem::transmute;


#[cfg(test)]
use crate::test_framework::Testable;
use das_proc_macro::{test_level};

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

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Role {
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
        let signature_hex: String = self
            .signature
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();

        let message_hex: String = self
            .message
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();

        write!(
            f,
            "SignInfo {{ signature: 0x{}, message: 0x{} }}",
            signature_hex, message_hex
        )
    }
}

//strum cannot use in no_std
// #[derive(Debug, PartialEq, EnumString, Display)]
// pub enum DasAction {
//     #[strum(serialize = "confirm_proposal")]
//     ConfirmProposal,
//     #[strum(serialize = "renew_account")]
//     RenewAccount,
//     #[strum(serialize = "accept_offer")]
//     AcceptOffer,
//     #[strum(serialize = "unlock_account_for_cross_chain")]
//     UnlockAccountForCrossChain,
//     #[strum(serialize = "force_recover_account_status")]
//     ForceRecoverAccountStatus,
//     #[strum(serialize = "recycle_expired_account")]
//     RecycleExpiredAccount,
//     #[strum(serialize = "edit_records")]
//     EditRecords,
//     #[strum(serialize = "create_sub_account")]
//     CreateSubAccount,
//     #[strum(serialize = "update_sub_account")]
//     UpdateSubAccount,
//     #[strum(serialize = "config_sub_account")]
//     ConfigSubAccount,
//     #[strum(serialize = "config_sub_account_custom_script")]
//     ConfigSubAccountCustomScript,
//     #[strum(serialize = "buy_account")]
//     BuyAccount,
//     #[strum(serialize = "enable_sub_account")]
//     EnableSubAccount,
//     #[strum(serialize = "revoke_approval")]
//     RevokeApproval,
//     #[strum(serialize = "fulfill_approval")]
//     FulfillApproval,
//
//     Others,
// }

//todo: replace this from string to das-type enum and match with 4 bytes header not string
#[derive(Debug, PartialEq)]
pub enum DasAction {
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
    RevokeApproval,
    FulfillApproval,
    Others,
}

// impl From<&str> for DasAction {
//     fn from(s: &str) -> DasAction {
//         s.parse().unwrap_or(DasAction::Others)
//     }
// }
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
            "revoke_approval" => DasAction::RevokeApproval,
            "fulfill_approval" => DasAction::FulfillApproval,

            _ => DasAction::Others,
        }
    }
}
impl fmt::Display for DasAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action_str = match self {
            DasAction::ConfirmProposal => "confirm_proposal",
            DasAction::RenewAccount => "renew_account",
            DasAction::AcceptOffer => "accept_offer",
            DasAction::UnlockAccountForCrossChain => "unlock_account_for_cross_chain",
            DasAction::ForceRecoverAccountStatus => "force_recover_account_status",
            DasAction::RecycleExpiredAccount => "recycle_expired_account",
            DasAction::EditRecords => "edit_records",
            DasAction::CreateSubAccount => "create_sub_account",
            DasAction::UpdateSubAccount => "update_sub_account",
            DasAction::ConfigSubAccount => "config_sub_account",
            DasAction::ConfigSubAccountCustomScript => "config_sub_account_custom_script",
            DasAction::BuyAccount => "buy_account",
            DasAction::EnableSubAccount => "enable_sub_account",
            DasAction::RevokeApproval => "revoke_approval",
            DasAction::FulfillApproval => "fulfill_approval",
            DasAction::Others => "others",
        };
        write!(f, "{}", action_str)
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
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

impl Into<u8> for AlgId {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AlgId {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value >= AlgId::Ckb.into() && value <= AlgId::WebAuthn.into() {
            Ok(unsafe { transmute(value) })
        } else {
            Err(Error::UnknownAlgorithmID)
        }
    }
}

impl fmt::Display for AlgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_id_str = match self {
            AlgId::Ckb => "Ckb",
            AlgId::CkbMultiSig => "CkbMultiSig",
            AlgId::AlwaysSuccess => "AlwaysSuccess",
            AlgId::Eth => "Eth",
            AlgId::Tron => "Tron",
            AlgId::Eip712 => "Eip712",
            AlgId::Ed25519 => "Ed25519",
            AlgId::DogeCoin => "DogeCoin",
            AlgId::WebAuthn => "WebAuthn",
        };
        write!(f, "{}", alg_id_str)
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

    // pub fn alg_id(&self) -> AlgId {
    //     self.alg_id
    // }

    // pub fn payload(&self) -> &[u8] {
    //     &self.payload
    // }
}
impl fmt::Display for LockArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "alg_id: {}, payload: 0x{}",
            self.alg_id,
            hex::encode(&self.payload)
        )
    }
}

//unit test
#[test_level(1)]
fn test_from_string_into_das_action() {
    assert_eq!(
        DasAction::from("confirm_proposal"),
        DasAction::ConfirmProposal
    );
    assert_eq!(DasAction::from("renew_account"), DasAction::RenewAccount);
    assert_eq!(DasAction::from("accept_offer"), DasAction::AcceptOffer);
    assert_eq!(
        DasAction::from("unlock_account_for_cross_chain"),
        DasAction::UnlockAccountForCrossChain
    );
    assert_eq!(
        DasAction::from("force_recover_account_status"),
        DasAction::ForceRecoverAccountStatus
    );
    assert_eq!(
        DasAction::from("recycle_expired_account"),
        DasAction::RecycleExpiredAccount
    );
    assert_eq!(DasAction::from("edit_records"), DasAction::EditRecords);
    assert_eq!(
        DasAction::from("create_sub_account"),
        DasAction::CreateSubAccount
    );
    assert_eq!(
        DasAction::from("update_sub_account"),
        DasAction::UpdateSubAccount
    );
    assert_eq!(
        DasAction::from("config_sub_account"),
        DasAction::ConfigSubAccount
    );
    assert_eq!(
        DasAction::from("config_sub_account_custom_script"),
        DasAction::ConfigSubAccountCustomScript
    );
    assert_eq!(DasAction::from("buy_account"), DasAction::BuyAccount);
    assert_eq!(
        DasAction::from("enable_sub_account"),
        DasAction::EnableSubAccount
    );
    assert_eq!(
        DasAction::from("revoke_approval"),
        DasAction::RevokeApproval
    );
    assert_eq!(
        DasAction::from("fulfill_approval"),
        DasAction::FulfillApproval
    );
    assert_eq!(DasAction::from("othersasdf"), DasAction::Others);
}
