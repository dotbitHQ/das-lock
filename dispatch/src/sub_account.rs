use crate::debug_log;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::ToString;
use ckb_std::ckb_types::prelude::{Entity, Reader};
use core::ops::Index;
use das_core::error::{ErrorCode, ScriptError, SubAccountCellErrorCode};
use das_core::witness_parser::sub_account::{
    SubAccountEditValue, SubAccountWitness, SubAccountWitnessesParser,
};
use das_core::witness_parser::webauthn_signature::WebAuthnSignature;
use das_core::{code_to_error, das_assert, data_parser, util, verifiers, warn};

use das_dynamic_libs::error::Error;
use das_dynamic_libs::sign_lib::SignLib;
use das_types::constants::{das_lock, AccountStatus, DasLockType, SubAccountAction};
use das_types::packed::{
    AccountApproval, AccountApprovalTransferReader, Bytes, Records, SubAccount, Uint64, Uint8,
};
use das_types::prelude::Builder;
use das_types::prettier::Prettier;

//A shortened version of sub action in type contract.
pub struct SubAction<'a> {
    sign_lib: SignLib,
    timestamp: u64,
    //quote: u64,
    sub_account_last_updated_at: u64,
    #[allow(dead_code)]
    parent_account: &'a [u8],
    parent_expired_at: u64,
}

impl<'a> SubAction<'a> {
    pub fn new(
        sign_lib: SignLib,
        timestamp: u64,
        //quote: u64,
        sub_account_last_updated_at: u64,
        parent_account: &'a [u8],
        parent_expired_at: u64,
    ) -> Self {
        Self {
            sign_lib,
            timestamp,
            //quote,
            sub_account_last_updated_at,
            parent_account,
            parent_expired_at,
        }
    }

    pub fn dispatch(
        &self,
        witness: &SubAccountWitness,
        witness_parser: &SubAccountWitnessesParser,
    ) -> Result<(), Box<dyn ScriptError>> {
        //let sub_account_reader = witness.sub_account.as_reader();

        debug_log!(
            "  witnesses[{:>2}] Start verify {} action ...",
            witness.index,
            witness.action.to_string()
        );

        match witness.action {
            SubAccountAction::Edit => self.edit(witness, witness_parser)?,
            SubAccountAction::CreateApproval
            | SubAccountAction::DelayApproval
            | SubAccountAction::RevokeApproval
            | SubAccountAction::FulfillApproval => self.approve(witness, witness_parser)?,
            _ => {
                debug_log!("This action does not require verification of the signature.");
            }
        }

        Ok(())
    }

    fn edit(
        &self,
        witness: &SubAccountWitness,
        witness_parser: &SubAccountWitnessesParser,
    ) -> Result<(), Box<dyn ScriptError>> {
        //Only checks whether the signature is correct, regardless of the modified content
        verifiers::sub_account_cell::verify_unlock_role(&witness)?;

        verifiers::sub_account_cell::verify_sub_account_edit_sign_not_expired(
            &witness,
            self.parent_expired_at,
            self.sub_account_last_updated_at,
        )?;
        verify_sub_account_edit_sign_v2(&witness, &self.sign_lib, witness_parser)?;

        Ok(())
    }

    fn approve(
        &self,
        witness: &SubAccountWitness,
        witness_parser: &SubAccountWitnessesParser,
    ) -> Result<(), Box<dyn ScriptError>> {
        let sub_account_reader = witness.sub_account.as_reader();
        let new_sub_account = generate_new_sub_account_by_edit_value(&witness)?;
        let new_sub_account_reader = new_sub_account.as_reader();

        debug_log!(
            "  witnesses[{:>2}] Calculated new sub-account structure is: {}",
            witness.index,
            Prettier::as_prettier(&new_sub_account_reader)
        );

        let approval_reader = match witness.action {
            SubAccountAction::CreateApproval => new_sub_account_reader.approval(),
            _ => {
                let sub_account_reader = sub_account_reader.try_into_latest().map_err(|_| {
                    code_to_error!(SubAccountCellErrorCode::WitnessVersionMismatched)
                })?;
                sub_account_reader.approval()
            }
        };
        let approval_action = approval_reader.action().raw_data();
        let approval_params = approval_reader.params().raw_data();

        debug_log!(
            "  witnesses[{:>2}] Verify if the signature is valid.",
            witness.index
        );

        match witness.action {
            SubAccountAction::CreateApproval | SubAccountAction::DelayApproval => {
                verifiers::sub_account_cell::verify_unlock_role(&witness)?;
                verifiers::sub_account_cell::verify_sub_account_edit_sign_not_expired(
                    &witness,
                    self.parent_expired_at,
                    self.sub_account_last_updated_at,
                )?;
                verify_sub_account_edit_sign_v2(&witness, &self.sign_lib, witness_parser)?;
            }
            SubAccountAction::RevokeApproval => {
                verifiers::sub_account_cell::verify_sub_account_edit_sign_not_expired(
                    &witness,
                    self.parent_expired_at,
                    self.sub_account_last_updated_at,
                )?;
                verify_sub_account_approval_sign_v2(&witness, &self.sign_lib, witness_parser)?;
            }
            SubAccountAction::FulfillApproval => match approval_action {
                b"transfer" => {
                    let params =
                        AccountApprovalTransferReader::from_compatible_slice(approval_params)
                            .map_err(|_| {
                                code_to_error!(SubAccountCellErrorCode::WitnessParsingError)
                            })?;
                    let sealed_util = u64::from(params.sealed_until());

                    if self.timestamp <= sealed_util {
                        debug_log!(
                            "  witnesses[{:>2}] The approval is sealed, verify the signature with the owner lock.",
                            witness.index
                        );

                        verifiers::sub_account_cell::verify_sub_account_edit_sign_not_expired(
                            &witness,
                            self.parent_expired_at,
                            self.sub_account_last_updated_at,
                        )?;
                        verify_sub_account_approval_sign_v2(
                            &witness,
                            &self.sign_lib,
                            witness_parser,
                        )?;
                    } else {
                        debug_log!(
                            "  witnesses[{:>2}] The approval is released, no need to verify the signature.",
                            witness.index
                        );
                    }
                }
                _ => {
                    return Err(code_to_error!(
                        SubAccountCellErrorCode::ApprovalActionUndefined
                    ))
                }
            },
            _ => {
                warn!(
                    "  witnesses[{:>2}] The action is not an approval actions.",
                    witness.index
                );
                return Err(code_to_error!(SubAccountCellErrorCode::SignError));
            }
        }

        debug_log!("  witnesses[{:>2}] Get the approval action.", witness.index);

        Ok(())
    }
}

fn generate_new_sub_account_by_edit_value(
    witness: &SubAccountWitness,
) -> Result<SubAccount, Box<dyn ScriptError>> {
    das_assert!(
        witness.new_sub_account_version == 2,
        SubAccountCellErrorCode::WitnessUpgradeNeeded,
        "  witnesses[{:>2}] SubAccount.new_sub_account_version is invalid.(expected: {}, actual: {})",
        witness.index,
        2,
        witness.new_sub_account_version
    );

    // Upgrade the earlier version to the latest version, because the new SubAccount should always be kept up to date.
    let sub_account = witness.sub_account.clone();
    let sub_account = if sub_account.version() == 1 {
        let sub_account = sub_account
            .try_into_v1()
            .map_err(|_| code_to_error!(SubAccountCellErrorCode::WitnessVersionMismatched))?;

        SubAccount::new_builder()
            .lock(sub_account.lock().clone())
            .id(sub_account.id().clone())
            .account(sub_account.account().clone())
            .suffix(sub_account.suffix().clone())
            .registered_at(sub_account.registered_at().clone())
            .expired_at(sub_account.expired_at().clone())
            .status(sub_account.status().clone())
            .records(sub_account.records().clone())
            .nonce(sub_account.nonce().clone())
            .enable_sub_account(sub_account.enable_sub_account().clone())
            .renew_sub_account_price(sub_account.renew_sub_account_price().clone())
            .build()
    } else {
        sub_account
            .try_into_latest()
            .map_err(|_| code_to_error!(SubAccountCellErrorCode::WitnessVersionMismatched))?
    };

    let edit_value = &witness.edit_value;

    let current_nonce = u64::from(sub_account.nonce());
    let current_approval = sub_account.approval().clone();
    let current_approval_reader = current_approval.as_reader();
    let mut sub_account_builder = sub_account.as_builder();
    sub_account_builder = match witness.action {
        SubAccountAction::Edit => {
            match edit_value {
                SubAccountEditValue::Owner(val) | SubAccountEditValue::Manager(val) => {
                    let mut lock_builder = das_lock().clone().as_builder();
                    // Verify if the edit_value is a valid format.
                    data_parser::das_lock_args::get_owner_and_manager(val)?;
                    lock_builder = lock_builder.args(Bytes::from(val.to_owned()));

                    sub_account_builder = sub_account_builder.lock(lock_builder.build());

                    if let SubAccountEditValue::Owner(_) = edit_value {
                        sub_account_builder = sub_account_builder.records(Records::default())
                    }

                    sub_account_builder
                }
                SubAccountEditValue::Records(val) => sub_account_builder.records(val.to_owned()),
                _ => {
                    return Err(code_to_error!(
                        SubAccountCellErrorCode::WitnessEditKeyInvalid
                    ))
                }
            }
        }
        SubAccountAction::Renew => match edit_value {
            SubAccountEditValue::ExpiredAt(val) => {
                sub_account_builder.expired_at(Uint64::from(val.to_owned()))
            }
            _ => {
                return Err(code_to_error!(
                    SubAccountCellErrorCode::WitnessEditKeyInvalid
                ))
            }
        },
        SubAccountAction::CreateApproval | SubAccountAction::DelayApproval => {
            match edit_value {
                SubAccountEditValue::Approval(val) => {
                    // The status should be updated to AccountStatus::ApprovedTransfer when the edit_value is approval.
                    sub_account_builder = sub_account_builder
                        .status(Uint8::from(AccountStatus::ApprovedTransfer as u8));
                    sub_account_builder.approval(val.to_owned())
                }
                _ => {
                    return Err(code_to_error!(
                        SubAccountCellErrorCode::WitnessEditKeyInvalid
                    ))
                }
            }
        }
        SubAccountAction::RevokeApproval => {
            match edit_value {
                SubAccountEditValue::None => {}
                _ => {
                    return Err(code_to_error!(
                        SubAccountCellErrorCode::WitnessEditKeyInvalid
                    ));
                }
            }

            // The status should be updated to AccountStatus::Normal when the edit_value is None.
            sub_account_builder =
                sub_account_builder.status(Uint8::from(AccountStatus::Normal as u8));
            sub_account_builder.approval(AccountApproval::default())
        }
        SubAccountAction::FulfillApproval => {
            match edit_value {
                SubAccountEditValue::None => {}
                _ => {
                    return Err(code_to_error!(
                        SubAccountCellErrorCode::WitnessEditKeyInvalid
                    ));
                }
            }

            let approval_action = current_approval_reader.action().raw_data();
            let approval_params = current_approval_reader.params().raw_data();

            match approval_action {
                b"transfer" => {
                    let approval_params_reader =
                        AccountApprovalTransferReader::from_compatible_slice(approval_params)
                            .map_err(|_| {
                                code_to_error!(SubAccountCellErrorCode::WitnessParsingError)
                            })?;
                    sub_account_builder =
                        sub_account_builder.lock(approval_params_reader.to_lock().to_entity());
                    sub_account_builder = sub_account_builder.records(Records::default());
                    // The status should be updated to AccountStatus::Normal when the edit_value is None.
                    sub_account_builder =
                        sub_account_builder.status(Uint8::from(AccountStatus::Normal as u8));
                    sub_account_builder.approval(AccountApproval::default())
                }
                _ => {
                    return Err(code_to_error!(
                        SubAccountCellErrorCode::ApprovalActionUndefined
                    ))
                }
            }
        }
        _ => {
            return Err(code_to_error!(
                SubAccountCellErrorCode::WitnessEditKeyInvalid
            ))
        }
    };

    // Every time a sub-account is edited, its nonce must  increase by 1 .
    sub_account_builder = sub_account_builder.nonce(Uint64::from(current_nonce + 1));

    Ok(sub_account_builder.build())
}

pub fn verify_sub_account_edit_sign_v2(
    witness: &SubAccountWitness,
    sign_lib: &SignLib,
    witness_parser: &SubAccountWitnessesParser,
) -> Result<(), Box<dyn ScriptError>> {
    if cfg!(feature = "dev") {
        // CAREFUL Proof verification has been skipped in development mode.
        debug_log!(
            "  witnesses[{:>2}] Skip verifying the witness.sub_account.sig is valid.",
            witness.index
        );
        return Ok(());
    }

    debug_log!(
        "  witnesses[{:>2}] Verify if the witness.sub_account.signature is valid.",
        witness.index
    );

    let das_lock_type = match witness.sign_type {
        Some(val) => match val {
            DasLockType::CKBSingle
            | DasLockType::ETH
            | DasLockType::ETHTypedData
            | DasLockType::TRON
            | DasLockType::Doge
            | DasLockType::WebAuthn => val,
            _ => {
                warn!(
                        "  witnesses[{:>2}] Parsing das-lock(witness.sub_account.lock.args) algorithm failed (maybe not supported for now), but it is required in this transaction.",
                        witness.index
                    );
                return Err(code_to_error!(ErrorCode::InvalidTransactionStructure));
            }
        },
        _ => {
            warn!(
                "  witnesses[{:>2}] Parsing das-lock(witness.sub_account.lock.args) algorithm failed (maybe not supported for now), but it is required in this transaction.",
                witness.index
            );
            return Err(code_to_error!(ErrorCode::InvalidTransactionStructure));
        }
    };

    let sub_account_reader = witness
        .sub_account
        .as_reader()
        .try_into_latest()
        .map_err(|_| code_to_error!(SubAccountCellErrorCode::WitnessVersionMismatched))?;

    let account_id = sub_account_reader.id().as_slice().to_vec();
    let edit_key = witness.edit_key.as_slice();
    let edit_value = witness.edit_value_bytes.as_slice();
    let nonce = sub_account_reader.nonce().as_slice().to_vec();

    let signature = witness.signature.as_slice();
    let args = witness.sign_args.as_slice();
    let sign_expired_at = witness.sign_expired_at.to_le_bytes().to_vec();

    let ret = if das_lock_type == DasLockType::WebAuthn
        && u8::from_le_bytes(
            WebAuthnSignature::try_from(signature)?
                .pubkey_index()
                .try_into()
                .unwrap(),
        ) != 255
    {
        let data = [
            account_id,
            edit_key.to_vec(),
            edit_value.to_vec(),
            nonce,
            sign_expired_at,
        ]
        .concat();
        let message = util::blake2b_256(&data);
        debug_log!(
            "Getting DeviceKeyListCellData for sign_args: {}",
            hex::encode(args)
        );

        let device_key_list = witness_parser
            .device_key_lists
            .get(args.index(..))
            .ok_or(code_to_error!(ErrorCode::WitnessStructureError))?;
        sign_lib.validate_device(
            das_lock_type,
            0,
            &signature,
            &message,
            device_key_list.as_slice(),
            Default::default(),
        )
    } else {
        sign_lib.verify_sub_account_sig(
            das_lock_type,
            account_id,
            edit_key.to_vec(),
            edit_value.to_vec(),
            nonce,
            signature.to_vec(),
            args.to_vec(),
            sign_expired_at,
        )
    };

    match ret {
        Err(_error_code) if _error_code == Error::UndefinedDasLockType as i32 => {
            warn!(
                "  witnesses[{:>2}] The signature algorithm has not been supported",
                witness.index
            );
            Err(code_to_error!(ErrorCode::HardCodedError))
        }
        Err(_error_code) => {
            warn!(
                "  witnesses[{:>2}] The witness.signature is invalid, the error_code returned by dynamic library is: {}",
                witness.index, _error_code
            );
            Err(code_to_error!(
                SubAccountCellErrorCode::SubAccountSigVerifyError
            ))
        }
        _ => {
            debug_log!(
                "  witnesses[{:>2}] The witness.signature is valid.",
                witness.index
            );
            Ok(())
        }
    }
}

pub fn verify_sub_account_approval_sign_v2(
    witness: &SubAccountWitness,
    sign_lib: &SignLib,
    witness_parser: &SubAccountWitnessesParser,
) -> Result<(), Box<dyn ScriptError>> {
    if cfg!(feature = "dev") {
        // CAREFUL Proof verification has been skipped in development mode.
        debug_log!(
            "  witnesses[{:>2}] Skip verifying the witness.sub_account.sig is valid.",
            witness.index
        );
        return Ok(());
    }

    debug_log!(
        "  witnesses[{:>2}] Verify if the witness.sub_account.signature is valid.",
        witness.index
    );

    das_assert!(
        witness.sign_role.is_some(),
        SubAccountCellErrorCode::SubAccountSigVerifyError,
        "  witnesses[{:>2}] Verify the signature is required, but the sign_role, sign_args or sign is missing.",
        witness.index
    );

    let das_lock_type = match witness.sign_type {
        Some(val) => match val {
            DasLockType::CKBSingle
            | DasLockType::ETH
            | DasLockType::ETHTypedData
            | DasLockType::TRON
            | DasLockType::Doge
            | DasLockType::WebAuthn => val,
            _ => {
                warn!(
                        "  witnesses[{:>2}] Parsing das-lock(witness.sub_account.lock.args) algorithm failed (maybe not supported for now), but it is required in this transaction.",
                        witness.index
                    );
                return Err(code_to_error!(ErrorCode::InvalidTransactionStructure));
            }
        },
        _ => {
            warn!(
                "  witnesses[{:>2}] Parsing das-lock(witness.sub_account.lock.args) algorithm failed (maybe not supported for now), but it is required in this transaction.",
                witness.index
            );
            return Err(code_to_error!(ErrorCode::InvalidTransactionStructure));
        }
    };

    let sub_account_reader = witness
        .sub_account
        .as_reader()
        .try_into_latest()
        .map_err(|_| code_to_error!(SubAccountCellErrorCode::WitnessVersionMismatched))?;

    let nonce = sub_account_reader.nonce().as_slice().to_vec();
    let signature = witness.signature.as_slice();
    let args = witness.sign_args.as_slice();
    let sign_expired_at = witness.sign_expired_at.to_le_bytes().to_vec();

    let ret = if das_lock_type == DasLockType::WebAuthn
        && u8::from_le_bytes(
            WebAuthnSignature::try_from(signature)?
                .pubkey_index()
                .try_into()
                .unwrap(),
        ) != 255
    {
        let action_bytes = witness.action.to_string().as_bytes().to_vec();
        let approval_bytes = sub_account_reader.approval().as_slice().to_vec();
        let data = [action_bytes, approval_bytes, nonce, sign_expired_at].concat();
        let message = util::blake2b_256(&data);

        debug_log!(
            "Getting DeviceKeyListCellData for sign_args: {}",
            hex::encode(args)
        );

        let device_key_list = witness_parser
            .device_key_lists
            .get(args.index(..))
            .ok_or(code_to_error!(ErrorCode::WitnessStructureError))?;
        sign_lib.validate_device(
            das_lock_type,
            0,
            &signature,
            &message,
            device_key_list.as_slice(),
            Default::default(),
        )
    } else {
        sign_lib.verify_sub_account_approval_sig(
            das_lock_type,
            witness.action,
            sub_account_reader.approval(),
            nonce,
            signature.to_vec(),
            args.to_vec(),
            sign_expired_at,
        )
    };

    match ret {
        Err(_error_code) if _error_code == Error::UndefinedDasLockType as i32 => {
            warn!(
                "  witnesses[{:>2}] The signature algorithm has not been supported",
                witness.index
            );
            Err(code_to_error!(ErrorCode::HardCodedError))
        }
        Err(_error_code) => {
            warn!(
                "  witnesses[{:>2}] The witness.signature is invalid, the error_code returned by dynamic library is: {}",
                witness.index, _error_code
            );
            Err(code_to_error!(
                SubAccountCellErrorCode::SubAccountSigVerifyError
            ))
        }
        _ => {
            debug_log!(
                "  witnesses[{:>2}] The witness.signature is valid.",
                witness.index
            );
            Ok(())
        }
    }
}
