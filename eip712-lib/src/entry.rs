use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};

use ckb_std::ckb_constants::Source;
use ckb_std::error::SysError;
use ckb_std::high_level;
use config::constants::FieldKey;
use das_core::constants::*;
use das_core::error::*;
use witness_parser::WitnessesParserV1;

use das_core::{assert, code_to_error, data_parser, debug, util, warn};
use das_map::map::Map;
use das_map::util as map_util;
use das_types::constants::{Action, DataType, LockRole};
use das_types::mixer::AccountCellDataMixer;
use das_types::packed::*;
use das_types::prelude::*;
use eip712::util::{to_semantic_capacity, to_semantic_currency};
use witness_parser::traits::WitnessQueryable;
use witness_parser::types::{CellMeta, WitnessMeta};

use super::eip712::{get_type_id, to_semantic_address, verify_eip712_hashes_if_has_das_lock};

pub fn main() -> Result<(), Box<dyn ScriptError>> {
    debug!("====== EIP712 Lib ======");

    let mut parser = WitnessesParserV1::get_instance();
    debug!("WitnessesParserV1::get_instance() success");

    parser
        .init()
        .map_err(|err| {
            debug!("Error: witness parser init failed, {:?}", err);
            das_core::error::ErrorCode::WitnessDataDecodingError
        })
        .unwrap();

    let action = parser.action;

    debug!("The action of the transaction is: {}", action);

    let func = match action {
        // b"transfer_account" => transfer_account_to_semantic,
        Action::TransferAccount => transfer_account_to_semantic,

        // b"edit_manager" => edit_manager_to_semantic,
        Action::EditManager => edit_manager_to_semantic,

        // b"edit_records" => edit_records_to_semantic,
        Action::EditRecords => edit_records_to_semantic,

        // b"bid_expired_account_dutch_auction" => bid_expired_account_dutch_auction_to_semantic,
        Action::BidExpiredAccountDutchAuction => bid_expired_account_dutch_auction_to_semantic,

        // b"start_account_sale" => start_account_sale_to_semantic,
        Action::StartAccountSale => start_account_sale_to_semantic,

        // b"cancel_account_sale" => cancel_account_sale_to_semantic,
        Action::CancelAccountSale => cancel_account_sale_to_semantic,

        // b"buy_account" => buy_account_to_semantic,
        Action::BuyAccount => buy_account_to_semantic,

        // b"edit_account_sale" => edit_account_sale_to_semantic,
        Action::EditAccountSale => edit_account_sale_to_semantic,

        // b"make_offer" => make_offer_to_semantic,
        Action::MakeOffer => make_offer_to_semantic,

        // b"edit_offer" => edit_offer_to_semantic,
        Action::EditOffer => edit_offer_to_semantic,

        // b"cancel_offer" => cancel_offer_to_semantic,
        Action::CancelOffer => cancel_offer_to_semantic,

        // b"accept_offer" => accept_offer_to_semantic,
        Action::AcceptOffer => accept_offer_to_semantic,

        // b"retract_reverse_record" => retract_reverse_record_to_semantic,
        Action::RetractReverseRecord => retract_reverse_record_to_semantic,

        // b"lock_account_for_cross_chain" => lock_account_for_cross_chain_to_semantic,
        Action::LockAccountForCrossChain => lock_account_for_cross_chain_to_semantic,

        // b"create_approval" => create_approval_to_semantic,
        Action::CreateApproval => create_approval_to_semantic,

        // b"delay_approval" => delay_approval_to_semantic,
        Action::DelayApproval => delay_approval_to_semantic,

        // b"fulfill_approval" => fulfill_approval_to_semantic,
        Action::FulfillApproval => fulfill_approval_to_semantic,

        // b"transfer_dp" => transfer_dp_to_semantic,
        Action::TransferDP => transfer_dp_to_semantic,

        // b"burn_dp" => burn_dp_to_semantic,
        Action::BurnDP => burn_dp_to_semantic,

        _ => transfer_to_semantic,
    };

    verify_eip712_hashes_if_has_das_lock(&mut parser, func)?;

    Ok(())
}

fn transfer_account_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (input_cells, output_cells) = util::find_cells_by_type_id_in_inputs_and_outputs(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(input_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    // Parse from address from the AccountCell's lock script in inputs.
    // let from_lock = high_level::load_cell_lock(input_cells[0], Source::Input)?;
    // let from_address = to_semantic_address(from_lock.as_reader().into(), 1..21)?;
    // Parse to address from the AccountCell's lock script in outputs.
    let to_lock = high_level::load_cell_lock(output_cells[0], Source::Output)?;
    let to_address = to_semantic_address(to_lock.as_reader().into(), LockRole::Owner)?;

    Ok(format!(
        "TRANSFER THE ACCOUNT {} TO {}",
        account, to_address
    ))
}

fn edit_manager_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (input_cells, _output_cells) = util::find_cells_by_type_id_in_inputs_and_outputs(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(input_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    // TODO Improve semantic message of this transaction.
    Ok(format!("EDIT MANAGER OF ACCOUNT {}", account))
}

fn edit_records_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (input_cells, _output_cells) = util::find_cells_by_type_id_in_inputs_and_outputs(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(input_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    // TODO Improve semantic message of this transaction.
    Ok(format!("EDIT RECORDS OF ACCOUNT {}", account))
}

fn bid_expired_account_dutch_auction_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (input_account_cells, _output_account_cells) =
        util::find_cells_by_type_id_in_inputs_and_outputs(
            ScriptType::Type,
            get_type_id(FieldKey::AccountCellTypeArgs),
        )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(input_account_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    let (input_dpoint_cells, output_dpoint_cells) =
        util::find_cells_by_type_id_in_inputs_and_outputs(
            ScriptType::Type,
            get_type_id(FieldKey::DpointCellTypeArgs),
        )?;
    let lock = Script::from(high_level::load_cell_lock(
        input_dpoint_cells[0],
        Source::Input,
    )?);

    let input_dp = util::get_total_dpoint_by_lock(
        lock.as_reader().into(),
        &input_dpoint_cells,
        Source::Input,
    )?;
    let output_dp = util::get_total_dpoint_by_lock(
        lock.as_reader().into(),
        &output_dpoint_cells,
        Source::Output,
    )?;
    let spent_dp = input_dp - output_dp;

    Ok(format!(
        "BID EXPIRED ACCOUNT {} WITH {}",
        account,
        to_semantic_currency(spent_dp, "DP")
    ))
}

fn start_account_sale_to_semantic(
    parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let account_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
        Source::Input,
    )?;
    let account_sale_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountSaleCellTypeArgs),
        Source::Output,
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(account_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    let cell_meta = CellMeta::new(account_sale_cells[0], das_types::constants::Source::Output);
    let witness_meta = parser
        .get_witness_meta_by_cell_meta(cell_meta)
        .expect("get_witness_meta_by_cell_meta failed");

    let price = get_account_sale_cell_data_price(parser, &witness_meta, cell_meta)?;
    Ok(format!("SELL {} FOR {}", account, price))
}

fn edit_account_sale_to_semantic(
    parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let account_sale_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountSaleCellTypeArgs),
        Source::Output,
    )?;

    let cell_meta = CellMeta::new(account_sale_cells[0], das_types::constants::Source::Output);
    let witness_meta = parser
        .get_witness_meta_by_cell_meta(cell_meta)
        .expect("get_witness_meta_by_cell_meta failed");
    let price = get_account_sale_cell_data_price(parser, &witness_meta, cell_meta)?;

    Ok(format!("EDIT SALE INFO, CURRENT PRICE IS {}", price))
}

fn cancel_account_sale_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let account_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
        Source::Input,
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(account_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    Ok(format!("CANCEL SALE OF {}", account))
}

fn buy_account_to_semantic(parser: &mut WitnessesParserV1) -> Result<String, Box<dyn ScriptError>> {
    let account_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
        Source::Input,
    )?;
    let account_sale_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountSaleCellTypeArgs),
        Source::Input,
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(account_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    let cell_meta = CellMeta::new(account_sale_cells[0], das_types::constants::Source::Input);

    let witness_meta = parser
        .get_witness_meta_by_cell_meta(cell_meta)
        .expect("get_witness_meta_by_cell_meta failed");

    let price = get_account_sale_cell_data_price(parser, &witness_meta, cell_meta)?;
    Ok(format!("BUY {} WITH {}", account, price))
}

fn offer_to_semantic(
    _parser: &WitnessesParserV1,
    source: Source,
) -> Result<(String, String), Box<dyn ScriptError>> {
    let offer_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::OfferCellTypeArgs),
        source,
    )?;

    assert!(
        offer_cells.len() > 0,
        ErrorCode::InvalidTransactionStructure,
        "There should be at least 1 OfferCell in transaction."
    );

    let witness = util::parse_offer_cell_witness(offer_cells[0], source)?;
    let witness_reader = witness.as_reader();

    let account =
        String::from_utf8(witness_reader.account().raw_data().to_vec()).map_err(|_| {
            warn!("EIP712 decoding OfferCellData failed");
            ErrorCode::WitnessEntityDecodingError
        })?;
    let amount = to_semantic_capacity(u64::from(witness_reader.price()));

    Ok((account, amount))
}

fn make_offer_to_semantic(parser: &mut WitnessesParserV1) -> Result<String, Box<dyn ScriptError>> {
    let (account, amount) = offer_to_semantic(parser, Source::Output)?;
    Ok(format!("MAKE AN OFFER ON {} WITH {}", account, amount))
}

fn edit_offer_to_semantic(parser: &mut WitnessesParserV1) -> Result<String, Box<dyn ScriptError>> {
    let (_, old_amount) = offer_to_semantic(parser, Source::Input)?;
    let (account, new_amount) = offer_to_semantic(parser, Source::Output)?;
    Ok(format!(
        "CHANGE THE OFFER ON {} FROM {} TO {}",
        account, old_amount, new_amount
    ))
}

fn cancel_offer_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let offer_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::OfferCellTypeArgs),
        Source::Input,
    )?;

    Ok(format!("CANCEL {} OFFER(S)", offer_cells.len()))
}

fn accept_offer_to_semantic(
    parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (account, amount) = offer_to_semantic(parser, Source::Input)?;
    Ok(format!("ACCEPT THE OFFER ON {} WITH {}", account, amount))
}

fn retract_reverse_record_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let source = Source::Input;
    let reverse_record_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::ReverseRecordCellTypeArgs),
        source,
    )?;
    let lock = Script::from(
        high_level::load_cell_lock(reverse_record_cells[0], source)
            .map_err(Error::<ErrorCode>::from)?,
    );
    let address = to_semantic_address(lock.as_reader(), LockRole::Owner)?;

    Ok(format!("RETRACT REVERSE RECORDS ON {}", address))
}

fn lock_account_for_cross_chain_to_semantic(
    _parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let account_cells = util::find_cells_by_type_id(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
        Source::Input,
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(account_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    Ok(format!("LOCK {} FOR CROSS CHAIN", account))
}

fn parse_approval_tx_info(
    _parser: &WitnessesParserV1,
    source: Source,
) -> Result<(usize, String, Box<dyn AccountCellDataMixer>), Box<dyn ScriptError>> {
    let (input_cells, output_cells) = util::find_cells_by_type_id_in_inputs_and_outputs(
        ScriptType::Type,
        get_type_id(FieldKey::AccountCellTypeArgs),
    )?;

    // Parse account from the data of the AccountCell in inputs.
    let data_in_bytes = util::load_cell_data(input_cells[0], Source::Input)?;
    let account_in_bytes = data_parser::account_cell::get_account(&data_in_bytes);
    let account = String::from_utf8(account_in_bytes.to_vec())
        .map_err(|_| ErrorCode::EIP712SerializationError)?;

    let index = if source == Source::Input {
        input_cells[0]
    } else {
        output_cells[0]
    };
    let witness = util::parse_account_cell_witness(index, source)?;

    Ok((index, account, witness))
}

fn create_approval_to_semantic(
    parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (output_index, account, witness) = parse_approval_tx_info(parser, Source::Output)?;
    let witness_reader = witness.as_reader();
    let witness_reader = match witness_reader.try_into_latest() {
        Ok(reader) => reader,
        Err(_) => {
            warn!(
                "{:?}[{}] The AccountCell should be upgraded to the latest version.",
                Source::Output,
                output_index
            );
            return Err(code_to_error!(AccountCellErrorCode::WitnessParsingError));
        }
    };

    let approval_reader = witness_reader.approval();
    match approval_reader.action().raw_data() {
        b"transfer" => {
            let approval_params =
                AccountApprovalTransfer::from_compatible_slice(approval_reader.params().raw_data())
                    .map_err(|e| {
                        warn!(
                            "{:?}[{}] Decoding approval.params failed: {}",
                            Source::Output,
                            output_index,
                            e.to_string()
                        );
                        return code_to_error!(AccountCellErrorCode::WitnessParsingError);
                    })?;

            let to_lock = approval_params.to_lock();
            let to_address = to_semantic_address(to_lock.as_reader().into(), LockRole::Owner)?;
            let sealed_until = u64::from(approval_params.sealed_until());

            Ok(format!(
                "APPROVE TRANSFER {} TO {} AFTER {}",
                account, to_address, sealed_until
            ))
        }
        _ => {
            warn!(
                "{:?}[{}] Found unsupported approval action: {:?}",
                Source::Output,
                output_index,
                String::from_utf8(approval_reader.action().raw_data().to_vec())
            );
            return Err(code_to_error!(
                AccountCellErrorCode::ApprovalActionUndefined
            ));
        }
    }
}

fn delay_approval_to_semantic(
    parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (output_index, account, witness) = parse_approval_tx_info(parser, Source::Output)?;
    let witness_reader = witness.as_reader();
    let witness_reader = match witness_reader.try_into_latest() {
        Ok(reader) => reader,
        Err(_) => {
            warn!(
                "{:?}[{}] The AccountCell should be upgraded to the latest version.",
                Source::Output,
                output_index
            );
            return Err(code_to_error!(AccountCellErrorCode::WitnessParsingError));
        }
    };

    let approval_reader = witness_reader.approval();
    match approval_reader.action().raw_data() {
        b"transfer" => {
            let approval_params =
                AccountApprovalTransfer::from_compatible_slice(approval_reader.params().raw_data())
                    .map_err(|e| {
                        warn!(
                            "{:?}[{}] Decoding approval.params failed: {}",
                            Source::Output,
                            output_index,
                            e.to_string()
                        );
                        return code_to_error!(AccountCellErrorCode::WitnessParsingError);
                    })?;

            let sealed_until = u64::from(approval_params.sealed_until());

            Ok(format!(
                "DELAY THE TRANSFER APPROVAL OF {} TO {}",
                account, sealed_until
            ))
        }
        _ => {
            warn!(
                "{:?}[{}] Found unsupported approval action: {:?}",
                Source::Output,
                output_index,
                String::from_utf8(approval_reader.action().raw_data().to_vec())
            );
            return Err(code_to_error!(
                AccountCellErrorCode::ApprovalActionUndefined
            ));
        }
    }
}

fn fulfill_approval_to_semantic(
    parser: &mut WitnessesParserV1,
) -> Result<String, Box<dyn ScriptError>> {
    let (input_index, account, witness) = parse_approval_tx_info(parser, Source::Input)?;
    let witness_reader = witness.as_reader();
    let witness_reader = match witness_reader.try_into_latest() {
        Ok(reader) => reader,
        Err(_) => {
            warn!(
                "{:?}[{}] The AccountCell should be upgraded to the latest version.",
                Source::Input,
                input_index
            );
            return Err(code_to_error!(AccountCellErrorCode::WitnessParsingError));
        }
    };

    let approval_reader = witness_reader.approval();
    match approval_reader.action().raw_data() {
        b"transfer" => {
            let approval_params =
                AccountApprovalTransfer::from_compatible_slice(approval_reader.params().raw_data())
                    .map_err(|e| {
                        warn!(
                            "{:?}[{}] Decoding approval.params failed: {}",
                            Source::Input,
                            input_index,
                            e.to_string()
                        );
                        return code_to_error!(AccountCellErrorCode::WitnessParsingError);
                    })?;

            let to_lock = approval_params.to_lock();
            let to_address = to_semantic_address(to_lock.as_reader().into(), LockRole::Owner)?;

            Ok(format!(
                "FULFILL THE TRANSFER APPROVAL OF {}, TRANSFER TO {}",
                account, to_address
            ))
        }
        _ => {
            warn!(
                "{:?}[{}] Found unsupported approval action: {:?}",
                Source::Input,
                input_index,
                String::from_utf8(approval_reader.action().raw_data().to_vec())
            );
            return Err(code_to_error!(
                AccountCellErrorCode::ApprovalActionUndefined
            ));
        }
    }
}

fn transfer_to_semantic(parser: &mut WitnessesParserV1) -> Result<String, Box<dyn ScriptError>> {
    fn sum_cells(
        _parser: &WitnessesParserV1,
        source: Source,
    ) -> Result<String, Box<dyn ScriptError>> {
        let mut i = 0;
        let mut capacity_map = Map::new();
        loop {
            let ret = high_level::load_cell_capacity(i, source);
            match ret {
                Ok(capacity) => {
                    let lock = Script::from(
                        high_level::load_cell_lock(i, source)
                            .map_err(|e| Error::<ErrorCode>::from(e))?,
                    );
                    let address = to_semantic_address(lock.as_reader(), LockRole::Owner)?;
                    map_util::add(&mut capacity_map, address, capacity);
                }
                Err(SysError::IndexOutOfBound) => {
                    break;
                }
                Err(err) => {
                    return Err(Error::<ErrorCode>::from(err).into());
                }
            }

            i += 1;
        }

        let mut comma = "";
        let mut ret = String::new();
        for (address, capacity) in capacity_map.items {
            ret += format!("{}{}({})", comma, address, to_semantic_capacity(capacity)).as_str();
            comma = ", ";
        }

        Ok(ret)
    }

    let inputs = sum_cells(parser, Source::Input)?;
    let outputs = sum_cells(parser, Source::Output)?;

    Ok(format!("TRANSFER FROM {} TO {}", inputs, outputs))
}

fn transfer_dp_to_semantic(parser: &mut WitnessesParserV1) -> Result<String, Box<dyn ScriptError>> {
    let (input_cells, output_cells) = util::find_cells_by_type_id_in_inputs_and_outputs(
        ScriptType::Type,
        get_type_id(FieldKey::DpointCellTypeArgs),
    )?;

    fn sum_cells(
        _parser: &WitnessesParserV1,
        cells: Vec<usize>,
        source: Source,
    ) -> Result<String, Box<dyn ScriptError>> {
        let mut dp_map = Map::new();
        for i in cells.into_iter() {
            let ret = high_level::load_cell_data(i, source);
            match ret {
                Ok(data) => {
                    let value = data_parser::dpoint_cell::get_value(&data).unwrap_or(0);
                    let lock = Script::from(
                        high_level::load_cell_lock(i, source)
                            .map_err(|e| Error::<ErrorCode>::from(e))?,
                    );
                    let address = to_semantic_address(lock.as_reader(), LockRole::Owner)?;
                    map_util::add(&mut dp_map, address, value);
                }
                Err(SysError::IndexOutOfBound) => {
                    break;
                }
                Err(err) => {
                    return Err(Error::<ErrorCode>::from(err).into());
                }
            }
        }

        let mut comma = "";
        let mut ret = String::new();
        for (address, dp) in dp_map.items {
            ret += format!("{}{}({})", comma, address, to_semantic_currency(dp, "DP")).as_str();
            comma = ", ";
        }

        Ok(ret)
    }

    let inputs = sum_cells(parser, input_cells, Source::Input)?;
    let outputs = sum_cells(parser, output_cells, Source::Output)?;

    Ok(format!("TRANSFER FROM {} TO {}", inputs, outputs))
}

fn burn_dp_to_semantic(_parser: &mut WitnessesParserV1) -> Result<String, Box<dyn ScriptError>> {
    let (input_cells, output_cells) = util::find_cells_by_type_id_in_inputs_and_outputs(
        ScriptType::Type,
        get_type_id(FieldKey::DpointCellTypeArgs),
    )?;

    let input_dp = util::get_total_dpoint(&input_cells, Source::Input)?;
    let output_dp = util::get_total_dpoint(&output_cells, Source::Output)?;

    let lock = Script::from(high_level::load_cell_lock(input_cells[0], Source::Input)?);
    let burn_address = to_semantic_address(lock.as_reader(), LockRole::Owner)?;

    let burn_dp = if input_dp > output_dp {
        input_dp - output_dp
    } else {
        0
    };

    Ok(format!(
        "BURN {} FROM {}",
        to_semantic_currency(burn_dp, "DP"),
        burn_address
    ))
}

fn get_account_sale_cell_data_price(
    parser: &mut WitnessesParserV1,
    witness_meta: &WitnessMeta,
    cell_meta: CellMeta,
) -> Result<String, Box<dyn ScriptError>> {
    if witness_meta.data_type != DataType::AccountSaleCellData {
        return Err(Box::from(ErrorCode::WitnessDataDecodingError));
    }
    let version = witness_meta.version;
    let price = if version == 1 {
        let entity: AccountSaleCellDataV1 = parser
            .get_entity_by_cell_meta(cell_meta)
            .expect("get_entity_by_cell_meta failed");
        to_semantic_capacity(u64::from(entity.price()))
    } else {
        let entity: AccountSaleCellData = parser
            .get_entity_by_cell_meta(cell_meta)
            .expect("get_entity_by_cell_meta failed");

        to_semantic_capacity(u64::from(entity.price()))
    };
    Ok(price)
}
//AccountSaleCellData
