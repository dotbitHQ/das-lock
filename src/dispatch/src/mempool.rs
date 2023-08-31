// use crate::error::Error;
// use alloc::collections::BTreeMap;
// use alloc::vec::Vec;
// use ckb_std::ckb_constants::Source;
// use ckb_std::dynamic_loading::CKBDLContext;
// use ckb_std::error::SysError;
// use ckb_std::syscalls;
// use core::convert::Infallible;
// use das_types::constants::{DataType, WITNESS_HEADER, WITNESS_HEADER_BYTES, WITNESS_TYPE_BYTES};
// use crate::entry::MAX_WITNESS_SIZE;
//
// struct WitnessMap {
//     pub witness_map: BTreeMap<DataType, usize>,
// }
//
// struct FieldInfo {
//     pub name: &'static str,
//     pub len_bytes: usize,
// }
//
// enum DasWitness {
//     ActionData(DasAction),
//     DeviceKeyListEntityData(DasDeviceKeyEntityCell),
//     DeviceKeyListCellData(DasDeviceKeyListCell), //
// }
//
// // impl From<DataType> for DasWitness {
// //     fn from(data_type: DataType) -> Self {
// //         match data_type {
// //             DataType::ActionData => DasWitness::ActionData(DasAction {
// //                 action_data: Vec::new(),
// //                 params: 0,
// //             }),
// //             DataType::DeviceKeyListCellData => DasWitness::DeviceKeyListCellData(
// //                 DasDeviceKeyListCell {
// //                     device_key_list_cell_data: Vec::new(),
// //                     params: 0,
// //                 },
// //             ),
// //         }
// //     }
// // }
// struct DasAction {
//     pub action_data: Vec<u8>,
//     pub params: u8,
// }
// struct DasDeviceKeyListCell {
//     pub device_key_list_cell_data: Vec<u8>,
//     pub params: u8,
// }
// struct DasDeviceKeyEntityCell {
//
// }
// static mut G_WITNESS_MAP: Option<WitnessMap> = None;
// impl WitnessMap {
//     //single instance
//     pub fn get() -> &'static mut Self {
//         unsafe {
//             match G_WITNESS_MAP.as_mut() {
//                 Some(v) => v,
//                 None => {
//                     G_WITNESS_MAP = Some(Self::new());
//                     G_WITNESS_MAP.as_mut().unwrap()
//                 }
//             }
//         }
//     }
//
//     fn new() -> Self {
//         Self {
//             witness_map: BTreeMap::new(),
//         }
//     }
//
//     fn scan_all(&mut self) -> Result<(), Error> {
//         let mut i = 0;
//         loop {
//             let mut buf = [0u8; (WITNESS_HEADER_BYTES + WITNESS_TYPE_BYTES)];
//             let ret = syscalls::load_witness(&mut buf, 0, i, Source::Input);
//             match ret {
//                 Ok(_) => {
//                     i += 1;
//                 }
//                 Err(SysError::LengthNotEnough(_)) => {
//                     match buf.get(..WITNESS_HEADER_BYTES) {
//                         None => {
//                             i += 1;
//                             continue;
//                         }
//                         Some(raw) => {
//                             if raw != &WITNESS_HEADER {
//                                 i += 1;
//                                 continue;
//                             }
//                         }
//                     }
//                     if let Some(raw) =  buf.get(WITNESS_HEADER_BYTES..(WITNESS_HEADER_BYTES + WITNESS_TYPE_BYTES)){
//                             let data_type_in_int = u32::from_le_bytes(raw.try_into().unwrap());
//                             match DataType::try_from(data_type_in_int) {
//                                 Ok(d) => {
//                                     //insert into map
//                                     self.witness_map.insert(d, i);
//                                 }
//                                 Err(_) => {}
//                             }
//                     }
//                     i += 1;
//                     continue;
//                 }
//                 Err(SysError::IndexOutOfBound) => break,
//                 Err(e) => return Err(e.into()),
//             }
//         }
//
//         Ok(())
//     }
//
//     fn parse_witness(&self, buf: &[u8], data_type: DataType) -> Result<DasWitness, Error> {
//         match data_type {
//             DataType::ActionData => {
//                 let action_data = buf.get(..).unwrap();
//                 let params = buf.get(..).unwrap();
//                 Ok(DasWitness::ActionData(DasAction {
//                     action_data: action_data.to_vec(),
//                     params: params[0],
//                 }))
//             }
//             DataType::DeviceKeyListEntityData => {
//                 let device_key_list_entity_data = buf.get(..).unwrap();
//             }
//             DataType::DeviceKeyListCellData => {
//                 let device_key_list_cell_data = buf.get(..).unwrap();
//                 let params = buf.get(..).unwrap();
//                 Ok(DasWitness::DeviceKeyListCellData(
//                     DasDeviceKeyListCell {
//                         device_key_list_cell_data: device_key_list_cell_data.to_vec(),
//                         params: params[0],
//                     },
//                 ))
//             }
//
//             _ => {
//
//             }
//         }
//     }
//
//     fn get_witness(&mut self, data_type: DataType) -> Result<DasWitness, Error> {
//         //check if the witness is loaded
//         let witness_index = match self.witness_map.get(&data_type) {
//             None => return Err(Error::InvalidPubkeyIndex),
//             Some(v) => v,
//         };
//
//         //load the witness
//         let mut buf = [0u8; MAX_WITNESS_SIZE];
//         let mut witness_len = MAX_WITNESS_SIZE;
//         let ret = syscalls::load_witness(&mut buf, 0, *witness_index, Source::Input);
//         //buf, len, data_type
//         //return DasWitness
//         match ret {
//             Ok(len) => {
//                 Ok(self.parse_witness(&buf, data_type)?)
//                 //parse it to DasWitness
//                 //return DasWitness
//                 //return Ok(())
//             }
//             Err(e) => return Err(e.into()),
//         }
//     }
// }
