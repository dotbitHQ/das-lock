// use alloc::string::String;
// use alloc::vec;
// use alloc::vec::Vec;
// use das_core::{warn};
//
// use crate::error::Error;
// use crate::impl_unwrap;
//
// //const WITNESS_LENGTH_BYTES: usize = 4;
//
// #[allow(dead_code)]
// pub enum LVType {
//     LvU8(u8),
//     LvU16(u16),
//     LvU32(u32),
//     LvVecU8(Vec<u8>),
//     LvString(String),
//     //todo2: add json support
//     //LvJson ??
// }
// #[allow(dead_code)]
// impl LVType {
//     /* //use macro impl_unwrap! is better
//        pub fn unwrap_vec_u8(self) -> Vec<u8> {
//         match self {
//             LVType::LvVecU8(value) => value,
//             _ => panic!("Called `unwrap_vec_u8()` on a variant that was not LvVecU8"),
//         }
//     }
//      */
//     impl_unwrap!(LvU8, unwrap_u8, u8);
//     impl_unwrap!(LvU16, unwrap_u16, u16);
//     impl_unwrap!(LvU32, unwrap_u32, u32);
//     impl_unwrap!(LvVecU8, unwrap_vec_u8, Vec<u8>);
//     impl_unwrap!(LvString, unwrap_string, String);
// }
// pub fn parse_field(
//     field_name: &str,
//     bytes: &[u8],
//     start: usize,
//     lv_type: LVType,
// ) -> Result<(usize, LVType), Error> {
//     // Every field is start with 4 bytes of uint32 as its length.
//     let length = match bytes.get(start..(start + WITNESS_LENGTH_BYTES)) {
//         Some(bytes) => {
//             assert_eq!(
//                 bytes.len(), 4,
//                 "  [{}] witness structure error, expect {}..{} to be bytes of LE uint32.",
//                 field_name,
//                 start,
//                 start + WITNESS_LENGTH_BYTES
//             );
//
//             u32::from_le_bytes(bytes.try_into().unwrap()) as usize
//         }
//         None => {
//             warn!(
//                 "  [{}] witness structure error, expect 4 bytes in {}..{} .",
//                 field_name,
//                 start,
//                 start + WITNESS_LENGTH_BYTES
//             );
//             return Err(Error::WitnessStructureError);
//         }
//     };
//
//     // Slice the field base on the start and length.
//     let from = start + WITNESS_LENGTH_BYTES;
//     let to = from + length;
//     let field_bytes = match bytes.get(from..to) {
//         Some(bytes) => bytes,
//         None => {
//             warn!(
//                 "  [{}] witness structure error, expect {} bytes in {}..{} .",
//                 field_name, length, from, to
//             );
//             return Err(Error::WitnessStructureError);
//         }
//     };
//
//     let new_start = start + WITNESS_LENGTH_BYTES + length;
//     let filed_value = match lv_type {
//         LVType::LvU8(_) => {
//             LVType::LvU8(u8::from_le_bytes(field_bytes.try_into().unwrap()))
//         }
//         LVType::LvU16(_) => {
//             LVType::LvU16(u16::from_le_bytes(field_bytes.try_into().unwrap()))
//         }
//         LVType::LvU32(_) => {
//             LVType::LvU32(u32::from_le_bytes(field_bytes.try_into().unwrap()))
//         }
//         LVType::LvVecU8(_) => {
//             LVType::LvVecU8(field_bytes.to_vec())
//         }
//         LVType::LvString(_) => {
//             LVType::LvString(String::from_utf8(field_bytes.to_vec()).unwrap())
//         }
//     };
//     Ok((new_start, filed_value))
// }
//
//
// #[allow(dead_code)]
// pub fn parse_field_with_varying_length(
//     field_name: &str,
//     bytes: &[u8],
//     start: usize,
//     length_length: usize, //length_length is the length of length field
//     lv_type: LVType,
// ) -> Result<(usize, LVType), Error> {
//     // Every field is start with 4 bytes of uint32 as its length.
//     let length = match bytes.get(start..(start + length_length)) {
//         Some(bytes) => {
//             match length_length {
//                 1 => u8::from_le_bytes(bytes.try_into().unwrap()) as usize,
//                 2 => u16::from_le_bytes(bytes.try_into().unwrap()) as usize,
//                 4 => u32::from_le_bytes(bytes.try_into().unwrap()) as usize,
//                 _ => panic!("length_length must be 1, 2 or 4"),
//             }
//         }
//         None => {
//             warn!(
//                 "  [{}] witness structure error, expect {} bytes in {}..{} .",
//                 field_name,
//                 length_length,
//                 start,
//                 start + length_length
//             );
//             return Err(Error::WitnessStructureError);
//         }
//     };
//
//     // Slice the field base on the start and length.
//     let from = start + length_length;
//     let to = from + length;
//     let field_bytes = match bytes.get(from..to) {
//         Some(bytes) => bytes,
//         None => {
//             warn!(
//                 "  [{}] witness structure error, expect {} bytes in {}..{} .",
//                 field_name, length, from, to
//             );
//             return Err(Error::WitnessStructureError);
//         }
//     };
//
//     let new_start = start + length_length + length;
//     let filed_value = match lv_type {
//         LVType::LvU8(_) => {
//             LVType::LvU8(u8::from_le_bytes(field_bytes.try_into().unwrap()))
//         }
//         LVType::LvU16(_) => {
//             LVType::LvU16(u16::from_le_bytes(field_bytes.try_into().unwrap()))
//         }
//         LVType::LvU32(_) => {
//             LVType::LvU32(u32::from_le_bytes(field_bytes.try_into().unwrap()))
//         }
//         LVType::LvVecU8(_) => {
//             LVType::LvVecU8(field_bytes.to_vec())
//         }
//         LVType::LvString(_) => {
//             LVType::LvString(String::from_utf8(field_bytes.to_vec()).unwrap())
//         }
//     };
//     Ok((new_start, filed_value))
// }
//
//
// //parse device key list
// #[allow(dead_code)]
// pub struct DeviceKeyListLvData {
//     pk_idx: u8,
//     signature: Vec<u8>,
//     pubkey: Vec<u8>,
//     authn_data: Vec<u8>,
//     json_data: Vec<u8>,
// }
//
// #[allow(dead_code)]
// pub fn parse_device_key_list_lv(
//     bytes: &[u8],
// ) -> Result<DeviceKeyListLvData, Error> {
//     let start = 0;
//     let (start, pk_idx) = parse_field_with_varying_length("pk_idx", bytes, start,1, LVType::LvU8(0))?;
//     let (start, signature) = parse_field_with_varying_length("signature", bytes, start,1, LVType::LvVecU8(vec![]))?;
//     let (start, pubkey) = parse_field_with_varying_length("pubkey", bytes, start, 1, LVType::LvVecU8(vec![]))?;
//     let (start, authn_data) = parse_field_with_varying_length("authn_data", bytes, start, 1, LVType::LvVecU8(vec![]))?;
//     let (_, json_data) = parse_field_with_varying_length("json_data", bytes, start, 2,LVType::LvVecU8(vec![]))?;
//
//     Ok(DeviceKeyListLvData {
//         pk_idx: pk_idx.unwrap_u8(),
//         signature: signature.unwrap_vec_u8(),
//         pubkey: pubkey.unwrap_vec_u8(),
//         authn_data: authn_data.unwrap_vec_u8(),
//         json_data: json_data.unwrap_vec_u8(),
//     })
// }
//
// //parse action
// // #[allow(dead_code)]
// // pub struct ActionStringLvData {
// //     action: String,
// // }
// //
// // #[allow(dead_code)]
// // pub fn parse_action_string_lv(
// //     bytes: &[u8],
// // ) -> Result<ActionStringLvData, Error> {
// //     let start = 7;
// //     let (_, action) = parse_field("action", bytes, start, LVType::LvString(String::new()))?;
// //
// //     Ok(ActionStringLvData {
// //         action: action.unwrap_string(),
// //     })
// // }
//
// //unit test
// use das_proc_macro::test_level;
//
// #[test_level(1)]
// fn test_parse_field(){
//     //test u8
//     let bytes = vec![
//         0x01, 0x00, 0x00, 0x00, 0x12,
//         0x02, 0x00, 0x00, 0x00, 0x34, 0x56,
//         0x04, 0x00, 0x00, 0x00, 0x78, 0x9a, 0xbc, 0xde,
//         0x05, 0x00, 0x00, 0x00, 0xf0, 0x9a, 0xbc, 0xde, 0xab,
//         0x06, 0x00, 0x00, 0x00, 116, 101, 32, 115, 32, 116,];
//     let mut cursor = 5;
//     let (start, filed_value) = parse_field("test u8", &bytes, 0, LVType::LvU8(0)).unwrap();
//     assert_eq!(start, cursor);
//     assert_eq!(filed_value.unwrap_u8(), 0x12);
//
//     //test u16
//     let (start, filed_value) = parse_field("test u16", &bytes, start, LVType::LvU16(0)).unwrap();
//     cursor += 6;
//     assert_eq!(start, cursor);
//     assert_eq!(filed_value.unwrap_u16(), 0x5634);
//
//     //test u32
//     let (start, filed_value) = parse_field("test u32", &bytes, start, LVType::LvU32(0)).unwrap();
//     cursor += 8;
//     assert_eq!(start, cursor);
//     assert_eq!(filed_value.unwrap_u32(), 0xdebc9a78);
//
//     //test vec
//     let (start, filed_value) = parse_field("test vec", &bytes, start, LVType::LvVecU8(vec![])).unwrap();
//     cursor += 9;
//     assert_eq!(start, cursor);
//     assert_eq!(filed_value.unwrap_vec_u8(), vec![0xf0, 0x9a, 0xbc, 0xde, 0xab]);
//
//     //test string
//     let (start, filed_value) = parse_field("test string", &bytes, start, LVType::LvString(String::new())).unwrap();
//     cursor += 10;
//     assert_eq!(start, cursor);
//     assert_eq!(filed_value.unwrap_string(), "te s t");
//
// }
//
// #[test_level(1)]
// fn test_parse_device_key_list_lv(){
//     let data = "0115\
//     406d3ace298f3a2616fdb37ed0cd1d4fe5f19f5fec2c4ce01bc34be09e5952a756dbf76e0ec3ff1f2633ed687fa020a9471ae40292639db4b23e7211ef2fd542f7\
//     4096e07df8713895932052ce68061c208aab9210fe30adb501b32729c24a250470ddce694298aae92e415031caa81dec6767c53fea9300db49ce10ea68bc8a0805\
//     2549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000\
//     b100\
//     7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f44646b4f574d784e54597a4d6d51314e7a466d4d6a59334e6d56684f574d795a54526b4d574d774d545530596d4d784d6a67324f5745304d4745774e44466a59546c684d446c6a4f544577593245774e7a63315a41222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303031222c2263726f73734f726967696e223a66616c73657d";
//     let bytes = hex::decode(data).unwrap();
//     let device_key_list = parse_device_key_list_lv(&bytes).unwrap();
//     assert_eq!(device_key_list.pk_idx, 21); //just for test, in fact the pk_idx cannot bigger than 9
//     assert_eq!(device_key_list.signature, hex::decode("6d3ace298f3a2616fdb37ed0cd1d4fe5f19f5fec2c4ce01bc34be09e5952a756dbf76e0ec3ff1f2633ed687fa020a9471ae40292639db4b23e7211ef2fd542f7").unwrap());
//     assert_eq!(device_key_list.pubkey, hex::decode("96e07df8713895932052ce68061c208aab9210fe30adb501b32729c24a250470ddce694298aae92e415031caa81dec6767c53fea9300db49ce10ea68bc8a0805").unwrap());
//     assert_eq!(device_key_list.authn_data, hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000").unwrap());
//     assert_eq!(device_key_list.json_data, hex::decode("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f44646b4f574d784e54597a4d6d51314e7a466d4d6a59334e6d56684f574d795a54526b4d574d774d545530596d4d784d6a67324f5745304d4745774e44466a59546c684d446c6a4f544577593245774e7a63315a41222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303031222c2263726f73734f726967696e223a66616c73657d").unwrap());
//     assert_eq!(device_key_list.json_data.len(), 0xb1);
//
// }
