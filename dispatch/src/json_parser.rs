// #![no_std]
//
// extern crate alloc;
// use alloc::string::{String, ToString};
// use core::str;
// use crate::error::Error;
// use alloc::vec::Vec;
// use base64::DecodeError;
// use ckb_std::debug;
//
// //find challenge in json
// pub fn extract_challenge(input: &[u8]) -> Result<String, Error> {
//     // convert input bytes to string
//     let input_str = match str::from_utf8(input){
//         Ok(v) => {v}
//         Err(e) => {
//             debug!("str::from_utf8 error: {:?}", e);
//             return Err(Error::InvalidString);
//         }
//     };
//
//     // find "challenge" field
//     if let Some(start_idx) = input_str.find("\"challenge\":\"") {
//         // jump over field name and quotes
//         let start = start_idx + "\"challenge\":\"".len();
//         let end = start + 86; // fixed length 86 characters
//
//         // check if index is out of range
//         if end <= input_str.len() {
//             let a = input_str[start..end].to_string();
//             return Ok(input_str[start..end].to_string());
//         }
//     }
//
//     Err(Error::InvalidString)
//     //Err("Field 'challenge' not found or its value is not 86 characters long")
// }
//
//
// fn base64_url_decode(input: &str) -> Result<Vec<u8>, Error> {
//     match base64_url::decode(input){
//         Ok(v) => {Ok(v)}
//         Err(e) => {
//             debug!("base64_url_decode error: {:?}", e);
//             Err(Error::InvalidString)
//         }
//     }
//
// }
//
// pub fn extract_and_decode_challenge(input: &[u8]) -> Result<Vec<u8>, Error> {
//     let challenge_str = extract_challenge(input)?;
//
//     base64_url_decode(&challenge_str)
// }
///////////////////////////////use serde but have some trouble/////////////////////////////////////////

//use serde
//#![no_std]
//#![no_main]

//extern crate alloc;
//extern crate serde;
//extern crate serde_json;

//use alloc::string::String;
//use alloc::vec::Vec;
//use serde::{Deserialize, Serialize};
//use crate::error::Error;
//
// #[derive(Debug, Deserialize, Serialize)]
// struct WebAuthnJson {
//     #[serde(rename = "type")]
//     type_field: String,
//     challenge: String,
//     origin: String,
//     #[serde(default)]
//     crossOrigin: Option<bool>,
//     #[serde(flatten)]
//     extra: serde_json_core::Value,
// }
//
// pub fn extract_challenge(input: &[u8]) -> Result<String, serde_json::Error> {
//     // convert &[u8] to str
//     let input_str = str::from_utf8(input).map_err(|_| serde_json::Error::custom("Invalid UTF-8"))?;
//
//     // deserilize JSON data
//     let data: WebAuthnJson = serde_json::from_str(input_str)?;
//
//     // check the length of challenge string
//     if data.challenge.len() == 86 {
//         Ok(data.challenge)
//     } else {
//         Err(serde_json::Error::custom("Challenge string is not 86 characters long"))
//     }
// }
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_webauthn_decode() {
//         let data = r#"{ "type": "webauthn.get", "challenge": "32d81bc302f450ea3a67ef4c1db5c3da845ca12dc71ac211a43a5a2267ecac1a15c3cc225123", "origin": "http://localhost", "crossOrigin": false, "unknown_field": "some value" }"#;
//
//         let decoded: WebAuthn = serde_json_core::from_str(data).unwrap();
//
//         assert_eq!(decoded.type_field, "webauthn.get");
//         assert_eq!(
//             decoded.challenge,
//             "32d81bc302f450ea3a67ef4c1db5c3da845ca12dc71ac211a43a5a2267ecac1a15c3cc225123"
//         );
//         assert_eq!(decoded.origin, "http://localhost");
//         assert_eq!(decoded.crossOrigin, Some(false));
//     }
// }
//////////////////////////////////////////////////////////////////////////////
