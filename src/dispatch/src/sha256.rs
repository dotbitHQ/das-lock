// use alloc::vec::Vec;
// use sha2::{Digest, Sha256};
//
// fn compute_sha256(input: &[u8], rounds: usize) -> Vec<u8> {
//     let mut output = input.to_vec();
//     for _ in 0..rounds {
//         let mut hasher = Sha256::new();
//         hasher.update(&output);
//         output = hasher.finalize().to_vec();
//     }
//     output
// }

// #[test]
// fn test_sha256_once() {
//     let data = b"Hello, world!";
//     let hashed_data = compute_sha256(data, 1);
//     let expected = "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9";
//     assert_eq!(
//         alloc::format!("{:x}", hashed_data.iter().format("")),
//         expected
//     );
// }
//
// #[test]
// fn test_sha256_twice() {
//     let data = b"Hello, world!";
//     let hashed_data = compute_sha256(data, 2);
//     let expected = Sha256::digest(&Sha256::digest(data).as_slice());
//     assert_eq!(hashed_data, expected.as_slice());
// }
//
// #[test]
// fn test_sha256_empty_data() {
//     let data = b"";
//     let hashed_data = compute_sha256(data, 1);
//     let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
//     assert_eq!(
//         alloc::format!("{:x}", hashed_data.iter().format("")),
//         expected
//     );
// }
//
// #[test]
// fn test_sha256_zero_rounds() {
//     let data = b"Hello, world!";
//     let hashed_data = compute_sha256(data, 0);
//     assert_eq!(hashed_data, data);
// }
