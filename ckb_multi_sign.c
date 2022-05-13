#include "inc_def.h"

int check_lock_args(uint8_t* lock_bytes, uint8_t* lock_args) {
	debug_print("Enter check_lock_args");
	int ret = CKB_SUCCESS;

	// Extract multisig script flags.
	uint8_t pubkeys_cnt = lock_bytes[3];
	uint8_t threshold = lock_bytes[2];
	uint8_t require_first_n = lock_bytes[1];
	uint8_t reserved_field = lock_bytes[0];
	if (reserved_field != 0) {
		return ERROR_INVALID_RESERVE_FIELD;
	}
	if (pubkeys_cnt == 0) {
		return ERROR_INVALID_PUBKEYS_CNT;
	}
	if (threshold > pubkeys_cnt) {
		return ERROR_INVALID_THRESHOLD;
	}
	if (threshold == 0) {
		return ERROR_INVALID_THRESHOLD;
	}
	if (require_first_n > threshold) {
		return ERROR_INVALID_REQUIRE_FIRST_N;
	}
	// Based on the number of public keys and thresholds, we can calculate
	// the required length of the lock field.
	size_t multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * pubkeys_cnt;

	// Perform hash check of the `multisig_script` part, notice the signature part
	// is not included here.
	uint8_t temp[TEMP_SIZE];
	blake2b_state blake2b_ctx;
	blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
	blake2b_update(&blake2b_ctx, lock_bytes, multisig_script_len);
	blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

	if (memcmp(lock_args, temp, BLAKE160_SIZE) != 0) {
		return ERROR_MULTSIG_SCRIPT_HASH;
	}

	// Check lock period logic, we have prepared a handy utility function for this.
	uint64_t since = 0;
	since = *(uint64_t *)&lock_args[BLAKE160_SIZE];
	ret = check_since(since);
	SIMPLE_ASSERT(CKB_SUCCESS);

	return ret;
}

int verify_signature(uint8_t* message, uint8_t* lock_bytes) {
	debug_print("Enter verify_signature");
	int ret = CKB_SUCCESS;

	uint8_t threshold = lock_bytes[2];
	uint8_t used_signatures[threshold];
	memset(used_signatures, 0, threshold);

	// We are using bitcoin's [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
	// for signature verification here. To the best of our knowledge, this is an unmatched
	// advantage of CKB: you can ship cryptographic algorithm within your smart contract,
	// you don't have to wait for the foundation to ship a new cryptographic algorithm. You
	// can just build and ship your own.
	secp256k1_context context;
	uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
	ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
	if (ret != 0) {
		return ret;
	}

	uint8_t pubkeys_cnt = lock_bytes[3];
	size_t multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * pubkeys_cnt;
	// We will perform *threshold* number of signature verifications here.
	for (size_t i = 0; i < threshold; i++) {
		// Load signature
		secp256k1_ecdsa_recoverable_signature signature;
		size_t signature_offset = multisig_script_len + i * SIGNATURE_SIZE;
		if (secp256k1_ecdsa_recoverable_signature_parse_compact(
					&context, &signature, &lock_bytes[signature_offset],
					lock_bytes[signature_offset + RECID_INDEX]) == 0) {
			return ERROR_SECP_PARSE_SIGNATURE;
		}

		// verifiy signature and Recover pubkey
		secp256k1_pubkey pubkey;
		if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
			return ERROR_SECP_RECOVER_PUBKEY;
		}

		// Calculate the blake160 hash of the derived public key
		size_t pubkey_size = PUBKEY_SIZE;
		unsigned char temp[TEMP_SIZE];
		if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
					SECP256K1_EC_COMPRESSED) != 1) {
			return ERROR_SECP_SERIALIZE_PUBKEY;
		}

		unsigned char calculated_pubkey_hash[BLAKE2B_BLOCK_SIZE];
		blake2b_state blake2b_ctx;
		blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
		blake2b_update(&blake2b_ctx, temp, PUBKEY_SIZE);
		blake2b_final(&blake2b_ctx, calculated_pubkey_hash, BLAKE2B_BLOCK_SIZE);

		// Check if this signature is signed with one of the provided public key.
		uint8_t matched = 0;
		for (size_t i = 0; i < pubkeys_cnt; i++) {
			if (used_signatures[i] == 1) {
				continue;
			}
			if (memcmp(&lock_bytes[FLAGS_SIZE + i * BLAKE160_SIZE],
						calculated_pubkey_hash, BLAKE160_SIZE) != 0) {
				continue;
			}
			matched = 1;
			used_signatures[i] = 1;
			break;
		}

		// If the signature doesn't match any of the provided public key, the script
		// will exit with an error.
		if (matched != 1) {
			return ERROR_VERIFICATION;
		}
	}

	// The above scheme just ensures that a *threshold* number of signatures have
	// successfully been verified, and they all come from the provided public keys.
	// However, the multisig script might also require some numbers of public keys
	// to always be signed for the script to pass verification. This is indicated
	// via the *required_first_n* flag. Here we also checks to see that this rule
	// is also satisfied.
	uint8_t require_first_n = lock_bytes[1];
	for (size_t i = 0; i < require_first_n; i++) {
		if (used_signatures[i] != 1) {
			return ERROR_VERIFICATION;
		}
	}
	return ret;
}

__attribute__((visibility("default"))) int validate(int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args) {
	debug_print("Enter validate");
	int ret = CKB_SUCCESS;

	ret = check_lock_args(lock_bytes, lock_args);
	SIMPLE_ASSERT(CKB_SUCCESS);


	/* verify signature with personal hash */
	return verify_signature(message, lock_bytes);
}
