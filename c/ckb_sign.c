#include "inc_def.h"

int verify_signature(uint8_t *message, uint8_t *lock_bytes, const void *lock_args) {
	debug_print("Enter verify_signature");
	debug_print_data("digest: ", message, HASH_SIZE);
	debug_print_data("WitnessArgs.lock(lock_bytes): ", lock_bytes, RECID_INDEX + 1);
	debug_print_data("lock_args: ", lock_args, BLAKE160_SIZE);
	int ret = CKB_SUCCESS;
	uint8_t temp[TEMP_SIZE];

	/* Load signature */
	secp256k1_context context;
	uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
	ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
	SIMPLE_ASSERT(CKB_SUCCESS);

	secp256k1_ecdsa_recoverable_signature signature;
	if (secp256k1_ecdsa_recoverable_signature_parse_compact(
		&context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
		return ERROR_SECP_PARSE_SIGNATURE;
	}
	debug_print_data("secp256k1_ecdsa_recoverable_signature signature: ", signature.data, 65);

	/* Recover pubkey */
	secp256k1_pubkey pubkey;
	if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
		return ERROR_SECP_RECOVER_PUBKEY;
	}
	debug_print_data("secp256k1_pubkey pubkey: ", pubkey.data, 64);

	/* Check pubkey hash */
	size_t pubkey_size = SIGNATURE_SIZE;
	if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
		return ERROR_SECP_SERIALIZE_PUBKEY;
	}
	debug_print_data("before last blake2b, temp: ", temp, pubkey_size);

	blake2b_state blake2b_ctx;
	blake2b_init(&blake2b_ctx, HASH_SIZE);
	blake2b_update(&blake2b_ctx, temp, pubkey_size);
	blake2b_final(&blake2b_ctx, temp, HASH_SIZE);

	if (memcmp(lock_args, temp, BLAKE160_SIZE) != 0) {
		debug_print_data("cmp failed, temp: ", temp, BLAKE160_SIZE);
		debug_print_data("cmp failed, lock_args: ", lock_args, BLAKE160_SIZE);
		return ERROR_PUBKEY_BLAKE160_HASH;
	}


	return ret;
}

__attribute__((visibility("default"))) int validate(int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args) {

	debug_print("Enter validate");

	/* verify signature with peronsal hash */
	return verify_signature(message, lock_bytes, lock_args);
}
