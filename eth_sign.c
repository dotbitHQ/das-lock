
#include "inc_def.h"


int verify_signature(uint8_t *message, uint8_t *lock_bytes,
                    const void *lock_args) {
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
	if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
					  SECP256K1_EC_UNCOMPRESSED) != 1) {
		return ERROR_SECP_SERIALIZE_PUBKEY;
	}
	debug_print_data("before last blake2b, temp: ", temp, pubkey_size);

	SHA3_CTX sha3_ctx;
	keccak_init(&sha3_ctx);
	keccak_update(&sha3_ctx, &temp[1], pubkey_size - 1);
	keccak_final(&sha3_ctx, temp);

	debug_print_data("after last blake2b, temp: ", temp, pubkey_size);
	if (memcmp(lock_args, &temp[12], BLAKE160_SIZE) != 0) {
		return ERROR_PUBKEY_BLAKE160_HASH;
	}

	debug_print_int("END OF ETH SIGN: ret ", ret);
	return ret;
}

__attribute__((visibility("default"))) int validate(int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* eth_address) {

	debug_print("Enter validate");
	debug_print_data("digest before keccak with eth prefix: ", message, HASH_SIZE);
	debug_print_int("type: ", type);
	if (type == 1) { // eip712
		return verify_signature(message, lock_bytes, eth_address);
	}

    uint8_t message_hex_string[64];
    bin_to_hex(message_hex_string, message, HASH_SIZE);

    uint8_t message_with_prefix[COMMON_PREFIX_AND_MESSAGE_LENGTH];
    memcpy(message_with_prefix, COMMON_PREFIX, COMMON_PREFIX_LENGTH);
    memcpy(message_with_prefix + COMMON_PREFIX_LENGTH, message_hex_string, 64);
    debug_print_data("message_with_prefix ", message_with_prefix, COMMON_PREFIX_AND_MESSAGE_LENGTH);
    //message = "from .bit" + message;
	/* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
	uint8_t eth_prefix[28];
	eth_prefix[0] = 0x19;
	memcpy(eth_prefix + 1, "Ethereum Signed Message:\n75", 27);
    debug_print_data("eth_prefix ", eth_prefix, 28);


    SHA3_CTX sha3_ctx;
	keccak_init(&sha3_ctx);
	keccak_update(&sha3_ctx, eth_prefix, 28);
	keccak_update(&sha3_ctx, message_with_prefix, COMMON_PREFIX_AND_MESSAGE_LENGTH);
	keccak_final(&sha3_ctx, message);

	/* verify signature with peronsal hash */
	return verify_signature(message, lock_bytes, eth_address);
}


__attribute__((visibility("default"))) int validate_str(int type, uint8_t* message, size_t message_len, uint8_t* lock_bytes, uint8_t* eth_address) {

	debug_print("Enter validate_str");
	debug_print_data("digest before keccak with eth prefix: ", message, message_len);
	debug_print_int("type: ", type);
	debug_print_int("message_len: ", message_len);
    if (type == 1) { // eip712
		return verify_signature(message, lock_bytes, eth_address);
	}
    uint8_t eth_prefix[50];
    eth_prefix[0] = 0x19;
    memcpy(eth_prefix + 1, "Ethereum Signed Message:\n", 25);

    //convert message to hex
    uint8_t message_hex[message_len * 2];
    bin_to_hex(message_hex, message, message_len);

    //common prefix
    uint8_t message_with_prefix_length = COMMON_PREFIX_LENGTH + message_len * 2;
    uint8_t message_with_prefix[message_with_prefix_length];
    memcpy(message_with_prefix, COMMON_PREFIX, COMMON_PREFIX_LENGTH);
    memcpy(message_with_prefix + COMMON_PREFIX_LENGTH, message_hex, message_len * 2);
    debug_print_data("message_with_prefix : ", message_with_prefix, message_with_prefix_length);

    uint8_t len_str[10];
    int2str(message_with_prefix_length, len_str);
    size_t len_str_len = strlen((const char*)len_str);
    debug_print_data("len_str: ", len_str, len_str_len);
    debug_print_int("len_str_len: ", len_str_len);

    memcpy(eth_prefix + 26, len_str, len_str_len);
    debug_print_data("eth_prefix before keccak: ", eth_prefix, len_str_len + 26);

    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, eth_prefix, 26 + len_str_len);
    keccak_update(&sha3_ctx, message_with_prefix, message_with_prefix_length);
    //keccak_update(&sha3_ctx, message, message_len);
    keccak_final(&sha3_ctx, message);

    /* verify signature with personal hash */
    return verify_signature(message, lock_bytes, eth_address);

}
