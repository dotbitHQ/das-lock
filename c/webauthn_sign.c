#include "inc_def.h"
#include "sha256.h"
#include "json_operator.h"
#include "secp256r1_helper.h"
#include "keylist_oprate.h"
enum SubAlgId {
    Secp256r1 = 7,
};

int verify_signature_secp256r1(uint8_t *sig, uint8_t *msg, size_t msg_len, uint8_t *pk) {
    int ret = 0;

    ret = secp256r1_verify(sig, msg, msg_len, pk);
    debug_print_int("Verify the signature, result = ", ret);
    NORMAL_ASSERT(0, ERROR_SECP_VERIFICATION);

    return ret;
}


/*
 * Input parameters:
 *      message: digest of webauthn, 32 bytes;
 *      locked_bytes: signature of webauthn, 67 bytes; (length, main_alg_id, sub_alg_id, pk_idx, signature)
 *      lock_args: payload, 22 bytes; (length, main_alg_id, sub_alg_id, cid`, pk`)
 *
 */
int verify_signature(uint8_t *sig, size_t sig_len, uint8_t *message, size_t message_len,
                     uint8_t *pk, size_t pk_len, uint8_t sub_alg_id) {
    int ret = CKB_SUCCESS;

    //int sub_alg_id = lock_args[1];
    debug_print_int("sub_alg_id = ", sub_alg_id);
    switch (sub_alg_id) {
        case Secp256r1: {
            ret = verify_signature_secp256r1(sig, message, message_len, pk);
            break;
        }
        default: {
            debug_print("wrong value in sub_alg_id");
            return -1;
        }

    }
    return ret;
}

int get_tx_digest_from_json(uint8_t *tx_digest, uint8_t *json_data, size_t json_len) {
    int ret = 0;

    //get challenge string from json that is base64url encoded
    size_t challenge_len = 100;
    char challenge_str[100] = {0}; //The challenge has a fixed length of 86 characters.
    ret = get_challenge_from_json(challenge_str, &challenge_len, json_data, json_len);
    debug_print_string("challenge_str = ", (unsigned char *) challenge_str, challenge_len);
    SIMPLE_ASSERT(0);

    //convert from base64url to string
    char tx_digest_str[64];//The tx_digest has a fixed length of 64 characters.
    ret = decode_base64url_to_string(tx_digest_str, challenge_str, &challenge_len);
    debug_print_int("decode_base64url_to_string, ret = ", ret);
    SIMPLE_ASSERT(0);

    //convert from string to bytes
    //11 is the length of "From .bit "
    //If there is no From.bit at the beginning, it will report an error and exit
    if (memcmp(tx_digest_str, COMMON_PREFIX, COMMON_PREFIX_LENGTH) == 0) {
        memcpy(tx_digest, tx_digest_str, COMMON_PREFIX_LENGTH);
        str2bin(tx_digest + COMMON_PREFIX_LENGTH, (unsigned char *) (tx_digest_str + COMMON_PREFIX_LENGTH),
                challenge_len - COMMON_PREFIX_LENGTH);
    } else {
        //str2bin(tx_digest, (unsigned char *) (tx_digest_str), challenge_len);
        return -1; //

    }
    return 0;
}
/*
 * Input parameters:
 *      type: don't care;
 *      message: digest of transaction, 32 bytes;
 *      lock_bytes: contains 5 parts, pubkey_index, signature, pubkey, authenticator_data, client_data_json
 *      lock_args: payload, 22 bytes; (main_alg_id, sub_alg_id, cid`, pk`)
 *
 */
//for lock contract use
__attribute__((visibility("default"))) int validate(int type, uint8_t *message, uint8_t *lock_bytes, uint8_t *lock_args) {
    int ret = 0;

    //print some log
    debug_print("Enter validate WebAuthn ");
    //debug_print_int("type: ", type);
    //debug_print_data("message: ", message, SHA256_HASH_SIZE);
    //debug_print_data("lock_bytes[0..10] : ", lock_bytes, 10);
    //debug_print_data("lock_args: ", lock_args, DAS_MAX_LOCK_ARGS_SIZE);

    //it is a variable length array, the first byte is the length of the array
    uint8_t pk_idx_offset = 0;
    uint8_t pk_idx_len = lock_bytes[pk_idx_offset];
    uint8_t pk_idx_value = lock_bytes[pk_idx_offset + 1];

    uint8_t sig_offset = pk_idx_offset + 2;
    uint8_t sig_len = lock_bytes[sig_offset];
    uint8_t *sig_value = lock_bytes + sig_offset + 1;

    uint8_t pk_offset = sig_offset + sig_len + 1;
    uint8_t pk_len = lock_bytes[pk_offset];
    uint8_t *pk_value = lock_bytes + pk_offset + 1;

    uint8_t authn_data_offset = pk_offset + pk_len + 1;
    size_t authn_data_len = lock_bytes[authn_data_offset];  //authn_data length use size_t
    uint8_t *authn_data_value = lock_bytes + authn_data_offset + 1;

    uint8_t json_offset = authn_data_offset + authn_data_len + 1;
    //note: json length is 2 bytes, small endian
    size_t json_len = lock_bytes[json_offset] + lock_bytes[json_offset + 1] * 256;
    uint8_t *json_value = lock_bytes + json_offset + 2;

    //Because need lock_bytes to provide pk_idx, put it here instead of the function get_lock_args
    //get pubkey idx
    unsigned char pk_idx = pk_idx_value;
    //
    unsigned char args_index = type;
    debug_print_int("pk_idx = ", pk_idx);

    //255 is for the case that don't have DeviceKeyListCell, just use lock_args to verify
    if (pk_idx != 255) {
        if (pk_idx > 9) {
            debug_print_int("public key index out of bounds, pk idx = ", pk_idx);
            return ERROR_ARGUMENTS_VALUE;
        }

        //get the payload according to the public key index and store it in lock_args
        //just use witness_action as temp buffer
        //use args_index to distinguish between owner and manager
        unsigned char temp[MAX_WITNESS_SIZE] = {0};
        ret = get_payload_from_cell(lock_args, temp, pk_idx, args_index);
        debug_print_int("get_payload from witness, ret = ", ret);
        SIMPLE_ASSERT(0);

        debug_print_data("payload from cell = ", lock_args, 21);
    }


    uint8_t sub_alg_id = lock_args[0];


    //print some log
    debug_print_int("pk_idx_len = ", pk_idx_len);
    debug_print_int("pk_idx_value = ", pk_idx_value);
    debug_print_int("sig_len = ", sig_len);
    debug_print_data("sig_value = ", sig_value, sig_len);
    debug_print_int("pk_len = ", pk_len);
    debug_print_data("pk_value = ", pk_value, pk_len);
    debug_print_int("authn_len = ", authn_data_len);
    debug_print_data("authn_value = ", authn_data_value, authn_data_len);
    debug_print_int("json_len = ", json_len);
    debug_print_string("json_value = ", json_value, json_len);
    debug_print_int("sub_alg_id = ", sub_alg_id);
    debug_print_data("lock_args = ", lock_args, 22);
    //check if value length is correct
    if (pk_idx_len != 1 || sig_len != 64 || pk_len != 64) {
        debug_print("Data parsing error, please check the length of the public key index and signature.");
        return ERROR_ARGUMENTS_LEN;
    }

    //check if pk_idx is correct
    if (pk_idx_value != 255 && pk_idx_value > 9) {
        debug_print("pk_idx is not correct");
        return ERROR_ARGUMENTS_VALUE;
    }

    //check if the sig_sub_alg_id is supported, now only support secp256r1
    if (sub_alg_id != Secp256r1) {
        debug_print_int("sub_alg_id = ", sub_alg_id);
        debug_print("Unsupported sub-algorithm id.");
        return ERROR_ARGUMENTS_VALUE;
    }

    //sha256x5 for pubkey and compare with the pubkey` in lock_args
    uint8_t pubkey_hash[HASH_SIZE] = {0};
    sha256_many_round(pubkey_hash, pk_value, 64, 5);
    ret = memcmp(pubkey_hash, lock_args + 11, 10); //11 is the offset of pubkey` in lock_args
    if (ret != 0) {
        debug_print_data("pubkey_hash calculated = ", pubkey_hash, 10);
        debug_print_data("pubkey_hash in lock_args = ", lock_args + 11, 10);
        debug_print("pubkey_hash is not equal to pubkey` in lock_args");
        return ERROR_SECP_PARSE_PUBKEY;
    }

    //get tx-digest from json then compare with the tx-digest calculated from transaction
    uint8_t tx_digest[100] = {0};
    ret = get_tx_digest_from_json(tx_digest, json_value, json_len);
    debug_print_int("get_tx_digest_from_json ret = ", ret);
    SIMPLE_ASSERT(0);

    //compare with the tx_digest
    ret = memcmp(tx_digest, COMMON_PREFIX, COMMON_PREFIX_LENGTH) +
          memcmp(tx_digest + COMMON_PREFIX_LENGTH, message, HASH_SIZE);

    if (ret != 0) {
        debug_print_data("tx_digest from json parsed = ", tx_digest, COMMON_PREFIX_LENGTH + HASH_SIZE);
        debug_print_data("tx_digest from transaction calculated = ", message, HASH_SIZE);
        debug_print("tx_digest from json is not equal to tx_digest calculated");
        return ERROR_INCORRECT_DIGEST;
    }

    //calculate the sha256 of the json
    uint8_t json_hash[SHA256_HASH_SIZE] = {0};
    sha256x1(json_hash, json_value, json_len);
    //debug_print_data("json_hash = ", json_hash, SHA256_HASH_SIZE);

    //splice WebAuthn digest
    //authn_data_len + SHA256_HASH_SIZE = 37 + 32 = 69
    //const size_t webauthn_digest_len = 69; //maybe not support in c89
    uint8_t webauthn_digest[WEBAUTHN_DIGEST_LEN] = {0};
    memcpy(webauthn_digest, authn_data_value, authn_data_len);
    memcpy(webauthn_digest + authn_data_len, json_hash, SHA256_HASH_SIZE);
    debug_print_data("webauthn_digest ", webauthn_digest, WEBAUTHN_DIGEST_LEN);

    /* verify signature with payload */
    return verify_signature(sig_value, 64, webauthn_digest, WEBAUTHN_DIGEST_LEN, pk_value, 64, sub_alg_id);

}

//for type contract use
__attribute__((visibility("default"))) int validate_str(int type, uint8_t *message, size_t message_len,
                                                        uint8_t *lock_bytes, uint8_t *lock_args) {

    debug_print("Enter validate_str WebAuthn ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, message_len);
    debug_print_int("message_len: ", message_len);
    debug_print_data("lock_bytes: ", lock_bytes, SIGNATURE_DOGE_SIZE);
    debug_print_data("lock_args: ", lock_args, RIPEMD160_HASH_SIZE);
    int ret = 0;

    //it is a variable length array, the first byte is the length of the array
    uint8_t pk_idx_offset = 0;
    uint8_t pk_idx_len = lock_bytes[pk_idx_offset];
    uint8_t pk_idx_value = lock_bytes[pk_idx_offset + 1];

    uint8_t sig_offset = pk_idx_offset + 2;
    uint8_t sig_len = lock_bytes[sig_offset];
    uint8_t *sig_value = lock_bytes + sig_offset + 1;

    uint8_t pk_offset = sig_offset + sig_len + 1;
    uint8_t pk_len = lock_bytes[pk_offset];
    uint8_t *pk_value = lock_bytes + pk_offset + 1;

    uint8_t authn_data_offset = pk_offset + pk_len + 1;
    size_t authn_data_len = lock_bytes[authn_data_offset];  //authn_data length use size_t
    uint8_t *authn_data_value = lock_bytes + authn_data_offset + 1;

    uint8_t json_offset = authn_data_offset + authn_data_len + 1;
    //note: json length is 2 bytes, small endian
    size_t json_len = lock_bytes[json_offset] + lock_bytes[json_offset + 1] * 256;
    uint8_t *json_value = lock_bytes + json_offset + 2;

    uint8_t sub_alg_id = lock_args[0];


    //print some log
    debug_print_int("pk_idx_len = ", pk_idx_len);
    debug_print_int("pk_idx_value = ", pk_idx_value);
    debug_print_int("sig_len = ", sig_len);
    debug_print_data("sig_value = ", sig_value, sig_len);
    debug_print_int("pk_len = ", pk_len);
    debug_print_data("pk_value = ", pk_value, pk_len);
    debug_print_int("authn_len = ", authn_data_len);
    debug_print_data("authn_value = ", authn_data_value, authn_data_len);
    debug_print_int("json_len = ", json_len);
    debug_print_data("json_value = ", json_value, json_len);
    debug_print_int("sub_alg_id = ", sub_alg_id);
    debug_print_data("lock_args = ", lock_args, 22);
    //check if value length is correct
    if (pk_idx_len != 1 || sig_len != 64 || pk_len != 64) {
        debug_print("Data parsing error, please check the length of the public key index and signature.");
        return ERROR_ARGUMENTS_LEN;
    }

    //check if pk_idx is correct
    if (pk_idx_value != 255 && pk_idx_value > 9) {
        debug_print("pk_idx is not correct");
        return ERROR_ARGUMENTS_VALUE;
    }

    //check if the sig_sub_alg_id is supported, now only support secp256r1
    if (sub_alg_id != Secp256r1) {
        debug_print_int("sub_alg_id = ", sub_alg_id);
        debug_print("Unsupported sub-algorithm id.");
        return ERROR_ARGUMENTS_VALUE;
    }

    //sha256x5 for pubkey and compare with the pubkey` in lock_args
    uint8_t pubkey_hash[HASH_SIZE] = {0};
    sha256_many_round(pubkey_hash, pk_value, 64, 5);
    ret = memcmp(pubkey_hash, lock_args + 11, 10);
    if (ret != 0) {
        debug_print_data("pubkey_hash calculated = ", pubkey_hash, 10);
        debug_print_data("pubkey_hash in lock_args = ", lock_args + 11, 10);
        debug_print("pubkey_hash is not equal to pubkey` in lock_args");
        return ERROR_SECP_PARSE_PUBKEY;
    }

    //get tx-digest from json then compare with the tx-digest calculated from transaction
    uint8_t tx_digest[100] = {0};
    ret = get_tx_digest_from_json(tx_digest, json_value, json_len);
    debug_print_int("get_tx_digest_from_json ret = ", ret);
    SIMPLE_ASSERT(0);

    //compare with the tx_digest
    ret = memcmp(tx_digest, COMMON_PREFIX, COMMON_PREFIX_LENGTH) +
          memcmp(tx_digest + COMMON_PREFIX_LENGTH, message, HASH_SIZE);

    if (ret != 0) {
        debug_print_data("tx_digest from json parsed = ", tx_digest, COMMON_PREFIX_LENGTH + HASH_SIZE);
        debug_print_data("tx_digest from transaction calculated = ", message, HASH_SIZE);
        debug_print("tx_digest from json is not equal to tx_digest calculated");
        return ERROR_INCORRECT_DIGEST;
    }

    //calculate the sha256 of the json
    uint8_t json_hash[SHA256_HASH_SIZE] = {0};
    sha256x1(json_hash, json_value, json_len);

    //splice WebAuthn digest
    //authn_data_len + SHA256_HASH_SIZE = 37 + 32 = 69
    //const size_t webauthn_digest_len = 69; //maybe not support in c89
    uint8_t webauthn_digest[WEBAUTHN_DIGEST_LEN] = {0};
    memcpy(webauthn_digest, authn_data_value, authn_data_len);
    memcpy(webauthn_digest + authn_data_len, json_hash, SHA256_HASH_SIZE);
    debug_print_data("webauthn_digest ", webauthn_digest, WEBAUTHN_DIGEST_LEN);

    /* verify signature with payload */
    return verify_signature(sig_value, 64, webauthn_digest, WEBAUTHN_DIGEST_LEN, pk_value, 64, sub_alg_id);


    //return verify_signature(message, lock_bytes, lock_args, message_len);
    //return -1;
}

//for type contract use
__attribute__((visibility("default"))) int validate_device(
        int version, uint8_t *sig, size_t sig_len, uint8_t *msg, size_t msg_len, uint8_t *device_key_list,
        size_t device_key_list_len, uint8_t *data, size_t data_len
){
    debug_print("Enter validate_device WebAuthn");
    debug_print_int("version: ", version);
    debug_print_data("sig: ", sig, sig_len);
    debug_print_int("sig_len: ", sig_len);
    debug_print_data("msg: ", msg, msg_len);
    debug_print_int("msg_len: ", msg_len);
    debug_print_data("device_key_list: ", device_key_list, device_key_list_len);
    debug_print_int("device_key_list_len: ", device_key_list_len);
    debug_print_data("data: ", data, data_len);
    debug_print_int("data_len: ", data_len);

    int ret = 0;
    uint8_t *lock_bytes = sig;

    //it is a variable length array, the first byte is the length of the array
    uint8_t pk_idx_offset = 0;
    uint8_t pk_idx_len = lock_bytes[pk_idx_offset];
    uint8_t pk_idx_value = lock_bytes[pk_idx_offset + 1];

    uint8_t sig_offset = pk_idx_offset + 2;
    uint8_t sig_len_inner = lock_bytes[sig_offset];
    uint8_t *sig_value = lock_bytes + sig_offset + 1;

    uint8_t pk_offset = sig_offset + sig_len_inner + 1;
    uint8_t pk_len = lock_bytes[pk_offset];
    uint8_t *pk_value = lock_bytes + pk_offset + 1;

    uint8_t authn_data_offset = pk_offset + pk_len + 1;
    size_t authn_data_len = lock_bytes[authn_data_offset];  //authn_data length use size_t
    uint8_t *authn_data_value = lock_bytes + authn_data_offset + 1;

    uint8_t json_offset = authn_data_offset + authn_data_len + 1;
    //note: json length is 2 bytes, small endian
    size_t json_len = lock_bytes[json_offset] + lock_bytes[json_offset + 1] * 256;
    uint8_t *json_value = lock_bytes + json_offset + 2;


    //print some log
    debug_print_int("pk_idx_len = ", pk_idx_len);
    debug_print_int("pk_idx_value = ", pk_idx_value);
    debug_print_int("sig_len_inner = ", sig_len_inner);
    debug_print_data("sig_value = ", sig_value, sig_len);
    debug_print_int("pk_len = ", pk_len);
    debug_print_data("pk_value = ", pk_value, pk_len);
    debug_print_int("authn_len = ", authn_data_len);
    debug_print_data("authn_value = ", authn_data_value, authn_data_len);
    debug_print_int("json_len = ", json_len);
    debug_print_data("json_value = ", json_value, json_len);

    //check if value length is correct
    if (pk_idx_len != 1 || sig_len_inner != 64 || pk_len != 64) {
        debug_print("Data parsing error, please check the length of the public key index and signature.");
        return ERROR_ARGUMENTS_LEN;
    }

    //check if pk_idx is correct
    size_t device_key_list_payload_num = device_key_list_len / 22;
    if (device_key_list_payload_num > 10 || device_key_list_payload_num < 1) {
        debug_print_int("device_key_list_payload_num is not correct, device_key_list_len = ", device_key_list_len);
        return ERROR_ARGUMENTS_LEN;
    }
    //check if pk_idx is out of bound
    if(pk_idx_value > device_key_list_payload_num) {
        debug_print_int("pk_idx_value is not correct, pk_idx_value = ", pk_idx_value);
        return ERROR_ARGUMENTS_VALUE;
    }

    //sha256x5 for pubkey and compare with the pubkey` in lock_args
    uint8_t pubkey_hash[HASH_SIZE] = {0};
    sha256_many_round(pubkey_hash, pk_value, 64, 5);

    bool matched = false;
    size_t sub_alg_id;
    for (int i = 0; i < device_key_list_payload_num; i++) {
        uint8_t *payload = device_key_list + i * 22;
        ret = memcmp(pubkey_hash, payload + 12, 10);
        if (ret == 0) {
            matched = true;
            sub_alg_id = payload[1];
            debug_print("The public key is matched.");
            break;
        }
    }
    if (!matched) {
        debug_print("The public key is not matched.");
        return ERROR_SECP_PARSE_PUBKEY;
    }

    //get tx-digest from json then compare with the tx-digest calculated from transaction
    uint8_t tx_digest[HASH_SIZE] = {0};
    ret = get_tx_digest_from_json(tx_digest, json_value, json_len);
    debug_print_int("get_tx_digest_from_json ret = ", ret);
    SIMPLE_ASSERT(0);

    //compare with the tx_digest
    ret = memcmp(tx_digest, msg, msg_len);
    if (ret != 0) {
        debug_print_data("tx_digest from json parsed = ", tx_digest, HASH_SIZE);
        debug_print_data("tx_digest from transaction calculated = ", msg, HASH_SIZE);
        debug_print("tx_digest from json is not equal to tx_digest calculated");
        return ERROR_INCORRECT_DIGEST;
    }

    //calculate the sha256 of the json
    uint8_t json_hash[SHA256_HASH_SIZE] = {0};
    sha256x1(json_hash, json_value, json_len);
    //debug_print_data("json_hash = ", json_hash, SHA256_HASH_SIZE);

    //splice WebAuthn digest
    //authn_data_len + SHA256_HASH_SIZE = 37 + 32 = 69
    uint8_t webauthn_digest[WEBAUTHN_DIGEST_LEN] = {0};
    memcpy(webauthn_digest, authn_data_value, authn_data_len);
    memcpy(webauthn_digest + authn_data_len, json_hash, SHA256_HASH_SIZE);
    debug_print_data("webauthn_digest ", webauthn_digest, WEBAUTHN_DIGEST_LEN);

    /* verify signature with payload */
    return verify_signature(sig_value, 64, webauthn_digest, WEBAUTHN_DIGEST_LEN, pk_value, 64, sub_alg_id);
}
