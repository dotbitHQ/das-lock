#include "inc_def.h"
#include "deps/cryptos/sha256.h"
#include "json_operator.h"
#include "secp256r1_helper.h"

enum SubAlgId{
    Secp256r1 = 7,
};

int verify_signature_secp256r1(uint8_t* message, uint8_t* signature, uint8_t* lock_args){
    int ret = 0;

    //recover public key
    uint8_t pk1[64]= {0}, pk2[64] = {0};
    ret = recover_public_key_from_sig(signature, message, SHA256_HASH_SIZE, pk1, pk2);
    debug_print_int("Recover the public key from the signature, result = ", ret);
    NORMAL_ASSERT(0, ERROR_SECP_RECOVER_PUBKEY);

    //calculate public key sha256*5 and compare with payload
    //Todo: The matching here and below can be implemented with a function.
    uint8_t payload_pk[SHA256_HASH_SIZE] = {0};
    sha256_many_round(payload_pk, pk1, 64, 5);
    int cmp1 = memcmp(payload_pk, lock_args + 12, 10);
    if(cmp1 == 0) {
        debug_print("The signature is verified successfully, pk1 matches.");
        return 0;
    }
    debug_print_data("payload real pk1` ", payload_pk, 10);

    //if pubkey1 not match, try pubkey2
    //memset(payload_pk, 0, 32);
    sha256_many_round(payload_pk, pk2, 64, 5);
    int cmp2 = memcmp(payload_pk, lock_args + 12, 10);

    if(cmp2 == 0){
        debug_print("The signature is verified successfully, pk2 matches.");
        return 0;
    }

    debug_print_data("payload expected ", lock_args + 12, 10);
    debug_print_data("payload real pk2` ", payload_pk, 10);
    debug_print("Signature verification failed");
    return ERROR_SECP_VERIFICATION;
}


/*
 * Input parameters:
 *      message: digest of webauthn, 32 bytes;
 *      locked_bytes: signature of webauthn, 67 bytes; (length, main_alg_id, sub_alg_id, pk_idx, signature)
 *      lock_args: payload, 22 bytes; (length, main_alg_id, sub_alg_id, cid`, pk`)
 *
 */
int verify_signature(uint8_t* message, uint8_t* sig, uint8_t* lock_args, size_t message_len) {
    int ret = CKB_SUCCESS;

    int sub_alg_id = lock_args[1];
    debug_print_int("sub_alg_id = ", sub_alg_id);
    switch (sub_alg_id) {
        case Secp256r1:{
                ret = verify_signature_secp256r1(message, sig, lock_args);
            break;
        }
        default: {
            debug_print("wrong value in sub_alg_id");
            return -1;
        }

    }
    return ret;
}

/*
 * Input parameters:
 *      type: don't care;
 *      message: digest of transaction, 32 bytes;
 *      lock_bytes: contains 4 parts, pubkey_index, signature, authenticator_data, client_data_json
 *      lock_args: payload, 22 bytes; (main_alg_id, sub_alg_id, cid`, pk`)
 *
 */
//for lock contract use
__attribute__((visibility("default"))) int validate(
        int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args) {
    int ret = 0;

    //print some log
    debug_print("Enter validate WebAuthn ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, SHA256_HASH_SIZE);
    debug_print_data("lock_bytes[0..10] : ", lock_bytes, 10);
    debug_print_data("lock_args: ", lock_args, DAS_MAX_LOCK_ARGS_SIZE);

    //it is a variable length array, the first byte is the length of the array
    uint8_t pk_idx_offset = 0;
    uint8_t pk_idx_len = lock_bytes[pk_idx_offset];
    uint8_t pk_idx_value = lock_bytes[pk_idx_offset + 1];

    uint8_t sig_offset = pk_idx_offset + 2;
    uint8_t sig_len = lock_bytes[sig_offset];
    uint8_t *sig_value = lock_bytes + sig_offset + 1;

    uint8_t authn_data_offset = sig_offset + sig_len + 1;
    size_t authn_data_len = lock_bytes[authn_data_offset];  //authn_data length use size_t
    uint8_t *authn_data_value = lock_bytes + authn_data_offset + 1;

    uint8_t json_offset = authn_data_offset + authn_data_len + 1;
    //size_t json_len = lock_bytes[json_offset]; //json length is 2 bytes, small endian
    size_t json_len = lock_bytes[json_offset] + lock_bytes[json_offset + 1] * 256;
    uint8_t *json_value = lock_bytes + json_offset + 2;

    uint8_t main_alg_id = lock_args[0];
    uint8_t sub_alg_id = lock_args[1];


    //print some log
    debug_print_int( "pk_idx_len = ", pk_idx_len);
    debug_print_int( "pk_idx_value = ", pk_idx_value);
    debug_print_int( "sig_len = ", sig_len);
    debug_print_data("sig_value = ", sig_value, sig_len);
    debug_print_int( "authn_len = ", authn_data_len);
    debug_print_data("authn_value = ", authn_data_value, authn_data_len);
    debug_print_int( "json_len = ", json_len);
    debug_print_data("json_value = ", json_value, json_len);
    debug_print_int( "main_alg_id = ", main_alg_id);
    debug_print_int( "sub_alg_id = ", sub_alg_id);

    //check if value length is correct
    if(pk_idx_len != 1 || sig_len != 64){
        debug_print("Data parsing error, please check the length of the public key index and signature.");
        return ERROR_ARGUMENTS_LEN;
    }

    //check if pk_idx is supported, only support 0-9
    if(pk_idx_value > 9) {
        debug_print("Public key index out of range.");
        return ERROR_ARGUMENTS_VALUE;
    }

    //check if the main_alg_id is supported
    if (main_alg_id != 8) {
        debug_print_int("main_alg_id = ", main_alg_id);
        debug_print("Error flow, the main algorithm id is not 8.");
        return ERROR_ARGUMENTS_VALUE;
    }

    //check if the sig_sub_alg_id is supported, now only support secp256r1
    if(sub_alg_id != Secp256r1){
        debug_print_int("sub_alg_id = ", sub_alg_id);
        debug_print("Unsupported sub-algorithm id.");
        return ERROR_ARGUMENTS_VALUE;
    }



    //get challenge string from json that is base64url encoded
    char challenge_str[200] = {0}; //The challenge has a fixed length of 86 characters.
    size_t challenge_len = 200;
    ret = get_challenge_from_json(challenge_str, &challenge_len, json_value, json_len);
    debug_print_string("challenge_str = ", (unsigned char*)challenge_str, challenge_len);
    SIMPLE_ASSERT(0);

    //convert from base64url to string
    char tx_digest_str[100];//The tx_digest has a fixed length of 64 characters.
    ret = decode_base64url_to_string(tx_digest_str, challenge_str, &challenge_len);
    SIMPLE_ASSERT(0);

    //convert from string to bytes
    uint8_t tx_digest[HASH_SIZE] = {0};
    str2bin(tx_digest, (unsigned char*)(tx_digest_str), challenge_len);

    //compare with the tx_digest
    ret = memcmp(tx_digest, message, HASH_SIZE);
    if(ret != 0){
        debug_print_data("tx_digest from json parsed = ", tx_digest, HASH_SIZE);
        debug_print_data("tx_digest from transaction calculated = ", message, HASH_SIZE);
        debug_print("tx_digest from json is not equal to tx_digest calculated");
        return ERROR_INCORRECT_DIGEST;
    }

    //calculate the sha256 of the json
    uint8_t json_hash[SHA256_HASH_SIZE] = {0};
    sha256x1(json_hash, json_value, json_len);
    debug_print_data("json_hash = ", json_hash, SHA256_HASH_SIZE);

    //calculate WebAuthn digest
    memset(message, 0, SHA256_HASH_SIZE); //use message as temp buffer
    SHA256_CTX ctx;
    SHA256Init(&ctx);
    SHA256Update(&ctx, authn_data_value, authn_data_len);
    SHA256Update(&ctx, json_hash, SHA256_HASH_SIZE);
    SHA256Final(&ctx, message);

    //sha256x1(message, lock_bytes + sig_length, json_len);
    debug_print_data("webauthn_digest ", message, SHA256_HASH_SIZE);

    /* verify signature with payload */
    return verify_signature(message, sig_value, lock_args, SHA256_HASH_SIZE);

}

//for type contract use
__attribute__((visibility("default"))) int validate_str(int type, uint8_t* message, size_t message_len, uint8_t* lock_bytes, uint8_t* lock_args) {

    debug_print("Enter validate_str WebAuthn ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, message_len);
    debug_print_int("message_len: ", message_len);
    debug_print_data("lock_bytes: ", lock_bytes, SIGNATURE_DOGE_SIZE);
    debug_print_data("lock_args: ", lock_args, RIPEMD160_HASH_SIZE);

    /* verify signature with personal hash */
    return verify_signature(message, lock_bytes, lock_args, message_len);
}

