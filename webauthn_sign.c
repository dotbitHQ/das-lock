//
// Created by peter on 23-5-17.
//


#include "inc_def.h"
#include "deps/cryptos/sha256.h"
#include "json_operator.h"
#include "secp256r1_helper.h"



enum SubAlgId{
    Secp256r1 = 7,
};



//int get_random(unsigned char *buf, u16 len) {
//    for (int i = 0; i < len; i++) {
//        buf[i] = 0;
//    }
//    return 0;
//}


int verify_signature_secp256r1(uint8_t* message, uint8_t* signature, uint8_t* lock_args){
    int ret = 0;
    //recover public key
    uint8_t pubkey1[64] = {0};
    uint8_t pubkey2[64] = {0};
    ret = recover_public_key_from_sig(signature, message, 32, pubkey1, pubkey2);
    debug_print_int("recover_public_key_from_sig result ret", ret);
    SIMPLE_ASSERT(0);

    //calculate public key sha256*5
    uint8_t payload_pubkey1[32] = {0};
    uint8_t payload_pubkey2[32] = {0};
    sha256_many_round(payload_pubkey1, pubkey1, 64, 5);
    sha256_many_round(payload_pubkey2, pubkey2, 64, 5);

    //compare is equal
    int cmp1 = memcmp(payload_pubkey1, lock_args + 12, 10);
    int cmp2 = memcmp(payload_pubkey2, lock_args + 12, 10);
    if(cmp1 == 0 || cmp2 == 0){
        return 0;
    }
    debug_print_data("payload expected ", lock_args + 12, 10);
    debug_print_data("payload real pubkey1 ", payload_pubkey1, 10);
    debug_print_data("payload real pubkey2 ", payload_pubkey2, 10);

    debug_print("verify_signature_secp256r1 failed, payload pubkey` not equal to lock args");
    return -1;
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


//for lock contract use
__attribute__((visibility("default"))) int validate(
        int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args) {
    int ret = 0;
    //print some log
    debug_print("Enter validate WebAuthn ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, SHA256_HASH_SIZE);
    debug_print_data("lock_bytes: ", lock_bytes, lock_bytes[0]);
    debug_print_data("lock_args: ", lock_args, DAS_MAX_LOCK_ARGS_SIZE);


    //test for sha256
    char *test_str = "fcb00bb8066aefc6a896e9150c822ee6669a8f0c5ce4f8f3144db21df517b9f01fba11afc017c935df72f73d6f9a00e521636409dc95361065a77aa6299ec5b5";
    uint8_t test_str_bytes[64] = {0};
    size_t input_len = 64;
    str2bin(test_str_bytes, (unsigned char*)test_str, input_len);
    debug_print_data("test_str_bytes: ", test_str_bytes, 64);

    uint8_t test_str_bytes2[SHA256_HASH_SIZE] = {0};
    sha256x1(test_str_bytes2, test_str_bytes, 64);
    debug_print_data("round 1 sha256 ", test_str_bytes2, SHA256_HASH_SIZE);
    for(int i = 0; i < 4; i++) {
        memcpy(test_str_bytes, test_str_bytes2, SHA256_HASH_SIZE);
        sha256x1(test_str_bytes2, test_str_bytes, 32);
        debug_print_int("i = ", i + 2);
        debug_print_data("sha256 ", test_str_bytes2, SHA256_HASH_SIZE);
    }
    //lock_bytes contains 4 parts, pubkey_index, signature, sha256(authenticator_data), client_data_json
    //it is a variable length array, the first byte is the length of the array
    uint8_t pk_idx_offset = 0;
    uint8_t pk_idx_len = lock_bytes[pk_idx_offset];
    uint8_t pk_idx_value = lock_bytes[pk_idx_offset + 1];

    uint8_t sig_offset = pk_idx_offset + 2;
    uint8_t sig_len = lock_bytes[sig_offset];
    uint8_t *sig_value = lock_bytes + sig_offset + 1;

    uint8_t authn_hash_offset = sig_offset + sig_len + 1;
    uint8_t authn_hash_len = lock_bytes[authn_hash_offset];
    uint8_t *authn_hash_value = lock_bytes + authn_hash_offset + 1;

    uint8_t json_offset = authn_hash_offset + authn_hash_len + 1;
    //size_t json_len = lock_bytes[json_offset]; //json length is 2 bytes
    size_t json_len = lock_bytes[json_offset] + lock_bytes[json_offset + 1] * 256;
    uint8_t *json_value = lock_bytes + json_offset + 2;

    uint8_t main_alg_id = lock_args[0];
    uint8_t sub_alg_id = lock_args[1];


    //print some log
    debug_print_int("pk_idx_len = ", pk_idx_len);
    debug_print_int("pk_idx_value = ", pk_idx_value);
    debug_print_int("sig_len = ", sig_len);
    debug_print_data("sig_value = ", sig_value, sig_len);
    debug_print_int("authn_hash_len = ", authn_hash_len);
    debug_print_data("authn_hash_value = ", authn_hash_value, authn_hash_len);
    debug_print_int("json_len = ", json_len);
    debug_print_string("json_value = ", json_value, json_len);
    debug_print_int("main_alg_id = ", main_alg_id);
    debug_print_int("sub_alg_id = ", sub_alg_id);
//    int authn_hash_offset = sig_offset + sig_len + 1;
//    int authn_hash_len = lock_bytes[authn_hash_offset];
//    uint8_t *authn_hash = lock_bytes + authn_hash_offset + 1;
//
//    int json_offset = authn_hash_offset + authn_hash_len + 1;
//    int json_len = lock_bytes[json_offset];
//    uint8_t *json = lock_bytes + json_offset + 1;

    //check if the length of lock_bytes is correct

//    if(lock_bytes[0] != pk_idx_len + sig_len + authn_hash_len + json_len + 4){
//        debug_print_int("lock_bytes_len = ", lock_bytes[0]);
//        debug_print_int("pk_idx_len = ", pk_idx_len);
//        debug_print_int("sig_len = ", sig_len);
//        debug_print_int("authn_hash_len = ", authn_hash_len);
//        debug_print_int("json_len = ", json_hash_len);
//        debug_print("The length of lock bytes is not equal to the sum of the parts.");
//        return -1;
//    }

    //check if the main_alg_id is supported
    if (main_alg_id != 8) {
        debug_print_int("main_alg_id = ", main_alg_id);
        debug_print("Error flow, the main algorithm id is not 8.");
        return -1;
    }

    //check if the sig_sub_alg_id is supported, now only support secp256r1
    if(sub_alg_id != Secp256r1){
        debug_print_int("sub_alg_id = ", sub_alg_id);
        debug_print("Unsupported subalgorithm id");
        return -1;
    }

    //get challenge from json
    char challenge_str[200] = {0};
    int challenge_len = -1;
    get_challenge_from_json(challenge_str, &challenge_len, json_value, json_len);
    debug_print_string("challenge_str = ", (unsigned char*)challenge_str, challenge_len);

    //convert from base64url to bytes
    char tx_digest_str[100];
    decode_base64url_to_string(tx_digest_str, challenge_str, &challenge_len);

    //compare with the tx_digest
    uint8_t tx_digest[HASH_SIZE] = {0};
    str2bin(tx_digest, (unsigned char*)tx_digest_str, challenge_len);

    ret = memcmp(tx_digest, message, HASH_SIZE);
    if(ret != 0){
        debug_print_data("tx_digest from json = ", tx_digest, HASH_SIZE);
        debug_print_data("tx_digest from message = ", message, HASH_SIZE);
        debug_print("tx_digest from json is not equal to tx_digest from message");
        return -1;
    }

    //calculate the sha256 of the json
    uint8_t json_hash_tmp[SHA256_HASH_SIZE] = {0};
    sha256x1(json_hash_tmp, json_value, json_len);
    debug_print_data("json_hash_tmp = ", json_hash_tmp, SHA256_HASH_SIZE);

    //calculate WebAuthn digest
    memset(message, 0, SHA256_HASH_SIZE); //use message as temp buffer
    SHA256_CTX ctx;
    SHA256Init(&ctx);
    SHA256Update(&ctx, authn_hash_value, authn_hash_len);
    SHA256Update(&ctx, json_hash_tmp, SHA256_HASH_SIZE);
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

