//
// Created by peter on 23-5-17.
//


#include "inc_def.h"
#include "deps/cryptos/sha256.h"
#include "json_parser.h"
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
    debug_print_int("recover_public_key_from_sig result ", ret);
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
    debug_print_data("payload pubkey1 ", payload_pubkey1, 32);
    debug_print_data("payload pubkey2 ", payload_pubkey2, 32);
    debug_print("verify_signature_secp256r1 failed, payload pubkey not equal to lock args");
    return -1;
}


/*
 * Input parameters:
 *      message: digest of webauthn, 32 bytes;
 *      locked_bytes: signature of webauthn, 67 bytes; (length, main_alg_id, sub_alg_id, pk_idx, signature)
 *      lock_args: payload, 22 bytes; (length, main_alg_id, sub_alg_id, cid`, pk`)
 *


 */
int verify_signature(uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args, size_t message_len) {
    int ret = CKB_SUCCESS;

    int sub_alg_id = lock_bytes[3];
    debug_print_int("sub_alg_id = ", sub_alg_id);
    switch (sub_alg_id) {
        case Secp256r1:{
                ret = verify_signature_secp256r1(message, lock_bytes + 6, lock_args);
            break;
        }
        default: {
            debug_print("wrong value in sub alg id");
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

    //lock_bytes contains 3 parts, signature, authenticator_hash, json
    //offsets are the start of every part, len is the length of every part
    int lock_bytes_len = lock_bytes[0];
    int sig_offset = 1;
    int sig_len = lock_bytes[sig_offset];
    uint8_t main_alg_id = lock_bytes[sig_offset + 1];
    uint8_t sig_sub_alg_id = lock_bytes[sig_offset + 2];
    //uint8_t pk_idx = lock_bytes[sig_offset + 3];
    //uint8_t *sig = lock_bytes + sig_offset + 4;

    int authn_hash_offset = sig_offset + sig_len + 1;
    int authn_hash_len = lock_bytes[authn_hash_offset];
    uint8_t *authn_hash = lock_bytes + authn_hash_offset + 1;

    int json_offset = authn_hash_offset + authn_hash_len + 1;
    int json_len = lock_bytes[json_offset];
    uint8_t *json = lock_bytes + json_offset + 1;


    if(lock_bytes_len != sig_len + authn_hash_len + json_len + 3){
        debug_print_int("lock_bytes_len = ", lock_bytes_len);
        debug_print_int("sig_len = ", sig_len);
        debug_print_int("authn_hash_len = ", authn_hash_len);
        debug_print_int("json_len = ", json_len);
        debug_print("lock_bytes_len not equal to sum of 3 parts");
        return -1;
    }

    //check if the main_alg_id is supported
    if (main_alg_id != 8) {
        debug_print_int("main_alg_id = ", main_alg_id);
        debug_print("main_alg_id not supported");
        return -1;
    }

    //check if the sig_sub_alg_id is supported, now only support secp256r1
    if(sig_sub_alg_id != Secp256r1){
        debug_print_int("sig_sub_alg_id = ", sig_sub_alg_id);
        debug_print("sig_sub_alg_id not supported");
        return -1;
    }

    //compare the alg_id in signature and payload,
    int pubkey_sub_alg_id = lock_args[1];

    if (sig_sub_alg_id != pubkey_sub_alg_id) {
        debug_print("sub_alg_id in sig and pk don't equal");
        debug_print_int("alg_id in sig = ", sig_sub_alg_id);
        debug_print_int("alg_id in pubkey = ", pubkey_sub_alg_id);
        return -1;
    }

    //get the tx_digest from json
    uint8_t tx_digest[BLAKE160_SIZE] = {0};
    size_t tx_digest_len = -1;

    ret = get_challenge_from_json(tx_digest, &tx_digest_len, json, json_len);
    SIMPLE_ASSERT(0);

    //convert tx_digest from base64url to bytes
    //todo

    if (tx_digest_len != BLAKE160_SIZE) {
        debug_print("digest from json is not blake160");
        return -1;
    }

    ret = memcmp(tx_digest, message, BLAKE160_SIZE);
    if(ret != 0) {
        debug_print("digest in json don't equal with digest in lock");
        debug_print_data("tx_digest in json =", tx_digest, BLAKE160_SIZE);
        debug_print_data("tx_digest in lock =", message, BLAKE160_SIZE);
        return -1;
    }

    //calculate WebAuthn digest, and cover it to message, the length of message is 32, don't exceed the range
    memset(message, 0, SHA256_HASH_SIZE);
    SHA256_CTX ctx;
    SHA256Init(&ctx);
    SHA256Update(&ctx, authn_hash, authn_hash_len);
    SHA256Update(&ctx, json, json_len);
    SHA256Final(&ctx, message);

    //sha256x1(message, lock_bytes + sig_length, json_len);
    debug_print_data("webauthn message = ", message, SHA256_HASH_SIZE);



    /* verify signature with payload */
    return verify_signature(message, lock_bytes, lock_args, SHA256_HASH_SIZE);

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

