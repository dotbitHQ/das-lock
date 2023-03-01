
//1 + 25 + 1 + 32
#define MAGIC_HASH_TOTAL_MESSAGE_LEN 59
#define DOGE_MASSAGE_PREFIX_LEN  25

#include "inc_def.h"
#include "deps/cryptos/sha256.h"
#include "deps/cryptos/ripemd160.h"
#include "deps/secp256k1/include/secp256k1.h"
#include "deps/secp256k1/include/secp256k1_recovery.h"

const char doge_massage_prefix[25] = {
        68, 111, 103, 101, 99, 111, 105, 110, 32, 83, 105, 103, 110, 101, 100, 32, 77, 101, 115, 115, 97, 103, 101, 58, 10
};


void magic_hash(uint8_t* hash, const uint8_t* message) {
    uint8_t total_message[MAGIC_HASH_TOTAL_MESSAGE_LEN] = {0};

    //total_message = [prefix_len, prefix, message_len, message]
    total_message[0] = DOGE_MASSAGE_PREFIX_LEN;
    memcpy(total_message + 1, doge_massage_prefix, DOGE_MASSAGE_PREFIX_LEN);

    total_message[DOGE_MASSAGE_PREFIX_LEN + 1] = HASH_SIZE;
    memcpy(total_message + DOGE_MASSAGE_PREFIX_LEN + 2, message, HASH_SIZE);
    debug_print_data("total message : ", total_message, MAGIC_HASH_TOTAL_MESSAGE_LEN);

    SHA256x2(hash, message, HASH_SIZE);
    debug_print_data("sha256x2 : ", hash, SHA256_HASH_SIZE);
}

void convert_doge_sig_into_secp_recoverable(uint8_t* secp_recover_sig, uint8_t* doge_sig){
    int i;

    for (i = 0; i < SIGNATURE_SIZE - 1; i++){
        secp_recover_sig[i] = doge_sig[i + 1];
    }
    secp_recover_sig[i] = doge_sig[0];
}
int recover_public_key(uint8_t *public_key, uint8_t* hash, uint8_t* sig_doge){

    int ret = 0;
    secp256k1_pubkey pubkey_recover;
    secp256k1_ecdsa_recoverable_signature sig_secp;
    int recid = 0;
    uint8_t sig_secp_serialized[SIGNATURE_SIZE] = {0};
    // create ctx
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    // convert doge signature into secp256k1
    convert_doge_sig_into_secp_recoverable(sig_doge, sig_secp_serialized);
    debug_print_data("convert doge into secp, sig_doge : ", sig_doge, SIGNATURE_SIZE);

    recid = sig_doge[0];
    if(recid < 0 || recid > 3){
        return ERROR_SECP_RECOVER_ID;
    }

    // parse compact signature
    ret = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig_secp, sig_secp_serialized, recid);
    debug_print_data("after parse sig_secp : ", sig_secp.data, SIGNATURE_SIZE);
    SIMPLE_ASSERT(1);

    // recover
    ret = secp256k1_ecdsa_recover(ctx, &pubkey_recover, &sig_secp, hash);
    debug_print_data("after recover, pubkey: ", pubkey_recover.data, ED25519_SIGNATURE_SIZE);

    SIMPLE_ASSERT(1);

    // serialize
    size_t output_len = PUBKEY_SIZE;
    ret = secp256k1_ec_pubkey_serialize(ctx, public_key, &output_len, &pubkey_recover, SECP256K1_EC_COMPRESSED);
    debug_print_data("after serialize pubkey :", public_key, PUBKEY_SIZE);
    if(output_len != PUBKEY_SIZE || ret != 1) {
        return ERROR_SECP_RECOVER_PUBKEY;
    }

    // destroy
    secp256k1_context_destroy(ctx);

    return 0;
}

void hash160(uint8_t* hash, const uint8_t* pub_key){
    uint8_t sha256_hash[SHA256_HASH_SIZE] = {0};

    SHA256(sha256_hash, pub_key, PUBKEY_SIZE);
    debug_print_data("hash160 sha256 : ", sha256_hash, SHA256_HASH_SIZE);

    RIPEMD160(hash, sha256_hash, SHA256_HASH_SIZE);
    debug_print_data("hash160 ripemd160 :", hash, RIPEMD160_HASH_SIZE);
}

int verify_signature(uint8_t* message, uint8_t* lock_bytes, void* lock_args) {

    debug_print("Enter validate doge");
    debug_print_data("digest : ", message, HASH_SIZE);
    debug_print_data("lock_bytes : ", lock_bytes, SIGNATURE_SIZE);
    debug_print_data("lock_args : ", lock_args, RIPEMD160_HASH_SIZE);

    int ret = -1;
    int i = 0;
    uint8_t hash[SHA256_HASH_SIZE] = {0};
    uint8_t pub_key[PUBKEY_SIZE] = {0};
    debug_print_int("doge_sign.c line:", __LINE__);
    //magic hash
    magic_hash(hash, message);
    debug_print_data("magic hash: ", hash, SHA256_HASH_SIZE);
    debug_print_int("doge_sign.c line:", __LINE__);

    //recover public_key from signatures(lock_bytes)
    ret = recover_public_key(pub_key, hash, lock_bytes);
    debug_print_int("doge_sign.c line:", __LINE__);
    SIMPLE_ASSERT(CKB_SUCCESS);

    //note: Reuse hash memory space.
    memset(hash, 0, SHA256_HASH_SIZE);
    debug_print_int("doge_sign.c line:", __LINE__);

    //Get the hash of the public key.
    hash160(hash, pub_key);
    debug_print_int("doge_sign.c line:", __LINE__);

    //compare with payload(lock_args)
    uint8_t* payload = lock_args;
    debug_print_int("doge_sign.c line:", __LINE__);

    for(i = 0; i < RIPEMD160_HASH_SIZE; i++){
        if(hash[i] != payload[i]){
            debug_print_int("pub_key_hash != payload, i = ", i);
            debug_print_data("public_key_hash : ", hash, SHA256_HASH_SIZE);
            debug_print_data("payload : ", payload, RIPEMD160_HASH_SIZE);
            ret = ERR_DAS_SIGNATURE_NOT_MATCH;
            break;
        }
    }
    debug_print_int("doge_sign.c line:", __LINE__);

    return ret;
}

/*
 * Input parameters:
 *      message: digest of tx, 32 bytes;
 *      locked_bytes: signature of dogecoin, 65 bytes;
 *      lock_args: payload, 20 bytes;
 */
__attribute__((visibility("default"))) int validate(
        int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args) {

    /* verify signature with payload */
    return verify_signature(message, lock_bytes, lock_args);

}