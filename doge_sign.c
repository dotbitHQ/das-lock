
//1 + 25 + 1 + 32
#define MAGIC_HASH_TOTAL_MESSAGE_LEN 59
#define DOGE_MASSAGE_PREFIX_LEN  25

#include "inc_def.h"
#include "deps/cryptos/sha256.h"
#include "deps/cryptos/ripemd160.h"
//#include "deps/secp256k1/include/secp256k1.h"
//#include "deps/secp256k1/include/secp256k1_recovery.h"

//
const char doge_massage_prefix[25] = {
        68, 111, 103, 101, 99, 111, 105, 110, 32, 83, 105, 103, 110, 101, 100, 32, 77, 101, 115, 115, 97, 103, 101, 58, 10
};

int magic_hash(uint8_t* hash, uint8_t* message, uint8_t message_len) {
    int ret = -11;
    uint8_t message_vi_len = 0;
    if (message_len < 65536 && message_len > 255) {
        message_vi_len = 2;
    }else if (message_len < 256) {
        message_vi_len = 1;
    }else {

        SIMPLE_ASSERT(0);
    }

    uint8_t total_message_len = 1 + DOGE_MASSAGE_PREFIX_LEN + message_vi_len + message_len;
    uint8_t total_message[total_message_len];

    //total_message = [prefix_len, prefix, message_len, message]
    total_message[0] = DOGE_MASSAGE_PREFIX_LEN;
    memcpy(total_message + 1, doge_massage_prefix, DOGE_MASSAGE_PREFIX_LEN);

    total_message[DOGE_MASSAGE_PREFIX_LEN + 1] = message_len;
    memcpy(total_message + 1 + DOGE_MASSAGE_PREFIX_LEN + message_vi_len, message, message_len);

    debug_print_data("total message : ", total_message, total_message_len);

    uint8_t first_round[32] = {0};
    uint8_t second_round[32] = {0};

    SHA256(first_round, total_message, total_message_len);
    debug_print_data("sha256 first round : ", first_round, SHA256_HASH_SIZE);
    

    SHA256(second_round, first_round, SHA256_HASH_SIZE);
    debug_print_data("sha256 second round : ", second_round, SHA256_HASH_SIZE);

    SHA256x2(hash, total_message, total_message_len);
    debug_print_data("sha256x2 : ", hash, SHA256_HASH_SIZE);
    return 0;
}

// void convert_doge_sig_into_secp_recoverable(uint8_t* secp_recover_sig, uint8_t* doge_sig){
//     int i;

//     for (i = 0; i < SIGNATURE_SIZE; i++){
//         secp_recover_sig[i] = doge_sig[i];
//     }
//    // secp_recover_sig[i] = doge_sig[0];
// }
int recover_public_key(uint8_t *public_key, uint8_t* hash, uint8_t* sig_doge, size_t* pubkey_len){

    int ret = 0;

    // create ctx
    //secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context context;
    secp256k1_context* ctx = &context;
    uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
    ret = ckb_secp256k1_custom_verify_only_initialize(ctx, secp_data);
    SIMPLE_ASSERT(CKB_SUCCESS);

    // convert doge signature into secp256k1
    uint8_t sig_secp_serialized[SIGNATURE_SIZE] = {0};
    //convert_doge_sig_into_secp_recoverable(sig_doge, sig_secp_serialized);
    memcpy(sig_secp_serialized, sig_doge, SIGNATURE_SIZE);
    debug_print_data("convert doge into secp, sig_doge : ", sig_doge, SIGNATURE_SIZE);

    int recid = sig_doge[64];
    if(recid < 0 || recid > 3){
        return ERROR_SECP_RECOVER_ID;
    }
    debug_print_int("recover id = ", recid);

    // parse compact signature
    secp256k1_ecdsa_recoverable_signature sig_secp;
    ret = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig_secp, sig_secp_serialized, recid);
    debug_print_data("after parse sig_secp : ", sig_secp.data, SIGNATURE_SIZE);
    SIMPLE_ASSERT(1);

    // recover
    secp256k1_pubkey pubkey_recover;
    ret = secp256k1_ecdsa_recover(ctx, &pubkey_recover, &sig_secp, hash);
    debug_print_data("after recover, pubkey: ", pubkey_recover.data, ED25519_SIGNATURE_SIZE);
    SIMPLE_ASSERT(1);

    // serialize
    int compressed = sig_doge[65];
    size_t output_len = 0;
    int flag = 0;
    if(compressed == 1) {
        debug_print("compressed");
        output_len = PUBKEY_COMPRESSED_SIZE;
        *pubkey_len = PUBKEY_COMPRESSED_SIZE;
        flag = SECP256K1_EC_COMPRESSED;
    } else {
        debug_print("uncompressed");
        output_len = PUBKEY_UNCOMPRESSED_SIZE;
        *pubkey_len = PUBKEY_UNCOMPRESSED_SIZE;
        flag = SECP256K1_EC_UNCOMPRESSED;

    };

    ret = secp256k1_ec_pubkey_serialize(ctx, public_key, &output_len, &pubkey_recover, flag);
    debug_print_data("after serialize pubkey :", public_key, output_len);

    if(ret != 1) {
        return ERROR_SECP_RECOVER_PUBKEY;
    }

    // destroy
    secp256k1_context_destroy(ctx);

    return 0;
}

void hash160(uint8_t* hash, uint8_t* pub_key, size_t pubkey_len){
    uint8_t sha256_hash[SHA256_HASH_SIZE] = {0};

    SHA256(sha256_hash, pub_key, pubkey_len);
    debug_print_data("hash160 sha256 : ", sha256_hash, SHA256_HASH_SIZE);

    RIPEMD160(hash, sha256_hash, SHA256_HASH_SIZE);
    debug_print_data("hash160 ripemd160 :", hash, RIPEMD160_HASH_SIZE);
}

int verify_signature(uint8_t* message, uint8_t* lock_bytes, void* lock_args, uint8_t message_len) {


    debug_print("Enter validate doge");
    debug_print_data("digest : ", message, message_len);
    debug_print_data("lock_bytes : ", lock_bytes, SIGNATURE_DOGE_SIZE);
    debug_print_data("lock_args : ", lock_args, RIPEMD160_HASH_SIZE);

    int ret = -1;

    uint8_t hash[SHA256_HASH_SIZE] = {0};
    uint8_t pub_key[PUBKEY_UNCOMPRESSED_SIZE] = {0};
    debug_print_int("doge_sign.c line:", __LINE__);

    //magic hash
    //magic_hash(hash, message);
    magic_hash(hash, message, message_len);
    debug_print_data("magic hash: ", hash, SHA256_HASH_SIZE);
    debug_print_int("doge_sign.c line:", __LINE__);

    //Recover public_key from signature(lock_bytes)
    size_t pubkey_len = 0;
    ret = recover_public_key(pub_key, hash, lock_bytes, &pubkey_len);
    debug_print_int("pubkey_len = ", pubkey_len);
    debug_print_int("doge_sign.c line:", __LINE__);
    SIMPLE_ASSERT(CKB_SUCCESS);

    //note: Reuse hash memory space.
    memset(hash, 0, SHA256_HASH_SIZE);
    debug_print_int("doge_sign.c line:", __LINE__);

    //Get the hash of the public key.
    hash160(hash, pub_key, pubkey_len);
    debug_print_int("doge_sign.c line:", __LINE__);

    //Compare with payload(lock_args)
    uint8_t* payload = lock_args;
    debug_print_int("doge_sign.c line:", __LINE__);

    debug_print_data("before compare pubkey_hash : ", hash, 20);
    debug_print_data("before compare payload     : ", payload, 20);

    ret = memcmp(hash, payload, RIPEMD160_HASH_SIZE);
    NORMAL_ASSERT(0, ERR_DAS_SIGNATURE_NOT_MATCH);

    debug_print_int("doge_sign.c line:", __LINE__);
    debug_print("Leave validate doge");
    return 0;
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
    return verify_signature(message, lock_bytes, lock_args, SHA256_HASH_SIZE);

}

__attribute__((visibility("default"))) int validate_str(int type, uint8_t* message, size_t message_len, uint8_t* lock_bytes, uint8_t* lock_args) {

    debug_print("Enter doge validate_str ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, message_len);
    debug_print_int("message_len: ", message_len);
    //debug_print_data("message: ", message, message_len);
    debug_print_data("lock_bytes: ", lock_bytes, 66);
    debug_print_data("lock_args: ", lock_args, 20);


//    uint8_t doge_prefix[50];
//    tron_prefix[0] = 0x19;
//
//    memcpy(tron_prefix + 1, "TRON Signed Message:\n32", 23);
//    SHA3_CTX sha3_ctx;
//    keccak_init(&sha3_ctx);
//    keccak_update(&sha3_ctx, tron_prefix, 24);
//    keccak_update(&sha3_ctx, message, message_len);
//    keccak_final(&sha3_ctx, message);

    /* verify signature with personal hash */
    return verify_signature(message, lock_bytes, lock_args, message_len);
}

