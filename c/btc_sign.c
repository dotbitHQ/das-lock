
// 1 + 25 + 1 + 32
#define MAGIC_HASH_TOTAL_MESSAGE_LEN 59
#define BTC_MASSAGE_PREFIX_LEN 25

#include "inc_def.h"
#include "sha256.h"
#include "ripemd160.h"

int magic_hash(uint8_t *hash, uint8_t *message, size_t message_len)
{
    debug_print(">>>>>>>>>>> btc magic_hash 18!!!!!");
    
    // Prevent stack overflow caused by excessively long messages.
    if (message_len > 4096)
    {
        return ERR_DAS_MESSAGE_TOO_LONG;
    }

    size_t msg_hex_len = message_len * 2;
    uint8_t msg_hex[msg_hex_len];
    bin_to_hex(msg_hex, message, message_len);

    debug_print_data("message_hex  : ", msg_hex, msg_hex_len);
    size_t total_message_len = BTC_MASSAGE_PREFIX_LEN + 1 + COMMON_PREFIX_LENGTH + msg_hex_len;
    uint8_t total_message[total_message_len];
    debug_print_int("message total len: ", total_message_len);

    // total_message = [prefix, message_with_prefix_len, COMMON_PREFIX, message_hex]
    memcpy(total_message, "\x18""Bitcoin Signed Message:\n", BTC_MASSAGE_PREFIX_LEN);
    debug_print_data("total message : after copy btc prefix : ", total_message, total_message_len);

    // add prefix and message_hex
    total_message[BTC_MASSAGE_PREFIX_LEN] = COMMON_PREFIX_LENGTH + msg_hex_len;
    memcpy(total_message + BTC_MASSAGE_PREFIX_LEN + 1, COMMON_PREFIX, COMMON_PREFIX_LENGTH);
    memcpy(total_message + BTC_MASSAGE_PREFIX_LEN + 1 + COMMON_PREFIX_LENGTH, msg_hex, msg_hex_len);
    debug_print_data("total message : after copy message : ", total_message, total_message_len);

    sha256x2(hash, total_message, total_message_len);
    debug_print_data("sha256x2 : ", hash, SHA256_HASH_SIZE);
    return 0;
}

int recover_public_key(uint8_t *pubkey, uint8_t *msg, uint8_t *sig_btc, size_t *pubkey_len)
{

    int ret = -1;

    // Create context
    secp256k1_context context;
    secp256k1_context *ctx = &context;
    uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
    ret = ckb_secp256k1_custom_verify_only_initialize(ctx, secp_data);
    SIMPLE_ASSERT(CKB_SUCCESS);

    // convert btc signature into secp256k1
    uint8_t sig_ecdsa_serialized[SIGNATURE_SIZE] = {0};
    memcpy(sig_ecdsa_serialized, sig_btc, SIGNATURE_SIZE);
    debug_print_data("convert btc into ecdsa, sig_btc : ", sig_btc, SIGNATURE_BTC_SIZE);
    debug_print_data("convert btc into ecdsa, sig_ecdsa_serialized : ", sig_ecdsa_serialized, SIGNATURE_SIZE);

    int recover_id = sig_btc[RECID_INDEX];
    if (recover_id < 0 || recover_id > 3)
    {
        return ERROR_SECP_RECOVER_ID;
    }
    debug_print_int("recover id = ", recover_id);

    // parse compact signature
    secp256k1_ecdsa_recoverable_signature sig_ecdsa;
    ret = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig_ecdsa, sig_ecdsa_serialized, recover_id);
    debug_print_data("after parse sig_ecdsa : ", sig_ecdsa.data, SIGNATURE_SIZE);
    SIMPLE_ASSERT(1);

    // recover public key
    secp256k1_pubkey pubkey_recover;
    ret = secp256k1_ecdsa_recover(ctx, &pubkey_recover, &sig_ecdsa, msg);
    debug_print_data("after recover, pubkey: ", pubkey_recover.data, ED25519_SIGNATURE_SIZE);
    SIMPLE_ASSERT(1);

    // serialize
    int compressed = sig_btc[PUBKEY_UNCOMPRESSED_SIZE];
    size_t output_len = 0;
    int flag = 0;
    if (compressed == 1)
    {
        debug_print("public key compressed");
        output_len = PUBKEY_COMPRESSED_SIZE;
        *pubkey_len = PUBKEY_COMPRESSED_SIZE;
        flag = SECP256K1_EC_COMPRESSED;
    }
    else if (compressed == 0)
    {
        debug_print("public key uncompressed");
        output_len = PUBKEY_UNCOMPRESSED_SIZE;
        *pubkey_len = PUBKEY_UNCOMPRESSED_SIZE;
        flag = SECP256K1_EC_UNCOMPRESSED;
    }
    else
    {
        debug_print_int("compressed value is wrong : ", compressed);
        return ERROR_SECP_PARSE_SIGNATURE;
    };

    ret = secp256k1_ec_pubkey_serialize(ctx, pubkey, &output_len, &pubkey_recover, flag);
    debug_print_data("after serialize pubkey :", pubkey, output_len);
    NORMAL_ASSERT(1, ERROR_SECP_RECOVER_PUBKEY);

    // destroy
    secp256k1_context_destroy(ctx);

    return 0;
}

void hash160(uint8_t *hash, uint8_t *pub_key, size_t pubkey_len)
{
    uint8_t sha256_hash[SHA256_HASH_SIZE] = {0};

    sha256x1(sha256_hash, pub_key, pubkey_len);
    debug_print_data("hash160 sha256 : ", sha256_hash, SHA256_HASH_SIZE);

    RIPEMD160(hash, sha256_hash, SHA256_HASH_SIZE);
    debug_print_data("hash160 ripemd160 :", hash, RIPEMD160_HASH_SIZE);
}

int is_array_all_zeros(const unsigned char *arr, size_t len)
{
    unsigned char result = 0;
    for (size_t i = 0; i < len; ++i)
    {
        result |= arr[i];
        if (result != 0)
        {
            return 0;
        }
    }
    return 1;
}

int verify_signature(uint8_t *message, uint8_t *lock_bytes, void *lock_args, size_t message_len)
{

    debug_print("Enter verify_signature btc");
    debug_print_data("digest : ", message, message_len);
    debug_print_data("lock_bytes : ", lock_bytes, SIGNATURE_BTC_SIZE);
    debug_print_data("lock_args : ", lock_args, RIPEMD160_HASH_SIZE);

    int ret = -1;

    ret = is_array_all_zeros(message, message_len);
    NORMAL_ASSERT(0, ERROR_INVALID_ARGS);

    ret = is_array_all_zeros(lock_bytes, SIGNATURE_BTC_SIZE);
    NORMAL_ASSERT(0, ERROR_INVALID_ARGS);

    ret = is_array_all_zeros(lock_args, RIPEMD160_HASH_SIZE);
    NORMAL_ASSERT(0, ERROR_INVALID_ARGS);
    uint8_t hash[SHA256_HASH_SIZE] = {0};
    uint8_t pub_key[PUBKEY_UNCOMPRESSED_SIZE] = {0};

    // convert message from bin to hex
    uint8_t message_hex[message_len * 2];
    bin_to_hex(message_hex, message, message_len);

    // magic hash
    magic_hash(hash, message, message_len);
    debug_print_data("magic hash: ", hash, SHA256_HASH_SIZE);

    // Recover public_key from signature(lock_bytes)
    size_t pubkey_len = 0;
    ret = recover_public_key(pub_key, hash, lock_bytes, &pubkey_len);
    debug_print_int("pubkey_len = ", pubkey_len);

    SIMPLE_ASSERT(CKB_SUCCESS);

    // note: Reuse hash memory space.
    memset(hash, 0, SHA256_HASH_SIZE);

    // Get the hash160 of the public key.
    hash160(hash, pub_key, pubkey_len);

    // Compare with payload(lock_args)
    uint8_t *payload = lock_args;

    debug_print_data("before compare pubkey_hash : ", hash, RIPEMD160_HASH_SIZE);
    debug_print_data("before compare payload     : ", payload, RIPEMD160_HASH_SIZE);
    ret = memcmp(hash, payload, RIPEMD160_HASH_SIZE);
    NORMAL_ASSERT(0, ERROR_PUBKEY_BLAKE160_HASH);

    debug_print("Leave validate btc");
    return 0;
}

/*
 * Input parameters:
 *      message: digest of tx, 32 bytes;
 *      locked_bytes: signature of btccoin, 66 bytes;
 *      lock_args: payload, 20 bytes;
 */
__attribute__((visibility("default"))) int validate(
    int type, uint8_t *message, uint8_t *lock_bytes, uint8_t *lock_args)
{

    /* verify signature with payload */
    return verify_signature(message, lock_bytes, lock_args, SHA256_HASH_SIZE);
}

__attribute__((visibility("default"))) int validate_str(int type, uint8_t *message, size_t message_len, uint8_t *lock_bytes, uint8_t *lock_args)
{

    debug_print("Enter validate_str btc ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, message_len);
    debug_print_int("message_len: ", message_len);
    debug_print_data("lock_bytes: ", lock_bytes, SIGNATURE_BTC_SIZE);
    debug_print_data("lock_args: ", lock_args, RIPEMD160_HASH_SIZE);

    /* verify signature with personal hash */
    return verify_signature(message, lock_bytes, lock_args, message_len);
}
