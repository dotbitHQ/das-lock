//
// Created by peter on 23-5-17.
//


#include "inc_def.h"
#include "deps/cryptos/sha256.h"
#include "json_parser.h"
//#include "keylist.h"

enum SubAlgId{
    EmptyFlag,
    Secp256r1,

};


int verify_signature_secp256r1(uint8_t* message, uint8_t* signature, uint8_t* lock_args){
    //recover public key

    //calculate public key sha256*5

    //compare is equal
    return 0;
}


/*
 * Input parameters:
 *      message: digest of tx, 32 bytes;
 *      locked_bytes: signature of dogecoin, 66 bytes;
 *      lock_args: payload, 20 bytes;
 */
int verify_signature(uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args, size_t message_len) {
    int sub_alg_id = lock_bytes[1];
    int ret = CKB_SUCCESS;
    switch (sub_alg_id) {
        case Secp256r1:{
                ret = verify_signature_secp256r1(message, lock_bytes + 2, lock_args + 1);
            break;
        }
        case EmptyFlag:{
            debug_print("empty flag in sub alg id");
                return -1;
        }
        default: {
            debug_print("wrong value; in sub alg id");
            return -1;
        }

    }
    return ret;
}


//for lock contract use
__attribute__((visibility("default"))) int validate(
        int type, uint8_t* message, uint8_t* lock_bytes, uint8_t* lock_args) {
    int ret = 0;
    //打印一堆调试日志
    debug_print("Enter validate WebAuthn ");
    debug_print_int("type: ", type);
    debug_print_data("message: ", message, SHA256_HASH_SIZE);
    debug_print_data("lock_bytes: ", lock_bytes, lock_bytes[0]);
    debug_print_data("lock_args: ", lock_args, DAS_MAX_LOCK_ARGS_SIZE);

    //比对签名的算法 id 和 payload 的算法id ，是否一致，不一致报错退出；
    int sig_alg_id, sig_length, pubkey_alg_id;
    sig_length = lock_bytes[0]; //1 + 1 + 64
    sig_alg_id = lock_bytes[1];
    pubkey_alg_id = lock_args[0];

    if (sig_alg_id != pubkey_alg_id) {
        debug_print("alg_id in sig and public key don't equal");
        debug_print_int("alg_id in sig", sig_alg_id);
        debug_print_int("alg_id in pubkey", pubkey_alg_id);
        return -1;
    }
    //判断message, lock_bytes, lock_args 是否存在全0，如果有，退出


    //解析 lock_bytes ， witness_args.lock 的结构，从中拿出来签名和 hash 和 json 数据
    uint8_t tx_digest[BLAKE160_SIZE] = {0};
    size_t tx_digest_len = BLAKE160_SIZE;
    int json_len = lock_bytes[sig_length];

    //比对 json 里的 tx digest 和这里的 message 是否一致，如果不一致报错退出
    ret = get_challenge_from_json(tx_digest, &tx_digest_len, lock_bytes + sig_length + 1, json_len);
    SIMPLE_ASSERT(0);
    if (tx_digest_len != BLAKE160_SIZE) {
        debug_print("digest from json is not blake160");
        return -1;
    }

    ret = memcmp(tx_digest, message, BLAKE160_SIZE);
    if(ret != 0) {
        debug_print("digest in json and lock don't equal");
        debug_print_data("tx_digest in json =", tx_digest, BLAKE160_SIZE);
        debug_print_data("tx_digest in lock =", message, BLAKE160_SIZE);
        return -1;
    }

    //计算 webAuthn digest， 覆盖到 message 里，注意 message 的长度是32，不要超出范围
    SHA256(message, lock_bytes + sig_length, json_len);

    //调用验证函数，
        //lock bytes 存放签名 （长度，子算法id， 签名内容）
        //message 存放 webAuthn 的 digest，
        //lock_args 存放 公钥 （子算法id， cid`， pubkey`）


    /* verify signature with payload */
    //这里可以仿照 libecc 的方式，创建一个结构体，在这里给一个统一的函数指针的方式
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

