#ifndef SECP256R1_HELPER_H
#define SECP256R1_HELPER_H

#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"
#include "utils_helper.h"

typedef struct {
    ec_alg_type sig_algo;
    hash_alg_type hash_algo;
    ec_params ec_params;
} secp256r1_context_t;

void print_pub_key(u8* pubkey, const char* title) {
    debug_print_data(title, pubkey, 64);
}

int secp256r1_context_init(secp256r1_context_t *context) {
    context->sig_algo = ECDSA;
    context->hash_algo = SHA256;
    int ret = import_params(&context->ec_params, &secp256r1_str_params);
    return ret;
}

int secp256r1_recover_public_key_from_signature(const secp256r1_context_t *context,
                                                ec_pub_key *pub_key1,
                                                ec_pub_key *pub_key2, const u8 *sig,
                                                u8 siglen, const u8 *hash,
                                                u8 hsize) {
    return __ecdsa_public_key_from_sig(pub_key1, pub_key2, &context->ec_params,
                                       sig, siglen, hash, hsize,
                                       context->sig_algo);
}

int secp256r1_pub_key_export_to_aff_buf(const secp256r1_context_t *context,
                                        const ec_pub_key *pub_key, u8 *pub_key_buf,
                                        u8 pub_key_buf_len) {
    return ec_pub_key_export_to_aff_buf(pub_key, pub_key_buf, pub_key_buf_len);
};

/////////////////////test for verify ////////////////////////////////////////


int secp256r1_verify_signature(const secp256r1_context_t *context, const u8 *sig,
                           u8 siglen, const ec_pub_key *pub_key, const u8 *m,
                           u32 mlen) {
    int ret;
    ret = ec_verify(sig, siglen, pub_key, m, mlen, context->sig_algo,
                    context->hash_algo, NULL, 0);
    debug_print_int("signature verification result: ", ret);
    return ret;
}
//////////////////////////////////////////////////////////////////
int recover_public_key_from_sig(u8* signature, u8* message, u8 message_len, u8* pubkey1, u8* pubkey2){
    int ret;

    debug_print_data("signature ", signature, 64);
    debug_print_data("message ", message, message_len);

    //uint8_t message_hash[32] = {0};

    //sha256x1
    //sha256x1(message_hash, message, message_len);
    //memcpy(message_hash, message, 32);
    //debug_print_data("message_hash ", message_hash, 32);

    secp256r1_context_t context;
    ret = secp256r1_context_init(&context);
    debug_print_int("Context init, ret ", ret);
    SIMPLE_ASSERT(ret);
    ec_pub_key pk_1, pk_2;
    ret = secp256r1_recover_public_key_from_signature(&context, &pk_1, &pk_2, signature, 64, message, message_len);
    //ret = ecdsa_public_key_from_sig(&pk_1, &pk_2, &context.ec_params, sig_michael, 64, message_hash, 32);
    debug_print_int("Recover PK from signature, ret ", ret);
    SIMPLE_ASSERT(ret);

    //convert pubkey to vec
    ret = secp256r1_pub_key_export_to_aff_buf(&context, &pk_1, pubkey1, 64);
    debug_print_int("PK1 export to buf, ret ", ret);
    print_pub_key(pubkey1, "PK1 = ");
    SIMPLE_ASSERT(ret);

    ret = secp256r1_pub_key_export_to_aff_buf(&context, &pk_2, pubkey2, 64);
    debug_print_int("PK2 export to buf, ret ", ret);
    print_pub_key(pubkey2, "PK2 = ");
    SIMPLE_ASSERT(ret);


    return ret;
}
/////////////////////////////////////////////////////////
//int verify_test(u8* signature, u8* message, u8 message_len, u8* pubkey){
//
//    secp256r1_context_t context;
//    int ret;
//    ret = secp256r1_context_init(&context);
//    ec_pub_key pk_3;
//    ret = ec_pub_key_import_from_aff_buf(&pk_3, &context.ec_params, pubkey, 64, context.sig_algo);
//    debug_print_int("Import PK from buf, ret ", ret);
//    ret = secp256r1_verify_signature(&context, signature, 64,
//                                     &pk_3, message, message_len);
//    debug_print_int("Verify signature, ret ", ret);
//    if(ret > 100){
//        return -1;
//    }
//    return 0;
//
//}
////////////////////////////////////////////////////////
#endif //SECP256R1_HELPER_H
