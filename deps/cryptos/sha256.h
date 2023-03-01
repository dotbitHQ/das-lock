#ifndef DOGECOIN_MESSAGE_C_SHA256_H
#define DOGECOIN_MESSAGE_C_SHA256_H
#define SHA256_HASH_SIZE 32
void SHA256(unsigned char* dst, const unsigned char* src, unsigned int src_len);
void SHA256x2(unsigned char* dst, const unsigned char* src, unsigned int src_len);
#endif //DOGECOIN_MESSAGE_C_SHA256_H
