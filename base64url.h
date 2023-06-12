//
// Created by peter on 23-5-12.
//

#ifndef DAS_LOCK_BASE64URL_H
#define DAS_LOCK_BASE64URL_H

#include "inc_def.h"

/* This is a public domain base64 implementation written by WEI Zhicheng. */

#define BASE64_ENCODE_OUT_SIZE(s) ((unsigned int)((((s) + 2) / 3) * 4 + 1))
#define BASE64_DECODE_OUT_SIZE(s) ((unsigned int)(((s) / 4) * 3))

#define BASE64_PAD '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST 'z'

/* BASE 64 encode table */
static const char base64en[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/',
};

/* ASCII order for BASE 64 decode, 255 in unused character */
static const unsigned char base64de[] = {
        /* nul, soh, stx, etx, eot, enq, ack, bel, */
        255, 255, 255, 255, 255, 255, 255, 255,

        /*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
        255, 255, 255, 255, 255, 255, 255, 255,

        /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
        255, 255, 255, 255, 255, 255, 255, 255,

        /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
        255, 255, 255, 255, 255, 255, 255, 255,

        /*  sp, '!', '"', '#', '$', '%', '&', ''', */
        255, 255, 255, 255, 255, 255, 255, 255,

        /* '(', ')', '*', '+', ',', '-', '.', '/', */
        255, 255, 255,  62, 255, 255, 255,  63,

        /* '0', '1', '2', '3', '4', '5', '6', '7', */
        52,  53,  54,  55,  56,  57,  58,  59,

        /* '8', '9', ':', ';', '<', '=', '>', '?', */
        60,  61, 255, 255, 255, 255, 255, 255,

        /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
        255,   0,   1,  2,   3,   4,   5,    6,

        /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
        7,   8,   9,  10,  11,  12,  13,  14,

        /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
        15,  16,  17,  18,  19,  20,  21,  22,

        /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
        23,  24,  25, 255, 255, 255, 255, 255,

        /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
        255,  26,  27,  28,  29,  30,  31,  32,

        /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
        33,  34,  35,  36,  37,  38,  39,  40,

        /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
        41,  42,  43,  44,  45,  46,  47,  48,

        /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
        49,  50,  51, 255, 255, 255, 255, 255
};

unsigned int base64_encode(char *out, const unsigned char *in, unsigned int inlen )
{
    int s;
    unsigned int i;
    unsigned int j;
    unsigned char c;
    unsigned char l;

    s = 0;
    l = 0;
    for (i = j = 0; i < inlen; i++) {
        c = in[i];

        switch (s) {
            case 0:
                s = 1;
                out[j++] = base64en[(c >> 2) & 0x3F];
                break;
            case 1:
                s = 2;
                out[j++] = base64en[((l & 0x3) << 4) | ((c >> 4) & 0xF)];
                break;
            case 2:
                s = 0;
                out[j++] = base64en[((l & 0xF) << 2) | ((c >> 6) & 0x3)];
                out[j++] = base64en[c & 0x3F];
                break;
        }
        l = c;
    }

    switch (s) {
        case 1:
            out[j++] = base64en[(l & 0x3) << 4];
            out[j++] = BASE64_PAD;
            out[j++] = BASE64_PAD;
            break;
        case 2:
            out[j++] = base64en[(l & 0xF) << 2];
            out[j++] = BASE64_PAD;
            break;
    }

    out[j] = 0;

    return j;
}
//
//unsigned int base64_decode(unsigned char *out, const char *in, unsigned int inlen)
//{
//    unsigned int i;
//    unsigned int j;
//    unsigned char c;
//
//    if (inlen & 0x3) {
//        return 0;
//    }
//
//    for (i = j = 0; i < inlen; i++) {
//        if (in[i] == BASE64_PAD) {
//            break;
//        }
//        if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST) {
//            return 0;
//        }
//
//        c = base64de[(unsigned char)in[i]];
//        if (c == 255) {
//            return 0;
//        }
//
//        switch (i & 0x3) {
//            case 0:
//                out[j] = (c << 2) & 0xFF;
//                break;
//            case 1:
//                out[j++] |= (c >> 4) & 0x3;
//                out[j] = (c & 0xF) << 4;
//                break;
//            case 2:
//                out[j++] |= (c >> 2) & 0xF;
//                out[j] = (c & 0x3) << 6;
//                break;
//            case 3:
//                out[j++] |= c;
//                break;
//        }
//    }
//
//    return j;
//}

/*
 * (+/=)   > (-_ )
 */
void base64_to_base64url( char* base64url, char* base64, int *len) {
    int i = 0;
    for(i = 0; i < *len; i++){
        if(base64[i] == '+'){
            base64url[i] = '-';
        }else if(base64[i] == '/'){
            base64url[i] = '_';
        }else if(base64[i] == '='){
            break;
        }else {
            base64url[i] = base64[i];
        }
    }
    *len = i;
}

//void base64url_to_base64(char* base64, char* base64url, int* len) {
//
//    int i = 0;
//    int quotient = *len / 4;
//    int modulus = *len % 4;
//    if(modulus != 0) {
//        quotient += 1;
//    }
//    int blank_len = quotient * 4 - *len;
//
//    memcpy(base64, base64url, *len);
//
//    //replace "-_" with "+/"
//    for(i = 0; i < *len; i++) {
//        if(base64[i] == '-'){
//            base64url[i] = '+';
//        }else if(base64[i] == '_'){
//            base64url[i] = '/';
//        }else {
//            base64url[i] = base64[i];
//        }
//    }
//
//    //add "="
//    for(i = 0; i < blank_len; i++){
//        printf("idx %d\n", *len + i);
//        base64[*len+i] = '=';
//    }
//
//    //base64[*len+i] = '\0';
//
//    *len = *len + blank_len;
//
//
//}

//
//int decode_base64url_to_string(char* str, char* base64url, int* len){
//    if(str == NULL || base64url == NULL) {
//        return -1;
//    }
//    //Manually set the limit here to 200
//    if(*len < 0 || *len > 200){
//        return -1;
//    }
//    char tmp[200];
//    int len_base64url = strlen(base64url);
//    base64url_to_base64(tmp, base64url, len_base64url);
//
//    base64_decode(str, tmp, len_base64url);
//    *len = BASE64_DECODE_OUT_SIZE(len_base64url)
//    return 0;
//}

#endif //DAS_LOCK_BASE64URL_H
