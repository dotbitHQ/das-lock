//
// Created by peter on 23-5-11.
//

#ifndef DAS_LOCK_JSON_PARSER_H
#define DAS_LOCK_JSON_PARSER_H
#include "utils_helper.h"
//#include <string.h>
//#include "jsmn.h"
#include "inc_def.h"
#include "base64url.h"
//
//#define KEYS_NUM 4
//char keys[10][20]  = {"type", "challenge", "origin", "crossOrigin"};
//enum key_index {
//    Jtype,
//    Jchallenge,
//    Jorigin,
//    JcrossOrigin,
//};
//int mystrncmp(const char *str1, const char *str2, size_t n){
//    if(str1 == NULL || str2 == NULL) {
//        return -1;
//    }
//    while(n--){
//        if(*str1 != *str2) {
//            return *str1 - *str2;
//        }
//        str1 ++;
//        str2 ++;
//
//    }
//    return 0;
//}

//
//static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
//    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
//        mystrncmp(json + tok->start, s, tok->end - tok->start) == 0) {
//        return 0;
//    }
//    return -1;
//}
//
//int parse_keys(const char* buf, jsmntok_t* tok) {
//    for(int i = 0; i < KEYS_NUM; i++) {
//        if (jsoneq(buf, tok, keys[i]) == 0) {
//            return i;
//        }
//    }
//    return -1;
//}

int splice_into_json(unsigned char* output, size_t* output_len, unsigned char* digest_bytes, size_t digest_len) {
    //convert digest from bytes to string
    unsigned char digest_hex[digest_len * 2]; //
    bin_to_hex(digest_hex, digest_bytes, digest_len);
    debug_print_data("digest_hex = ", digest_hex, digest_len * 2);

    //convert digest to base64url format
    int base64_len = BASE64_ENCODE_OUT_SIZE(digest_len * 2);
    debug_print_int("base64_len = ", base64_len);
    char base64[base64_len]; //fixed length, 86 bytes base64url for 32 bytes digest
    base64_encode(base64, digest_hex, digest_len * 2);
    debug_print_data("base64 = ", (unsigned char*)base64, base64_len);
    //build json
    char json_temple_buf[200] ={123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110, 46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 65, 34, 44, 34, 111, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 58, 47, 47, 108, 111, 99, 97, 108, 104, 111, 115, 116, 34, 44, 34, 99, 114, 111, 115, 115, 79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125};
    //memcpy(json_temple_buf + 36, base64url_digest, digest_len);
    base64_to_base64url(json_temple_buf + 36, base64, &base64_len);
    debug_print_data("json base64url = ", (unsigned char*)(json_temple_buf + 36), base64_len);
    debug_print_data("json temple buf = ", (unsigned char*)json_temple_buf, 200);

    //fixed length, 172 bytes json for 32 bytes digest
    memcpy(output, json_temple_buf, 172);
    *output_len = 172;

    return 0;
}
//
//int get_challenge_from_json(unsigned char* output, size_t *output_len, unsigned char* json_buf, int buf_len){
//    debug_print("start get_challenge_from_json");
//    debug_print_int("json_len = ", buf_len);
//    debug_print_data("json_buf = ", json_buf, buf_len);
//
//    //init
//    int i = 0, r = 0, ret = -1;
//    jsmn_parser p;
//    jsmntok_t t[128];
//
//    jsmn_init(&p);
//
//    size_t json_len = strlen((const char*)json_buf);
//    r = jsmn_parse(&p, (const char*)json_buf, json_len, t, sizeof(t) / sizeof(t[0]));
//    if (r < 0) {
//        debug_print_int("failed to parse JSON , ret = ", ret);
//        return -1;
//    }
//
//    /* Assume the top-level element is an object */
//    if (r < 1 || t[0].type != JSMN_OBJECT) {
//        debug_print_int("t[0].type = ", t[0].type);
//        debug_print("Json object expected");
//        return -1;
//    }
//    int key_idx = 0;
//    for(i = 1; i < r; i++){
//        key_idx = parse_keys((const char*)json_buf, &t[i]);
//        size_t value_length = t[i + 1].end - t[i + 1].start;
//        unsigned char* value_start = json_buf + t[i + 1].start;
//
//        switch (key_idx) {
//            case Jtype: {
//                debug_print_data("json parser: Type: ", value_start, value_length);
//                i++;
//                break;
//            }
//            case Jchallenge : {
//                debug_print_data("json parser: Challenge: ", value_start, value_length);
//                if (*output_len > value_length) {
//                    memcpy(output, value_start, value_length);
//                    *output_len = value_length;
//                }else {
//                    ret = -1;
//                }
//                i++;
//                break;
//            }
//            case Jorigin : {
//                debug_print_data("json parser: Origin: ", value_start, value_length);
//                i++;
//                break;
//            }
//            case JcrossOrigin : {
//                debug_print_data("json parser: CrossChain: ", value_start, value_length);
//                i++;
//                break;
//
//            }
//            default: {
//                debug_print_data("parse json wrong, Unexpected key", json_buf + t[i].start, t[i].end - t[i].start);
//
//                ret = -1;
//            }
//        }
//    }
//    return ret;
//}

#endif //DAS_LOCK_JSON_PARSER_H
