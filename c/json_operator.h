#ifndef DAS_LOCK_JSON_PARSER_H
#define DAS_LOCK_JSON_PARSER_H
#include "utils_helper.h"
//#include <string.h>
#include "jsmn.h"
#include "inc_def.h"
#include "base64url.h"
//
#define KEYS_NUM 4
char keys[10][20]  = {"type", "challenge", "origin", "crossOrigin"};
enum key_index {
    Jtype,
    Jchallenge,
    Jorigin,
    JcrossOrigin,
};
int mystrncmp(const char *str1, const char *str2, size_t n){
    if(str1 == NULL || str2 == NULL) {
        return -1;
    }
    while(n--){
        if(*str1 != *str2) {
            return *str1 - *str2;
        }
        str1 ++;
        str2 ++;

    }
    return 0;
}

//
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        mystrncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

int parse_keys(const char* buf, jsmntok_t* tok) {
    for(int i = 0; i < KEYS_NUM; i++) {
        if (jsoneq(buf, tok, keys[i]) == 0) {
            return i;
        }
    }
    return -1;
}

int get_challenge_from_json(char* output, size_t *output_len, unsigned char* json_buf, size_t buf_len){
    debug_print("Ready to parse json.");
    debug_print_string("json string = ", json_buf, buf_len);
    //init
    int i = 0, c = 0;
    jsmn_parser p;
    jsmntok_t t[128]; // We expect no more than 128 tokens in one json

    jsmn_init(&p);

    //Because of the agreement with the backend, the fixed-length witness_args.lock field is used,
    // so the length of the json data here is inconsistent with the length of the data.
    //Comment this out to avoid errors;
    /*size_t json_len = strlen((const char*)json_buf);
    if(json_len != buf_len) {
        debug_print_int("json len in witness lv = ", buf_len);
        debug_print_int("json len in strlen = ", json_len);
        debug_print("There is a null value before or after the json data");
        return ERROR_ENCODING;
    }*/


    c = jsmn_parse(&p, (const char*)json_buf, buf_len, t, sizeof(t) / sizeof(t[0]));
    if (c < 0) {
        debug_print_int("json parsing failed, the number of tokens is ", c);
        return ERROR_ENCODING;
    }

    /* Assume the top-level element is an object */
    if (c < 1 || t[0].type != JSMN_OBJECT) {
        debug_print_int("t[0].type = ", t[0].type);
        debug_print("Json object expected.");
        return ERROR_ENCODING;
    }
    int key_idx = 0;
    bool find_challenge = false;
    for(i = 1; i < c; i++){
        key_idx = parse_keys((const char*)json_buf, &t[i]);
        size_t value_length = t[i + 1].end - t[i + 1].start;
        unsigned char* value_start = json_buf + t[i + 1].start;

        switch (key_idx) {
            case Jtype: {
                //debug_print_string("json parser: Type: ", value_start, value_length);
                i++;
                break;
            }
            case Jchallenge : {
                //debug_print_string("json parser: Challenge: ", value_start, value_length);
                //if value_length > output_len, only copy output_len bytes
                //Protecting arrays from going out of bounds
                size_t cpy_len = value_length > *output_len ? *output_len : value_length;
                memcpy(output, value_start, cpy_len);
                *output_len = cpy_len;
                i++;
                find_challenge = true;
                break;
            }
            case Jorigin : {
                //debug_print_string("json parser: Origin: ", value_start, value_length);
                i++;
                break;
            }
            case JcrossOrigin : {
                //debug_print_string("json parser: CrossChain: ", value_start, value_length);
                i++;
                break;

            }
            default: {
                //debug_print_string("Unexpected json key ", json_buf + t[i].start, t[i].end - t[i].start);
                //return -1;
            }
        }
        if(find_challenge == true){
            //debug_print_data("json parser: Challenge: result ", (unsigned char*)output, *output_len);
            //debug_print_int("json parser: Challenge: result len", *output_len);
            break;
        }
    }
    return 0;
}

#endif //DAS_LOCK_JSON_PARSER_H
