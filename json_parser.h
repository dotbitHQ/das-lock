//
// Created by peter on 23-5-11.
//

#ifndef DAS_LOCK_JSON_PARSER_H
#define DAS_LOCK_JSON_PARSER_H
#include "utils_helper.h"

#include "jsmn.h"
#include "inc_def.h"

#define KEYS_NUM 4
char keys[10][20]  = {"type", "challenge", "origin", "crossOrigin"};
enum key_index {
    Jtype,
    Jchallenge,
    Jorigin,
    JcrossOrigin,
};

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
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

int get_challenge_from_json(unsigned char* output, int output_len, unsigned char* json_buf, int buf_len){
    int i, j, k, r, ret = -1;
    jsmn_parser p;
    jsmntok_t t[128];

    jsmn_init(&p);

    debug_print("start parse json");
    ret = jsmn_parse(&p, json_buf, strlen(json_buf), t, sizeof(t) / sizeof(t[0]));
    debug_print_int("parse ret", r);
    if (r < 0) {
        //printf("Failed to parse JSON: %d\n", r);
        return -1;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        //printf("Object expected\n");
        return -1;
    }

    for(i = 1; i < r; i++){
        key = parse_keys(json_buf, &t[i]);
        int value_length = t[i + 1].end - t[i + 1].start;
        unsigned char* value_start = json_buf + t[i + 1].start;

        switch (key) {
            case Jtype: {
                debug_print_data("json parser: Type: ", value_start, value_length);
                i++;
                break;
            }
            case Jchallenge : {
                debug_print_data("json parser: Challenge: ", value_start, value_length);
                if (output_len > value_length) {
                    memcpy(output, value_start, value_length);
                    *output_len = value_length;
                }else {
                    ret = -1;
                }
                i++;
                break;
            }
            case Jorigin : {
                debug_print_data("json parser: Origin: ", value_start, value_length);
                i++;
                break;
            }
            case JcrossOrigin : {
                debug_print_data("json parser: CrossChain: ", value_start, value_length);
                i++;
                break;

            }
            default: {
                debug_print_data("parse json wrong, Unexpected key", json_buf + t[i].start, t[i].end - t[i].start);

                ret = -1;
            }
        }
    }
    return ret;
}

#endif //DAS_LOCK_JSON_PARSER_H