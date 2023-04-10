
#include "entry.h"

#ifdef CKB_C_STDLIB_PRINTF
#define debug_print(s)							ckb_debug(s)
#define debug_print_int(prefix, value)			debug_print_int_impl((prefix), (value))
#define debug_print_data(prefix, data, data_len)  debug_print_data_impl((prefix), (data), (data_len))

static char debug_buffer[64 * 1024];
static void debug_print_data_impl(const char *prefix,
                                  const uint8_t *data,
                                  uint32_t data_len) {
    int offset = 0;
    offset += sprintf_(debug_buffer, "%s", prefix);
    for (size_t i = 0; i < data_len; i++) {
        offset += sprintf_(debug_buffer + offset, "%02x", data[i]);
    }
    debug_buffer[offset] = '\0';
    ckb_debug(debug_buffer);
}
static void debug_print_int_impl(const char *prefix, int ret) {
    int offset = 0;
    offset += sprintf_(debug_buffer, "%s%d", prefix, ret);
    debug_buffer[offset] = '\0';
    ckb_debug(debug_buffer);
}
#else
#define debug_print(s)
#define debug_print_int(prefix, value)
#define debug_print_data(prefix, data, data_len)
#endif

int find_char(char* str, char t) {
    int i;
    int len = strlen(str);
    for(i = 0; i < len; i++) {
        if (str[i] == t) {
            return i;
        }
        i ++;
    }
    return -1;
}

char char2hex(char hexChar) {
    char tmp;

    if(hexChar<='9') {
        tmp = hexChar-'0';
    }
    else if(hexChar<='F') {
        tmp = hexChar-'7';
    }
    else {
        tmp = hexChar-'W';
    }
    return tmp;
}

int convertHexCharToInt(char c){
    int t;
    if(c>='a' && c<='f'){
        t = c-'a' + 10;
    }else if (c>='0'&&c<='9'){
        t = c-'0';
    }else{
        t = 0;
    }
    return t;
}

// big endian
int big_endian_hex_str2int(char* hex, int len) {
    int i;
    int ret = 0;
    int base = 1;
    for(i = 0; i < len; i++) {
        ret = ret + (uint8_t)(hex[i]) * base;
        base = base * 256;
    }
    return ret;
}

int hex2str(const char* _hexStr, unsigned char* _str) {
    int i;
    int len;
    unsigned char* ptr;
    if(NULL == _str || NULL == _hexStr)
    {
        return -1;
    }

    len = strlen(_hexStr);
    ptr = _str;

    for(i=0; i<len-1;i++) {
        *ptr = char2hex(_hexStr[i])*16;
        i++;
        *ptr += char2hex(_hexStr[i]);
        ptr++;
    }
    //return strlen(_str);
    return 0;
}

unsigned char* int2str(int num, unsigned char *str) {
    int i = 0;
    if (num<0) {
        num = -num;
        str[i++] = '-';
    }
    do {
        str[i++] = num%10+48;
        num /= 10;
    } while(num);

    str[i] = '\0';

    int j = 0;
    if(str[0]=='-') {
        j = 1;
        ++i;
    }
    for(;j<i/2;j++) {
        str[j] = str[j] + str[i-1-j];
		str[i-1-j] = str[j] - str[i-1-j];
		str[j] = str[j] - str[i-1-j];
	}

	return str;
}

const char HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void bytes2str(uint8_t *dest, uint8_t *source, size_t len) {
    for (int i = 0; i < len; i++) {
        dest[i * 2] = HEX_TABLE[source[i] >> 4];
        dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
    }
    return;
}
struct NetworkPrefix {
    char* prefix_str;
    uint8_t prefix_len;
};

typedef enum {
    ETH,
    TRON,
    ED25519,
    DOGE
} BlockchainType;



struct NetworkPrefix get_network_prefix(BlockchainType blockchain){
    struct NetworkPrefix np;

    switch (blockchain) {
        case ETH:
            np.prefix_str = "Ethereum Signed Message:\n";
            np.prefix_len = 25;
            break;
        case TRON:
            np.prefix_str = "TRON Signed Message:\n";
            np.prefix_len = 21;
            break;
        case ED25519:
            np.prefix_str = "Ed25519 Signed Message:\n";
            np.prefix_len = 24;
            break;
        case DOGE:
            np.prefix_str = "Dogecoin Signed Message:\n";
            np.prefix_len = 25;
            break;
    }
    return np;
}



//外部的内存开辟的大一些   3 + Common_len(11) + message_len * 2
int add_prefix_to_message(uint8_t *message_with_prefix,  uint8_t *message_with_prefix_len,
                          uint8_t *message, uint8_t message_len, int network_type){
    if(message_with_prefix == NULL || message == NULL){
        return -1;
    }
    if(message_len > 120){
        return -2;
    }
    struct NetworkPrefix np = get_network_prefix(network_type);

    size_t idx = 0;
    message_with_prefix[idx] = np.prefix_len;

    idx += 1;
    memcpy(message_with_prefix + idx, np.prefix_str, np.prefix_len);
    debug_print_data("mes_with_pre: copy spec prefix: ", message_with_prefix, *message_with_prefix_len);

    uint8_t len_str[10];
    int2str(message_len * 2 + COMMON_PREFIX_LENGTH, len_str);
    size_t len_str_len = strlen((const char*)len_str);

    idx += np.prefix_len;
    memcpy(message_with_prefix + idx, len_str, len_str_len);
    debug_print_data("mes_with_pre: copy lenstr : ", message_with_prefix, *message_with_prefix_len);


    idx += len_str_len;
    memcpy(message_with_prefix + idx, COMMON_PREFIX, COMMON_PREFIX_LENGTH);
    debug_print_data("mes_with_pre: copy comm prefix: ", message_with_prefix, *message_with_prefix_len);


    idx += COMMON_PREFIX_LENGTH;
    bytes2str(message_with_prefix + idx, message, message_len);
    debug_print_data("mes_with_pre: copy message: ", message_with_prefix, *message_with_prefix_len);


    idx += message_len * 2;
    *message_with_prefix_len = idx;
    return  0;
}
















