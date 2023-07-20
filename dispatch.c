
#include "inc_def.h"
#include "keylist_oprate.h"

#define JUST_FOR_TEST

int get_args(uint8_t *lock_args) {

    debug_print("Enter get_args");
    int ret = 0;

    // Load args
    uint8_t script[SCRIPT_SIZE];
    uint64_t len = SCRIPT_SIZE;
    ret = ckb_load_script(script, &len, 0);
    debug_print_int("lock script len = ", len);
    debug_print_data("lock script data = ", script, len);
    NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
    if (len > SCRIPT_SIZE) {
        return ERROR_SCRIPT_TOO_LONG;
    }

    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *) script;
    script_seg.size = len;

    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
        return ERROR_ENCODING;
    }

    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
    if (args_bytes_seg.size > DAS_ARGS_MAX_LEN) {
        return ERROR_ARGUMENTS_LEN;
    }
    debug_print_data("args: ", args_bytes_seg.ptr, args_bytes_seg.size);

    memcpy(lock_args, args_bytes_seg.ptr, args_bytes_seg.size);

    return CKB_SUCCESS;
}

int get_plain_and_cipher(uint8_t *message, uint8_t *lock_bytes, uint8_t alg_id) {

    debug_print("Enter get_plain_and_cipher");
    int ret = 0;

    /* Load witness of first input */
    uint8_t temp[TEMP_SIZE];
    uint64_t witness_len = DAS_MAX_LOCK_BYTES_SIZE;
    ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);

    if (witness_len > DAS_MAX_LOCK_BYTES_SIZE) {
        return ERROR_WITNESS_SIZE;
    }

    /* load signature */
    mol_seg_t lock_bytes_seg;
//    if(alg_id == 8) {
//        //uint64_t witness_len_temp = witness_len;
//        //note: the first 4 bytes is the length of witness
//        uint64_t witness_len_temp = big_endian_hex_str2int((char* )temp, 4); //maybe the function is small endian really
//        debug_print_int("witness_len_temp: ", witness_len_temp);
//        debug_print_int("witness_len: ", witness_len);
//        ret = extract_witness_lock(temp, witness_len_temp, &lock_bytes_seg);
//    }else{
    ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
    //}
    NORMAL_ASSERT(CKB_SUCCESS, ERROR_ENCODING);

    debug_print_int("alg_id: ", alg_id);
    if (alg_id == 5) { // eip712
        debug_print_int("lock_bytes_seg.size: ", lock_bytes_seg.size);
        if (lock_bytes_seg.size != SIGNATURE_SIZE + HASH_SIZE + CHAIN_ID_LEN) {
            return ERROR_ARGUMENTS_LEN;
        }
        memcpy(lock_bytes, lock_bytes_seg.ptr, SIGNATURE_SIZE);
        debug_print_data("lock_bytes: ", lock_bytes, SIGNATURE_SIZE);
        memcpy(message, lock_bytes_seg.ptr + SIGNATURE_SIZE, HASH_SIZE);
        debug_print_data("message: ", message, HASH_SIZE);
        return ret;
    }

    /*
       else if (alg_id == 6) {
       if (lock_bytes_seg.size != ED25519_SIGNATURE_SIZE) {
       return ERROR_ARGUMENTS_LEN;
       }
       }
       else {
       if (lock_bytes_seg.size != SIGNATURE_SIZE) {
       return ERROR_ARGUMENTS_LEN;
       }
       }
       */

    memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);


    debug_print_data("lock_bytes: ", lock_bytes, SIGNATURE_SIZE);

    // get the offset of lock_bytes for sign
    size_t multisig_script_len = 0;

    if (alg_id == 1) {
        uint8_t pubkeys_cnt = lock_bytes[3];
        multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * pubkeys_cnt;

        uint8_t threshold = lock_bytes[2];
        size_t signatures_len = SIGNATURE_SIZE * threshold;
        size_t required_lock_len = multisig_script_len + signatures_len;
        if (required_lock_len != lock_bytes_seg.size) {
            return ERROR_WITNESS_SIZE;
        }
    }

    /* Load tx hash */
    uint8_t tx_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    ret = ckb_load_tx_hash(tx_hash, &len, 0);
    SIMPLE_ASSERT(CKB_SUCCESS);

    if (len != HASH_SIZE) {
        return ERROR_SYSCALL;
    }
    debug_print_data("tx_hash: ", tx_hash, HASH_SIZE);

    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, HASH_SIZE);

    blake2b_update(&blake2b_ctx, tx_hash, HASH_SIZE);
    debug_print_data("blake2b 01 tx_hash: ", tx_hash, HASH_SIZE);

    memset((void *) lock_bytes_seg.ptr + multisig_script_len, 0, lock_bytes_seg.size);
    blake2b_update(&blake2b_ctx, (uint8_t * ) & witness_len, sizeof(uint64_t));
    debug_print_data("blake2b 02 witness_len: ", (uint8_t * ) & witness_len, sizeof(uint64_t));

    blake2b_update(&blake2b_ctx, temp, witness_len);
    debug_print_data("blake2b 03 temp: ", temp, 30);

    debug_print_int("witness_len: ", witness_len);

    // Digest same group witnesses
    size_t i = 1;
    //debug_print_int("__line__", __LINE__);

    while (1) {
        ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_GROUP_INPUT);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
        i += 1;
    }
    //debug_print_int("__line__", __LINE__);

    // Digest witnesses that not covered by inputs
    i = ckb_calculate_inputs_len();
    //debug_print_int("__line__", __LINE__);

    while (1) {
        ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_INPUT);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
        i += 1;
    }
    //debug_print_int("__line__", __LINE__);

    blake2b_final(&blake2b_ctx, message, HASH_SIZE);
    //debug_print_int("__line__", __LINE__);



    return CKB_SUCCESS;
}

int get_lock_args_index(uint8_t *temp, uint8_t len, uint8_t *index) {
    int ret = 0;
    // 0x646173
    if (len >= 3 && memcmp(temp, "das", 3) != 0) {
        return ERR_DAS_PREFIX_NOT_MATCH;
    }
    *index = temp[len - 1];
    return ret;
}

int get_action_from_witness(uint8_t *temp, uint8_t *action, uint64_t *action_len) {
    debug_print("Enter get_action_from_witness");
    int ret = CKB_SUCCESS;
    int pre_len = 19;
    int action_len_len = 4;
    char action_len_buf[action_len_len];
    memcpy(action_len_buf, temp + pre_len, action_len_len);
    //debug_print_data("action_len_buf: ", (unsigned char*)action_len_buf, action_len_len);
    *action_len = big_endian_hex_str2int(action_len_buf, action_len_len);
    memcpy(action, temp + pre_len + action_len_len, *action_len);

    //debug_print_data("action: ", action, *action_len);
    debug_print_string("action string: ", action, *action_len);
    debug_print_int("action_len: ", *action_len);
    return ret;
}

int get_self_index_in_inputs(uint64_t *index) {
    debug_print("Enter get_self_index_in_inputs");
    uint8_t current_script_hash[32];
    uint64_t len = 32;
    int ret = ckb_load_script_hash(current_script_hash, &len, 0);
    if (ret != CKB_SUCCESS) {
        debug_print("Error loading current script hash!");
        return ret;
    }
    if (len != 32) {
        debug_print("Invalid script hash length!");
        return CKB_INVALID_DATA;
    }

    uint64_t i = 0;
    while (1) {
        uint8_t buffer[32];
        len = 32;
        ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
        if (ret != CKB_SUCCESS) {
            debug_print("Error fetching output type hash to locate type id index!");
            return ret;
        }
        if (len != 32) {
            debug_print("Invalid type hash length!");
            return CKB_INVALID_DATA;
        }
        if (memcmp(buffer, current_script_hash, 32) == 0) {
            break;
        }
        i += 1;
    }
    *index = i;
    return CKB_SUCCESS;
}

int check_cmd_match(uint8_t *temp, int type) {
    debug_print("Enter check_cmd_match");
    int ret = CKB_SUCCESS;

    uint8_t action_from_wit[1000];
    size_t action_from_wit_len;
    ret = get_action_from_witness(temp, action_from_wit, &action_from_wit_len);
    SIMPLE_ASSERT(CKB_SUCCESS);
    // 0x646173
    char *skip_str[] = {
#include "skip_cmd_list.txt"
    };
    char *manager_only_str[] = {
#include "manager_only_cmd_list.txt"
    };

    uint8_t list_len0 = sizeof(skip_str) / sizeof(skip_str[0]);
    uint8_t list_len1 = sizeof(manager_only_str) / sizeof(manager_only_str[0]);
    uint8_t list_len = (type ? list_len0 : list_len1);
    for (int i = 0; i < list_len; i++) {
        char *standard_str;
        if (type == SKIP_CMD) {
            standard_str = skip_str[i];
        } else {
            standard_str = manager_only_str[i];
        }
        size_t standard_str_len = strlen(standard_str);
        //uint8_t for_cmp[standard_str_len];
        //hex2str(standard_str, for_cmp);
        //debug_print_int("standard_str_len: ", standard_str_len);
        if (standard_str_len == action_from_wit_len && memcmp(action_from_wit, standard_str, standard_str_len) == 0) {
            debug_print("match success");
            return DAS_CMD_MATCH;
        }
    }
    return DAS_CMD_NOT_MATCH;
}

int check_has_pure_type_script() {
    int ret = CKB_SUCCESS;

    //char* balance_type_id = "334540e23ec513f691cdd9490818237cbc9675861e4f19c480e0c520c715fd33";
#ifdef CKB_C_STDLIB_PRINTF
    char* balance_type_id = "4ff58f2c76b4ac26fdf675aa82541e02e4cf896279c6d6982d17b959788b2f0c";
#else
    char *balance_type_id = "ebafc1ebe95b88cac426f984ed5fce998089ecad0cd2f8b17755c9de4cb02162";
#endif
    uint8_t for_cmp[HASH_SIZE];
    hex2str(balance_type_id, for_cmp);

    int i = 0;
    while (1) {
        uint8_t buffer[100];
        uint64_t len = 100;
        ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_TYPE);
        debug_print_data("ckb_load_cell_by_field buffer = ", buffer, len);
        if (ret == CKB_ITEM_MISSING) {
            i++;
            continue;
        } else if (ret == CKB_SUCCESS) {
            uint8_t typeid[HASH_SIZE];
            memcpy(typeid, buffer + 16, HASH_SIZE);
            debug_print_data("type id: ", typeid, HASH_SIZE);
            if (memcmp(for_cmp, typeid, HASH_SIZE) == 0) {
                i++;
                continue;
            } else {
                return DAS_NOT_PURE_LOCK_CELL;
            }
        } else if (ret == CKB_INDEX_OUT_OF_BOUND) {
            return DAS_PURE_LOCK_CELL;
        } else {
            return DAS_NOT_PURE_LOCK_CELL;
        }
    }
    return ret;
}

int check_the_first_input_cell_must_be_sub_account_type_script() {
    int ret = CKB_SUCCESS;

#ifdef CKB_C_STDLIB_PRINTF
    char* sub_account_type_id = "8bb0413701cdd2e3a661cc8914e6790e16d619ce674930671e695807274bd14c";
#else
    char *sub_account_type_id = "63516de8bb518ed1225e3b63f138ccbe18e417932d240f1327c8e86ba327f4b4";
#endif
    uint8_t for_cmp[HASH_SIZE];
    hex2str(sub_account_type_id, for_cmp);

    uint8_t buffer[SCRIPT_SIZE];
    uint64_t len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(buffer, &len, 0, 0, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE);
    if (ret != CKB_SUCCESS) {
        debug_print("Error fetching output type hash to locate type id index!");
        return ret;
    }

    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *) buffer;
    script_seg.size = len;
    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
        debug_print("Error encoding");
        return ERROR_ENCODING;
    }
    mol_seg_t hash_seg = MolReader_Script_get_code_hash(&script_seg);
    debug_print_data("type's code hash: ", hash_seg.ptr, hash_seg.size);

    uint8_t typeid[HASH_SIZE];
    memcpy(typeid, hash_seg.ptr, hash_seg.size);
    debug_print_data("the first cell in inputs's type id: ", typeid, HASH_SIZE);
    if (memcmp(for_cmp, typeid, HASH_SIZE) == 0) {
        return CKB_SUCCESS;
    }

    return CKB_INVALID_DATA;
}

int check_skip_sign_for_update_sub_account(uint8_t *temp) {
    debug_print("Enter check_skip_sign_for_update_sub_account");

    int ret = CKB_SUCCESS;

    uint8_t action_from_wit[1000];
    size_t action_from_wit_len;
    ret = get_action_from_witness(temp, action_from_wit, &action_from_wit_len);
    SIMPLE_ASSERT(CKB_SUCCESS);

    debug_print_data("action_from_wit: ", action_from_wit, action_from_wit_len);
    char *standard_str = "update_sub_account";
    size_t standard_str_len = strlen(standard_str);
    if (memcmp(action_from_wit, standard_str, standard_str_len) == 0) {
        debug_print("check type contract for update_sub_account");
        ret = check_the_first_input_cell_must_be_sub_account_type_script();
        SIMPLE_ASSERT(CKB_SUCCESS);

        return DAS_SKIP_CHECK_SIGN;
    }
    return DAS_NOT_SKIP_CHECK_SIGN;
}

int check_skip_sign_for_buy_account(uint8_t *temp, uint64_t alg_id) {
    debug_print("Enter check_skip_sign_for_buy_account");
    debug_print_int("alg_id: ", alg_id);
    if (alg_id != 5) {
        return DAS_NOT_SKIP_CHECK_SIGN;
    }
    uint64_t script_index = 0xFFFFFFFFFFFFFFFF;
    int ret = get_self_index_in_inputs(&script_index);
    if (ret != CKB_SUCCESS) {
        return ret;
    }
    debug_print_int("script_index: ", script_index);
    if (script_index != 0 && script_index != 1) {
        return DAS_NOT_SKIP_CHECK_SIGN;
    }

    uint8_t action_from_wit[1000];
    size_t action_from_wit_len;
    ret = get_action_from_witness(temp, action_from_wit, &action_from_wit_len);
    SIMPLE_ASSERT(CKB_SUCCESS);

    debug_print_data("action_from_wit: ", action_from_wit, action_from_wit_len);
    char *standard_str = "buy_account";
    size_t standard_str_len = strlen(standard_str);
    if (memcmp(action_from_wit, standard_str, standard_str_len) == 0) {
        debug_print("skip check sig buy_account");
        return DAS_SKIP_CHECK_SIGN;
    }
    return DAS_NOT_SKIP_CHECK_SIGN;
}

int check_skip_sign(uint8_t *temp) {
    debug_print("Enter check_skip_sign");
    int ret = CKB_SUCCESS;
    ret = check_has_pure_type_script();
    if (ret == DAS_PURE_LOCK_CELL) {
        return DAS_NOT_SKIP_CHECK_SIGN;
    }

    ret = check_cmd_match(temp, SKIP_CMD);
    return ret == DAS_CMD_MATCH ? DAS_SKIP_CHECK_SIGN : DAS_NOT_SKIP_CHECK_SIGN;
}

int check_manager_only(uint8_t *temp) {
    debug_print("Enter check_manager_only");
    int ret = check_cmd_match(temp, MANAGER_ONLY_CMD);
    return ret;
}

int check_and_downgrade_alg_id(uint8_t *temp, uint8_t *alg_id) {
    int ret = CKB_SUCCESS;
    if (*alg_id == 5) {
        debug_print("downgrade alg_id");
        uint8_t action_from_wit[1000];
        size_t action_from_wit_len;
        ret = get_action_from_witness(temp, action_from_wit, &action_from_wit_len);
        SIMPLE_ASSERT(CKB_SUCCESS);

        debug_print_data("for downgrade, action_from_wit: ", action_from_wit, action_from_wit_len);
        char *skip_str[] = {
#include "downgrade_algorithm_id.txt"
        };
        uint8_t list_len = sizeof(skip_str) / sizeof(skip_str[0]);
        for (int i = 0; i < list_len; i++) {
            char *standard_str = skip_str[i];
            size_t standard_str_len = strlen(standard_str);
            if (standard_str_len == action_from_wit_len &&
                memcmp(action_from_wit, standard_str, standard_str_len) == 0) {
                debug_print("downgrade match success");
                debug_print("change the alg id from 5 to 3");
                *alg_id = 3;
            }
        }
    }
    return CKB_SUCCESS;
}

int get_lock_args(uint8_t *temp, uint8_t *das_args, uint8_t index, uint8_t *lock_args, uint8_t *alg_id) {
    debug_print("Enter get_lock_args");
    int ret = CKB_SUCCESS;
    size_t args1_len = BLAKE160_SIZE;
    memcpy(alg_id, das_args, 1);
    debug_print_data("das_args: ", das_args, 20);
    debug_print_int("alg_id: in func", *alg_id);
    if (*alg_id == 1) { // multi sign
        args1_len += sizeof(uint64_t);
    } else if (*alg_id == 6) { // ed25519
        args1_len = HASH_SIZE;
    } else if (*alg_id == 5) {
        check_and_downgrade_alg_id(temp, alg_id);
    } else if (*alg_id == 7) {
        args1_len = RIPEMD160_HASH_SIZE;
    } else if (*alg_id == 8) {
        args1_len = 21;
    }

    if (0 == index) { // use first args (owner lock)
        memcpy(lock_args, das_args + 1, args1_len);
        return ret;
    } else if (1 == index) { // use second args (manager lock)
        if (check_manager_only(temp) != DAS_CMD_MATCH) {
            return ERR_DAS_INVALID_PERMISSION;
        }
        size_t args2_len = BLAKE160_SIZE;
        memcpy(alg_id, das_args + 1 + args1_len, 1);
        debug_print_int("alg_id: in func manager ", *alg_id);
        if (*alg_id == 1) { // multi sign
            args2_len += sizeof(uint64_t);
        } else if (*alg_id == 6) { // ed25519
            args2_len = HASH_SIZE;
        } else if (*alg_id == 5) {
            check_and_downgrade_alg_id(temp, alg_id);
        } else if (*alg_id == 7) {
            args2_len = RIPEMD160_HASH_SIZE;
        } else if (*alg_id == 8) {
            args2_len = 21;
        }
        memcpy(lock_args, das_args + 2 + args1_len, args2_len);
        return ret;
    } else {
        debug_print("only support owner and manager");
        return ERR_DAS_INDEX_NOT_FOUND;
    }

}

int get_code_hash(uint8_t index, uint8_t *code_hash) {
    int ret = CKB_SUCCESS;
    char *code_hash_map[] = {
//#ifdef CKB_C_STDLIB_PRINTF
//#include "test2_so_list.txt"
#include "test2_so_list.txt"
//#else
//#include "mainnet_so_list.txt"
//#endif
    };
    memset(code_hash, 0, 32);
    uint8_t len = sizeof(code_hash_map) / sizeof(code_hash_map[0]);
    if (index >= len) {
        return ERR_DAS_INDEX_OUT_OF_BOUND;
    }
    if (index == 2 || index == 1) {
        return ERR_DAS_INDEX_NOT_FOUND;
    }
    hex2str(code_hash_map[index], code_hash);
    return ret;
}

//
int get_payload_from_witness(uint8_t *payload, size_t *payload_len, uint8_t *temp, size_t temp_len, uint8_t pk_idx) {
    //init
    int ret = CKB_SUCCESS;

    //Caution: if the repo das-type update, this value should update too
    uint8_t das_type_wbkl[4] = {0x0d, 0x00, 0x00, 0x00};

    //get witness
    size_t input_idx = calculate_inputs_len() + 1;
    int witness_keylist_idx = -1;

    for (size_t i = input_idx; i < 20; i++) { //Caution: maybe 20 is not enough
        memset(temp, 0, temp_len); //if optimized in the future, can remove this memset
        size_t witness_len = MAX_WITNESS_SIZE;
        ret = ckb_load_witness(temp, &witness_len, 0, i, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
            debug_print_int("read witness success, index = ", i);
            debug_print_int("witness len = ", witness_len);
            debug_print_data("witness data = ", temp, 20);
            temp_len = witness_len;
        } else {
            continue;
        }
        if ((memcmp(temp, "das", 3) == 0) &&
            (memcmp(temp + 3, das_type_wbkl, 4) == 0)) {
            witness_keylist_idx = i;
            break;
        }

    }
    if (witness_keylist_idx == -1) {
        debug_print("witness not found");
        return ERROR_WITNESS_NOT_FOUND;
    }
    //get payload by idx
    //note: +7 for jump "das" and type_id
    //ret = get_payload_by_pk_index(payload , payload_len, temp + 7, temp_len - 7, pk_idx, OLD);
    ret = get_payload_by_pk_index(payload, payload_len, temp + 7, temp_len - 7, pk_idx);

    return ret;
}

/*
 * specify lock_args and field in transaction, then search for the content
 * if there are multiple cells, return all
 */
int get_data_hash(
        uint8_t* output, size_t* output_len,
        uint8_t* temp, size_t temp_len,
        uint8_t* lock_args, size_t lock_args_len,
        int field, bool is_owner){
    int ret;
    size_t output_len_temp = 0;
    //not type_id, but type_hash
    //todo the value in testnet and mainnet is not the same
#ifdef CKB_C_STDLIB_PRINTF
    //testnet
    char* device_key_list_type_id = "9986d68bbf798e21238f8e5f58178354a8aeb7cc3f38e2abcb683e6dbb08f737";
#else
    //mainnet
    char *device_key_list_type_id = "ebafc1ebe95b88cac426f984ed5fce998089ecad0cd2f8b17755c9de4cb02162";
#endif
    uint8_t device_key_list_type_id_for_cmp[HASH_SIZE];
    hex2str(device_key_list_type_id, device_key_list_type_id_for_cmp);


    //get cell_deps len //Todo: we need a way to get len of cell_deps
    int cells_number = 10;
    if(field == CKB_SOURCE_CELL_DEP){
        cells_number = 100;
    }else if(field == CKB_SOURCE_INPUT){
        cells_number = 100;
    }

    for(int i = 0; i < cells_number; i++){
        //get type id
        temp_len = MAX_WITNESS_SIZE;
        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_TYPE);
        if(ret != 0) {
            debug_print_int("load cell failed, index = ", i);
            continue;
        }
        //get code_hash of type
        mol_seg_t type_script_seg;
        type_script_seg.ptr = (uint8_t *) temp;
        type_script_seg.size = temp_len;
        if (MolReader_Script_verify(&type_script_seg, false) != MOL_OK) {
            debug_print_int("verify type_script failed, index = ", i);
            continue;
        }
        mol_seg_t hash_seg = MolReader_Script_get_code_hash(&type_script_seg);
        debug_print_data("type's code hash: ", hash_seg.ptr, hash_seg.size);
//
//        uint8_t typeid[HASH_SIZE];
//        memcpy(typeid, hash_seg.ptr, hash_seg.size);
//        debug_print_data("the first cell in inputs's type id: ", typeid, HASH_SIZE);
        if (memcmp(device_key_list_type_id_for_cmp, hash_seg.ptr, HASH_SIZE) != 0) {
            debug_print_data("expect type_id = ", device_key_list_type_id_for_cmp, HASH_SIZE);
            debug_print_data("actual type_id = ", hash_seg.ptr, HASH_SIZE);
            debug_print_int("cell type_hash not match, index = ", i);
            continue;
        }

//        mol_seg_t code_hash_seg = MolReader_Script_get_co(&lock_script);
//        debug_print_data("args_seg.ptr = ", args_seg.ptr, args_seg.size);
//
//        mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
//
//
//        if(memcmp(temp, device_key_list_type_id_for_cmp, 32) != 0){
//            debug_print_data("expect type_id = ", device_key_list_type_id_for_cmp, 32);
//            debug_print_data("actual type_id = ", temp, 32);
//            debug_print_int("cell type_hash not match, index = ", i);
//            continue;
//        }

//        temp_len = MAX_WITNESS_SIZE;
//        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_TYPE);
//        if (ret != CKB_SUCCESS) {
//            debug_print_int("load cell.type failed, index = ", i);
//            continue;
//        }
//        debug_print_data("type script in cell = ", temp, temp_len);

        temp_len = MAX_WITNESS_SIZE;
        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_LOCK);
        if (ret != CKB_SUCCESS) {
            debug_print_int("load cell.lock failed, index = ", i);
            continue;
        }

        mol_seg_t lock_script;
        lock_script.ptr = (uint8_t *) temp;
        lock_script.size = temp_len;
        if (MolReader_Script_verify(&lock_script, false) != MOL_OK) {
            debug_print_int("verify lock_script failed, index = ", i);
            continue;
        }
        //debug_print_data("lock script in cell = ", lock_script.ptr, lock_script.size);

        mol_seg_t args_seg = MolReader_Script_get_args(&lock_script);
        //debug_print_data("args_seg.ptr = ", args_seg.ptr, args_seg.size);

        mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
        //debug_print_data("args_bytes_seg.ptr = ", args_bytes_seg.ptr, args_bytes_seg.size);

//        if (args_bytes_seg.size != lock_args_len) {
//            debug_print_data("expect lock_args = ", lock_args, lock_args_len);
//            debug_print_data("actual lock_args = ", args_bytes_seg.ptr, args_bytes_seg.size);
//            debug_print_int("args_bytes_seg.size = ", args_bytes_seg.size);
//            debug_print_int("lock_args_len = ", lock_args_len);
//            debug_print_int("lock_args size not match, index = ", i);
//            continue;
//        }
        debug_print_data("lock args in cell = ", args_bytes_seg.ptr, args_bytes_seg.size);

        //compare lock_args
        uint8_t* lock_args_temp;
        const int payload_len = 21;
        //const int das_lock_key_len = 22;
        if(is_owner) {
            lock_args_temp = args_bytes_seg.ptr + 1;
        }else {
            lock_args_temp = args_bytes_seg.ptr + 23;
        }
        ret = memcmp(lock_args_temp, lock_args, payload_len);
        if(ret != 0){
            debug_print_data("lock_args in cell_deps = ", lock_args_temp, lock_args_len);
            debug_print_data("lock_args in inputs = ", lock_args, lock_args_len);
            debug_print_int("lock_args not match, index = ", i);
            continue;
        }
        //get data_hash
        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_DATA_HASH);
        if (ret != CKB_SUCCESS) {
            debug_print_int("load cell.data_hash failed, index = ", i);
            continue;
        }
        debug_print_data("data_hash in cell = ", temp, temp_len);

        memcpy(output + output_len_temp, temp, temp_len);
        output_len_temp += temp_len;
        break;
    }


    if(output_len_temp == 0){
        debug_print("data_hash not found");
        return -2;
    }else {
        *output_len = output_len_temp;
        return CKB_SUCCESS;
    }
}

/*
 * lock_args
 * lock_args_len
 * temp
 * pk_idx
 * args_index  0: owner 1: manager
 *
 */
int get_payload_from_cell(uint8_t *lock_args, size_t *lock_args_len, uint8_t *temp, uint8_t pk_idx, uint8_t args_index){
    int ret = CKB_SUCCESS;

    bool is_owner = false;
    if(args_index == 0){ //todo maybe we need to care the value
        is_owner = true;
    }else if(args_index == 1){
        is_owner = false;
    }else {
        return ERROR_ARGUMENTS_VALUE;
    }

    uint8_t data_hashs[TEMP_SIZE];
    size_t data_hashs_len = TEMP_SIZE;

    //get data_hash from cell_deps
    ret = get_data_hash(data_hashs, &data_hashs_len, temp, TEMP_SIZE, lock_args, *lock_args_len, CKB_SOURCE_CELL_DEP, is_owner);

    if(ret == -2){
        ret = get_data_hash(data_hashs, &data_hashs_len, temp, TEMP_SIZE, lock_args, *lock_args_len, CKB_SOURCE_INPUT, is_owner);
        if (ret == -2){
            debug_print("cannot find a device key list cell that qualified");
            return -2;
        }
    }

    //Caution: if the repo das-type update, this value should update too
    uint8_t data_type_1[4] = {0x0d, 0x00, 0x00, 0x00};
    uint8_t data_type_2[4] = {0x0f, 0x00, 0x00, 0x00};

    //get witness
    size_t input_idx = calculate_inputs_len() + 1;
    int witness_keylist_idx = -1;
    size_t temp_len = TEMP_SIZE;
    size_t witness_len;

    //todo the length of witness should cal
    for (size_t i = input_idx; i < 20; i++) { //Caution: maybe 20 is not enough
        witness_len = MAX_WITNESS_SIZE;
        ret = ckb_load_witness(temp, &witness_len, 0, i, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
            debug_print_int("read witness success, index = ", i);
            debug_print_int("witness len = ", witness_len);
            debug_print_data("witness data[0..20] = ", temp, 20);
            temp_len = witness_len;
        } else {
            continue;
        }

        if (memcmp(temp, "das", 3) == 0){
            if(memcmp(temp + 3, data_type_1, 4) == 0) {
                debug_print("find a device key list cell that qualified, 0x0d");
                ret = get_payload_by_pk_index_with_hash_check_0d(lock_args, lock_args_len,temp + 7, temp_len - 7,  pk_idx, data_hashs, data_hashs_len, OLD);
                if(ret != 0){
                    debug_print("get_payload_by_pk_index_with_hash_check_0d failed");
                    continue;
                }
                witness_keylist_idx = i;
                break;
            }else if(memcmp(temp + 3, data_type_2, 4) == 0){
                debug_print("find a device key list cell that qualified, 0x0f");
                get_payload_by_pk_index_with_hash_check_0f(lock_args, lock_args_len, temp + 7, temp_len - 7, pk_idx, data_hashs, data_hashs_len);
                if(ret != 0){
                    debug_print("get_payload_by_pk_index_with_hash_check_0f failed");
                    continue;
                }
                witness_keylist_idx = i;
                break;
            }else {
                continue;
            }
        }

//        size_t lock_args_len = MAX_LOCK_ARGS_SIZE;
//        if (top == 0) {
//            get_payload_by_pk_index_with_hash_check(lock_args, &lock_args_len, temp_len, temp + 7, temp_len - 7,data_hash_cell_deps, 32, OLD);
//
//        }


    }//end for
    if (witness_keylist_idx == -1) {
        debug_print("witness not found");
        return ERROR_WITNESS_NOT_FOUND;
    }




    return ret;

}

int main() {
    int ret = CKB_SUCCESS;

    //get witness action
    uint8_t witness_action[MAX_WITNESS_SIZE];
    uint64_t witness_action_len = MAX_WITNESS_SIZE;
    size_t i = calculate_inputs_len();
    debug_print_int("calculate_inputs_len = ", i);
    ret = ckb_load_witness(witness_action, &witness_action_len, 0, i, CKB_SOURCE_INPUT);
    SIMPLE_ASSERT(CKB_SUCCESS);

    //check witness action
    ret = check_skip_sign(witness_action);
    if (ret == DAS_SKIP_CHECK_SIGN) {
        return CKB_SUCCESS;
    }
    SIMPLE_ASSERT(DAS_NOT_SKIP_CHECK_SIGN);

    //get args index
    uint8_t args_index = 0;
    ret = get_lock_args_index(witness_action, witness_action_len, &args_index);
    SIMPLE_ASSERT(CKB_SUCCESS);
    debug_print_int("args_index: ", args_index);

    //get args
    uint8_t das_args[DAS_ARGS_MAX_LEN];
    ret = get_args(das_args);
    SIMPLE_ASSERT(CKB_SUCCESS);
    debug_print("get args success");

    uint8_t lock_args[DAS_MAX_LOCK_ARGS_SIZE];
    uint8_t alg_id = -1;
    ret = get_lock_args(witness_action, das_args, args_index, lock_args, &alg_id);
    SIMPLE_ASSERT(CKB_SUCCESS);
    debug_print_data("lock_args: ", lock_args, DAS_MAX_LOCK_ARGS_SIZE);
    debug_print_int("alg_id: ", alg_id);

    ret = check_skip_sign_for_buy_account(witness_action, alg_id);
    if (ret == DAS_SKIP_CHECK_SIGN) {
        return CKB_SUCCESS;
    }
    SIMPLE_ASSERT(DAS_NOT_SKIP_CHECK_SIGN);

    ret = check_skip_sign_for_update_sub_account(witness_action);
    if (ret == DAS_SKIP_CHECK_SIGN) {
        return CKB_SUCCESS;
    }
    SIMPLE_ASSERT(DAS_NOT_SKIP_CHECK_SIGN);

    uint8_t message[HASH_SIZE] = {0};
    uint8_t lock_bytes[DAS_MAX_LOCK_BYTES_SIZE] = {0};
    ret = get_plain_and_cipher(message, lock_bytes, alg_id);
    SIMPLE_ASSERT(CKB_SUCCESS);

    debug_print_data("tx digest: ", message, HASH_SIZE);
    debug_print_int("alg_id: ", alg_id);
    if (alg_id == 8) {
        //get pubkey idx
        //Because need lock_bytes to provide pk_idx, put it here instead of the function get_lock_args
        unsigned char pk_idx = lock_bytes[1];
        debug_print_int("pk_idx = ", pk_idx);

        //255 is for the case that don't have DeviceKeyListCell, just use lock_args to verify
        if (pk_idx != 255) {
            if (pk_idx > 9) {
                debug_print_int("get pubkey index out of bound ", pk_idx);
                return ERROR_ARGUMENTS_VALUE;
            }

            //get the payload according to the public key index and store it in lock_args
            //just use witness_action as temp buffer
            //use args_index to distinguish between owner and manager
            size_t lock_args_len = DAS_MAX_LOCK_ARGS_SIZE;
            ret = get_payload_from_cell(lock_args, &lock_args_len, witness_action, pk_idx, args_index);
            debug_print("get_payload from witness");
            SIMPLE_ASSERT(0);

//            //check payload len
//            if(payload_len != 22) {
//                return ERROR_ARGUMENTS_LEN;
//            }
            debug_print_data("get payload from witness = ", lock_args, 21);
        }
    }

    uint8_t code_so[HASH_SIZE];
    ret = get_code_hash(alg_id, code_so);
    SIMPLE_ASSERT(CKB_SUCCESS);
    debug_print_data("code so: ", code_so, HASH_SIZE);

    //warning! for test modify this from 128 * 1024 to 1024 * 1024
    uint8_t code_buffer[1024 * 1024] __attribute__((aligned(RISCV_PGSIZE)));
    uint64_t consumed_size = 0;
    void *handle = NULL;
    uint8_t hash_type = 1;
    ret = ckb_dlopen2(code_so, hash_type, code_buffer, 1024 * 1024, &handle, &consumed_size);

    debug_print_int("consumed size = ", consumed_size);
    debug_print_int("ckb_dlopen2 ret = ", ret);
    SIMPLE_ASSERT(CKB_SUCCESS);
    debug_print("ckb_dlopen success");

    int (*validate_func)(int, uint8_t *, uint8_t *, uint8_t *);
    *(void **) (&validate_func) = ckb_dlsym(handle, "validate");
    if (validate_func == NULL) {
        return ERR_DAS_INVALID_POINT;
    }

    int type = 0;
    if (alg_id == 5) {
        type = 1;
    }
    return validate_func(type, message, lock_bytes, lock_args);
}
