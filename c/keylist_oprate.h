#ifndef DAS_LOCK_KEYLIST_OPRATE_H
#define DAS_LOCK_KEYLIST_OPRATE_H

#include "inc_def.h"
#include "keylist.h"

enum MolTableData {
    DEP,
    OLD,
    NEW,
};

void print_mol_seg_t(mol_seg_t mol, const char *title) {
    debug_print_data(title, mol.ptr, mol.size);
}

//get DeviceKey by idx
//int get_payload_by_pk_index(uint8_t* out_data, size_t* out_data_len, uint8_t* in_data, size_t in_len,  int pk_idx, enum MolTableData m) {
int get_payload_by_pk_index(uint8_t *out_data, size_t *out_data_len, uint8_t *in_data, size_t in_len, int pk_idx) {
    mol_seg_t in_seg;
    in_seg.ptr = in_data;
    in_seg.size = in_len;

    //print log
    debug_print_int("get_payload pk_idx = ", pk_idx);
    //debug_print_int("get_payload MolTableData = ", m);
    debug_print_int("get_payload in_len = ", in_len);
    debug_print_data("get_payload in_buf = ", in_data, in_len);

    //init
    //int ret = 0;
    mol_seg_t mol = {0};

    //verify Data
    if (MolReader_Data_verify(&in_seg, false) != MOL_OK) {
        debug_print("cannot verify data mol reader\n");
        return ERROR_MOLECULE_ENCODING;
    } else {
        debug_print("verify data mol reader Success\n");
    }


    //try to get Dep first, if it fails then try to get Old, if it fails again return an error
    mol = MolReader_Data_get_dep(&in_seg);
    bool isnone = MolReader_DataEntityOpt_is_none(&mol);
    if (isnone) {
        debug_print("DataEntityOpt is none, MolTableData=DEP");
        mol = MolReader_Data_get_old(&in_seg);
        isnone = MolReader_DataEntityOpt_is_none(&mol);
        if (isnone) {
            debug_print("DataEntityOpt is none, MolTableData=OLD");
            return ERROR_MOLECULE_ENCODING;
        }
        debug_print("DataEntityOpt OLD is not none");
    } else {
        debug_print("DataEntityOpt DEP is not none");
    }

    //get entity
    mol_seg_t entity;
    entity = MolReader_DataEntity_get_entity(&mol);
    print_mol_seg_t(entity, "DataEntity.entity  ");


    //get Bytes
    mol_seg_t bytes_device_key_list_cell;
    bytes_device_key_list_cell = MolReader_Bytes_raw_bytes(&entity);
    print_mol_seg_t(bytes_device_key_list_cell, "bytes_device_key_list_cell ");

    //get DeviceKeyListCellData
    mol_seg_t keys;
    keys = MolReader_DeviceKeyListCellData_get_keys(&bytes_device_key_list_cell);

    //get key_list_len
    int key_list_len = MolReader_DeviceKeyList_length(&keys);
    debug_print_int("key_list_len ", key_list_len);

    //check pk_idx
    if (pk_idx < 0 || pk_idx >= key_list_len) {
        debug_print("choose public key out of bound");
        debug_print_int("choosed index = ", pk_idx);
        debug_print_int("key_list_len = ", key_list_len);
        return ERROR_MOLECULE_ENCODING;
    }

    //get key by pk_idx
    mol_seg_res_t key;
    key = MolReader_DeviceKeyList_get(&keys, pk_idx);
    if (key.errno != MOL_OK) {
        debug_print_int("MolReader_DeviceKeyList_get error ", key.errno);
        return ERROR_MOLECULE_ENCODING;
    }

    mol = key.seg;
    debug_print_int("key.size ", mol.size);
    //debug_print_data("key.content ", mol.ptr, mol.size);

    //copy data
    //int cpy_len = mol.size > DAS_MAX_LOCK_ARGS_SIZE ? DAS_MAX_LOCK_ARGS_SIZE : mol.size;
    if (mol.size != 22) {
        return ERROR_MOLECULE_ENCODING;
    }
    memcpy(out_data, mol.ptr + 1, 21);
    debug_print_data("get payload = ", out_data, 21);

    //return
    *out_data_len = 21;
    return 0;
}


void blak2b_hash(uint8_t *out, uint8_t *in, size_t in_len) {
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, in, in_len);
    blake2b_final(&blake2b_ctx, out, BLAKE2B_BLOCK_SIZE);
}

int get_payload_from_molecule_entity_data(uint8_t *out_data, size_t *out_data_len,
                                               uint8_t *in_data, size_t in_len, int pk_idx, uint8_t *hash,
                                               size_t hash_len, enum MolTableData m) {

    mol_seg_t in_seg;
    in_seg.ptr = in_data;
    in_seg.size = in_len;

    //init
    mol_seg_t mol = {0};

    //verify Data
    if (MolReader_Data_verify(&in_seg, false) != MOL_OK) {
        debug_print("Validation data Data failed");
        return ERROR_MOLECULE_ENCODING;
    }

    //get Data
    switch (m) {
        case DEP : {
            mol = MolReader_Data_get_dep(&in_seg);
            print_mol_seg_t(mol, "dep ");
            break;
        }
        case OLD : {
            mol = MolReader_Data_get_old(&in_seg);
            print_mol_seg_t(mol, "old ");
            break;
        }
        case NEW : {
            mol = MolReader_Data_get_new(&in_seg);
            print_mol_seg_t(mol, "new ");
            break;
        }
        default: {
            debug_print("MolTableData error");
            return ERROR_MOLECULE_ENCODING;
        }
    }

    //check DataEntityOpt
    bool isnone = MolReader_DataEntityOpt_is_none(&mol);
    if (isnone) {
        debug_print("DataEntityOpt is none");
        return ERROR_MOLECULE_ENCODING;
    }

    //get entity
    mol_seg_t entity;
    entity = MolReader_DataEntity_get_entity(&mol);
    print_mol_seg_t(entity, "DataEntity.entity  ");

    //get Bytes
    mol_seg_t bytes_device_key_list_cell;
    bytes_device_key_list_cell = MolReader_Bytes_raw_bytes(&entity);
    print_mol_seg_t(bytes_device_key_list_cell, "bytes_device_key_list_cell ");

    //hash and check
    uint8_t step1[BLAKE2B_BLOCK_SIZE];
    uint8_t for_cmp[BLAKE2B_BLOCK_SIZE];

    blak2b_hash(step1, bytes_device_key_list_cell.ptr, bytes_device_key_list_cell.size);
    blak2b_hash(for_cmp, step1, BLAKE2B_BLOCK_SIZE);

    bool find_hash = false;
    for (int i = 0; i < hash_len; i += HASH_SIZE) {
        if (memcmp(for_cmp, hash, BLAKE2B_BLOCK_SIZE) == 0) {
            find_hash = true;
            break;
        } else {
            debug_print_data("data before hash = ", bytes_device_key_list_cell.ptr, bytes_device_key_list_cell.size);
            debug_print_data("expected hash = ", hash, hash_len);
            debug_print_data("actual   hash = ", for_cmp, BLAKE2B_BLOCK_SIZE);
            debug_print("The hash of the calculated key list is different from that in the cell.");
            continue;
        }
    }

    //whent you don't find the hash in cells
    if (!find_hash) {
        return ERROR_MOLECULE_ENCODING;
    }

    //todo it's same with 0f after, maybe we can merge them
    //get DeviceKeyListCellData
    mol_seg_t keys;
    keys = MolReader_DeviceKeyListCellData_get_keys(&bytes_device_key_list_cell);

    //get key_list_len
    int keys_num = MolReader_DeviceKeyList_length(&keys);
    debug_print_int("key_list_len ", keys_num);

    //check pk_idx
    if (pk_idx < 0 || pk_idx >= keys_num) {
        debug_print("The index of the selected public key is out of range.");
        debug_print_int("chose index = ", pk_idx);
        debug_print_int("keys_num = ", keys_num);
        return ERROR_MOLECULE_ENCODING;
    }

    //get key by pk_idx
    mol_seg_res_t key;
    key = MolReader_DeviceKeyList_get(&keys, pk_idx);
    if (key.errno != MOL_OK) {
        debug_print_int("MolReader_DeviceKeyList_get error ", key.errno);
        return ERROR_MOLECULE_ENCODING;
    }

    mol = key.seg;

    //copy data
    if (mol.size != 22) {
        debug_print_int("key.size wrong", mol.size);
        return ERROR_MOLECULE_ENCODING;
    }
    memcpy(out_data, mol.ptr + 1, 21);
    *out_data_len = 21;

    return 0;
}


int get_payload_from_molecule_cell_data(uint8_t *out_data, size_t *out_data_len, uint8_t *in_data, size_t in_len,
                                               int pk_idx, uint8_t *hash, size_t hash_len) {


    uint8_t step1[BLAKE2B_BLOCK_SIZE];
    blak2b_hash(step1, in_data, in_len); //data

    uint8_t for_cmp[BLAKE2B_BLOCK_SIZE];
    blak2b_hash(for_cmp, step1, BLAKE2B_BLOCK_SIZE); //data.hash

    bool find_hash = false;
    for (int i = 0; i < hash_len; i += HASH_SIZE) {
        if (memcmp(for_cmp, hash, BLAKE2B_BLOCK_SIZE) == 0) {
            find_hash = true;
            break;
        } else {
            debug_print_data("data before hash = ", in_data, in_len);
            debug_print_data("expected hash = ", hash + i, HASH_SIZE);
            debug_print_data("actual   hash = ", for_cmp, BLAKE2B_BLOCK_SIZE);
            debug_print("The hash of the calculated key list is different from that in the cell.");
            continue;
        }
    }
    if (find_hash == false) {
        return ERROR_MOLECULE_ENCODING;
    }

    mol_seg_t in_seg;
    in_seg.ptr = in_data;
    in_seg.size = in_len;

    //init
    mol_seg_t mol = {0};

    //verify Data
    if (MolReader_DeviceKeyListCellData_verify(&in_seg, false) != MOL_OK) {
        debug_print("Validation data DeviceKeyListCellData failed.");
        return ERROR_MOLECULE_ENCODING;
    }

    //get DeviceKeyList
    mol_seg_t keys;
    keys = MolReader_DeviceKeyListCellData_get_keys(&in_seg);
    uint32_t keys_num = MolReader_DeviceKeyList_length(&keys);

    //check pk_idx
    if (pk_idx < 0 || pk_idx >= keys_num) {
        debug_print("The index of the selected public key is out of range.");
        debug_print_int("chose index = ", pk_idx);
        debug_print_int("keys_num = ", keys_num);
        return ERROR_MOLECULE_ENCODING;
    }

    //get key by pk_idx
    mol_seg_res_t key;
    key = MolReader_DeviceKeyList_get(&keys, pk_idx);
    if (key.errno != MOL_OK) {
        debug_print_int("MolReader_DeviceKeyList_get error ", key.errno);
        return ERROR_MOLECULE_ENCODING;
    }

    //copy data
    mol = key.seg;
    if (mol.size != 22) {
        debug_print_int("key.size ", mol.size);
        return ERROR_MOLECULE_ENCODING;
    }

    //just copy payload
    memcpy(out_data, mol.ptr + 1, 21);
    *out_data_len = 21;
    debug_print_data("get payload = ", out_data, 21);

    return 0;
}



/* calculate witness length */
int calculate_witnesses_len() {
    uint64_t len = 0;
    int lo = 0;
    int hi = 4;
    int ret;
    while (1) {
        ret = ckb_load_witness(NULL, &len, 0, hi, CKB_SOURCE_INPUT);

        if (ret == CKB_SUCCESS) {
            lo = hi;
            hi *= 2;

        } else {
            break;
        }
    }

    int i;
    while (lo + 1 != hi) {
        i = (lo + hi) / 2;
        ret = ckb_load_witness(NULL, &len, 0, i, CKB_SOURCE_INPUT);

        if (ret == CKB_SUCCESS) {
            lo = i;
        } else {
            hi = i;
        }
    }

    return hi;
}

/* calculate cell deps length */
int calculate_cell_deps_len() {
    uint64_t len = 0;
    int lo = 0;
    int hi = 4;
    int ret;
    while (1) {
        ret = ckb_load_cell_by_field(NULL, &len, 0, hi, CKB_SOURCE_CELL_DEP,
                                     CKB_CELL_FIELD_CAPACITY);

        if (ret == CKB_SUCCESS) {
            lo = hi;
            hi *= 2;

        } else {
            break;
        }
    }
    int i;
    while (lo + 1 != hi) {
        i = (lo + hi) / 2;
        ret = ckb_load_cell_by_field(NULL, &len, 0, i, CKB_SOURCE_CELL_DEP,
                                     CKB_CELL_FIELD_CAPACITY);
        if (ret == CKB_SUCCESS) {
            lo = i;
        } else {
            hi = i;
        }
    }

    return hi;
}


/*
 * specify lock_args and field in transaction, then search in cell_deps or inputs
 * if there are multiple cells, return all
 */
int get_data_hash_inner(uint8_t* output, size_t* output_len, uint8_t* temp, size_t temp_len, uint8_t* lock_args, int field, bool is_owner){

    int ret;
    size_t output_len_temp = 0;

#ifdef CKB_C_STDLIB_PRINTF
    //testnet
    char* device_key_list_type_id = "9986d68bbf798e21238f8e5f58178354a8aeb7cc3f38e2abcb683e6dbb08f737";
#else
    //mainnet
    char* device_key_list_type_id = "e1a03a44d5705926c34bddd974cb0d3b06a56718db8a2c63d77e06a6385331c9";
#endif
    uint8_t expected_type_id[HASH_SIZE];
    hex2str(device_key_list_type_id, expected_type_id);
    debug_print_data("expected type id = ", expected_type_id, HASH_SIZE);

    //get cell_deps len
    int cells_number;
    if (field == CKB_SOURCE_INPUT){
        cells_number = calculate_inputs_len();
    }else {
        cells_number = calculate_cell_deps_len();
    }
    if(cells_number < 1){ //no cell_deps found, maybe the logic of calculate_cell_deps_len is wrong
        cells_number = 255;
    }
    debug_print_int("cells_numbers ", cells_number);

    //Iterate over all cell_deps
    //when the type id is DeviceKeyListCell and lock_args is the incoming lock_args, save data.hash
    for(int i = 0; i < cells_number; i++){
        debug_print_int("cell idx", i);
        //step1: load type script to temp and get code hash
        temp_len = TEMP_SIZE;
        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_TYPE);
        if(ret != 0) {
            debug_print_int("load cell failed, index = ", i);
            continue;
        }
        //verify the type script
        mol_seg_t type_script_seg;
        type_script_seg.ptr = (uint8_t *) temp;
        type_script_seg.size = temp_len;
        //maybe there can be optimized when cycles are too many
        if (MolReader_Script_verify(&type_script_seg, false) != MOL_OK) {
            debug_print_int("verify type_script failed, index = ", i);
            continue;
        }

        //get code_hash of type script
        mol_seg_t hash_seg = MolReader_Script_get_code_hash(&type_script_seg);

        //compare code_hash
        if (memcmp(expected_type_id, hash_seg.ptr, HASH_SIZE) != 0) {
            //debug_print_data("expect type_id = ", expected_type_id, HASH_SIZE);
            debug_print_data("actual type_id = ", hash_seg.ptr, HASH_SIZE);
            debug_print_int("cell type_hash not match, index = ", i);
            continue;
        }
        debug_print_int("s1: The type hash of the cell matches successfully, index = ", i);

        //step2: get lock script
        temp_len = TEMP_SIZE;
        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_LOCK);
        if (ret != CKB_SUCCESS) {
            debug_print_int("load cell.lock failed, index = ", i);
            continue;
        }

        //verify the lock script
        mol_seg_t lock_script;
        lock_script.ptr = (uint8_t *) temp;
        lock_script.size = temp_len;
        if (MolReader_Script_verify(&lock_script, false) != MOL_OK) {
            debug_print_int("verify lock_script failed, index = ", i);
            continue;
        }

        //get lock args
        mol_seg_t args_seg = MolReader_Script_get_args(&lock_script);
        mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
        debug_print_data("s2: lock args in cell = ", args_bytes_seg.ptr, args_bytes_seg.size);

        //compare lock_args
        uint8_t* lock_args_temp;
        const int payload_len = 21;
        if(is_owner) {
            lock_args_temp = args_bytes_seg.ptr + 1;
        }else {
            lock_args_temp = args_bytes_seg.ptr + WEBAUTHN_PAYLOAD_LEN + 3;
        }
        ret = memcmp(lock_args_temp, lock_args, payload_len);
        if(ret != 0){
            debug_print_data("lock_args in cell_deps = ", lock_args_temp, payload_len);
            debug_print_data("lock_args in inputs = ", lock_args, payload_len);
            debug_print_int("lock_args not match, index = ", i);
            continue;
        }

        //step3: get data_hash and save it into data_hashs
        ret = ckb_load_cell_by_field(temp, &temp_len, 0, i, field, CKB_CELL_FIELD_DATA_HASH);
        if (ret != CKB_SUCCESS) {
            debug_print_int("load cell.data_hash failed, index = ", i);
            continue;
        }
        debug_print_data("s3: data_hash in cell = ", temp, temp_len);

        memcpy(output + output_len_temp, temp, temp_len);
        output_len_temp += temp_len;
        continue;
    }


    if(output_len_temp == 0){
        debug_print("data_hash not found");
        return ERROR_DEVICE_KEY_LIST_CELL_NOT_FOUND;
    }else {
        *output_len = output_len_temp;
        return CKB_SUCCESS;
    }
}

int get_data_hash(uint8_t* output, size_t* output_len, uint8_t* temp, uint8_t* lock_args, bool is_owner, bool* in_inputs){
    size_t temp_len = TEMP_SIZE;

    //get data.hash from cell_deps
    if (get_data_hash_inner(output, output_len, temp, temp_len, lock_args, CKB_SOURCE_INPUT, is_owner) == ERROR_DEVICE_KEY_LIST_CELL_NOT_FOUND){
        temp_len = TEMP_SIZE;
        *in_inputs = false;
        return get_data_hash_inner(output, output_len, temp, temp_len, lock_args,  CKB_SOURCE_CELL_DEP, is_owner);
    }else {
        *in_inputs = true;
        return 0;
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
int get_payload_from_cell(uint8_t *lock_args, uint8_t *temp, uint8_t pk_idx, uint8_t args_index){
    int ret = CKB_SUCCESS;

    //used to store multiple data.hash
    uint8_t data_hashs[TEMP_SIZE];
    size_t data_hashs_len = TEMP_SIZE;
    bool device_key_list_cell_in_inputs;
    //get data.hash from cell_deps
    ret = get_data_hash(data_hashs, &data_hashs_len, temp, lock_args, args_index == 0 ? true : false, &device_key_list_cell_in_inputs);
    SIMPLE_ASSERT(0);

    debug_print_int("device_key_list_cell_in_inputs = ", device_key_list_cell_in_inputs);

    //Caution: if the repo das-type update, this value should update too
    const uint8_t data_type_1[4] = {0x0d, 0x00, 0x00, 0x00}; //DeviceKeyListEntityData
    const uint8_t data_type_2[4] = {0x0f, 0x00, 0x00, 0x00}; //DeviceKeyListCellData

    //get witness
    size_t start_idx = calculate_inputs_len();
    size_t end_idx = calculate_witnesses_len();
    debug_print_int("start_idx = ", start_idx);
    debug_print_int("end_idx = ", end_idx);

    //Redundant design to prevent excessive cycle overhead
    if(end_idx < 1 || end_idx > 255){
        end_idx = 1;
    }

    int key_list_witness_idx = -1;
    size_t witness_len;
    size_t lock_args_len;
    for (size_t i = start_idx; i < end_idx; i++) {
        witness_len = MAX_WITNESS_SIZE;
        ret = ckb_load_witness(temp, &witness_len, 0, i, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
            debug_print_int("read witness success, index = ", i);
            debug_print_int("witness len = ", witness_len);
            debug_print_data("witness data[0..20] = ", temp, 20);
        } else {
            continue;
        }

        if (memcmp(temp, "das", 3) == 0){
            if(memcmp(temp + 3, data_type_1, 4) == 0 && device_key_list_cell_in_inputs == true){
                debug_print("find a device key list cell that qualified, 0x0d");
                ret = get_payload_from_molecule_entity_data(lock_args, &lock_args_len,temp + 7, witness_len - 7,  pk_idx, data_hashs, data_hashs_len, OLD);
                if(ret != 0){
                    debug_print("get_payload_from_molecule_entity_data failed");
                    continue;
                }
                key_list_witness_idx = i;
                break;
            }else if(memcmp(temp + 3, data_type_2, 4) == 0 && device_key_list_cell_in_inputs == false){
                debug_print("find a device key list cell that qualified, 0x0f");
                ret = get_payload_from_molecule_cell_data(lock_args, &lock_args_len, temp + 7, witness_len - 7, pk_idx, data_hashs, data_hashs_len);
                if(ret != 0){
                    debug_print("get_payload_from_molecule_cell_data failed");
                    continue;
                }
                key_list_witness_idx = i;
                break;
            }else {
                continue;
            }
        }
    }//end for
    if (key_list_witness_idx == -1) {
        debug_print("The witness containing the key list was not found.");
        return ERROR_DEVICE_KEY_LIST_CELL_NOT_MATCH;
    }else {
        return 0;
    }
}


#endif //DAS_LOCK_KEYLIST_OPRATE_H
