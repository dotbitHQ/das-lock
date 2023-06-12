//
// Created by peter on 23-5-25.
//

#ifndef DAS_LOCK_KEYLIST_OPRATE_H
#define DAS_LOCK_KEYLIST_OPRATE_H
#include "inc_def.h"
#include "keylist.h"

enum MolTableData{
    DEP,
    OLD,
    NEW,
};

void print_mol_seg_t(mol_seg_t mol, const char* title) {
    debug_print_data(title, mol.ptr, mol.size);
}
//get DeviceKey by idx
int get_payload_by_pk_index(uint8_t* in_data, size_t in_len, uint8_t* out_data, int pk_idx, enum MolTableData m) {
    mol_seg_t in_seg;
    in_seg.ptr = in_data;
    in_seg.size = in_len;

    //print log
    debug_print_int("get_payload pk_idx = ", pk_idx);
    debug_print_int("get_payload MolTableData = ", m);
    debug_print_data("get_payload in_buf = ", in_data, in_len);

    //init
    int ret = 0;
    mol_seg_t mol = {0};

    //verify Data
    if (MolReader_Data_verify(&in_seg, false) != MOL_OK) {
        debug_print("cannot verify data mol reader\n");
        return -1;
    }else {
        debug_print("verify data mol reader Success\n");
    }

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
    }
    bool isnone = MolReader_DataEntityOpt_is_none(&mol);
    if(isnone) {
        debug_print_int("DataEntityOpt is none, MolTableData=", m);
        return -1;
    }

    mol_seg_t entity;
    entity = MolReader_DataEntity_get_entity(&mol);
    print_mol_seg_t(entity, "DataEntity.entity  ");

    mol_seg_t bytes_device_key_list_cell;
    bytes_device_key_list_cell = MolReader_Bytes_raw_bytes(&entity);
    print_mol_seg_t(bytes_device_key_list_cell, "bytes_device_key_list_cell ");

    mol_seg_t keys;
    keys = MolReader_DeviceKeyListCellData_get_keys(&bytes_device_key_list_cell);

    int key_list_len = MolReader_DeviceKeyList_length(&keys);
    debug_print_int("key_list_len ", key_list_len);

    if (pk_idx < 0 || pk_idx >= key_list_len){
        debug_print("choose public key out of bound");
        debug_print_int("choosed index = ", pk_idx);
        debug_print_int("key_list_len = ", key_list_len);
        return -1;
    }

    mol_seg_res_t key;
    key = MolReader_DeviceKeyList_get(&keys, pk_idx);
    if(key.errno != MOL_OK){
        debug_print_int("MolReader_DeviceKeyList_get error ", key.errno);
        return -1;
    }

    mol = key.seg;
    debug_print_int("key.size ", mol.size);

    int cpy_len = mol.size > DAS_MAX_LOCK_ARGS_SIZE ? DAS_MAX_LOCK_ARGS_SIZE : mol.size;
    memcpy(out_data,mol.ptr, cpy_len);
    //debug_print_data("output payload = ", out_data, 22);
    return ret;
}







#endif //DAS_LOCK_KEYLIST_OPRATE_H
