#ifndef DAS_LOCK_KEYLIST_OPRATE_H
#define DAS_LOCK_KEYLIST_OPRATE_H
#include "inc_def.h"
#include "keylist.h"

//enum MolTableData{
//    DEP,
//    OLD,
//    NEW,
//};

void print_mol_seg_t(mol_seg_t mol, const char* title) {
    debug_print_data(title, mol.ptr, mol.size);
}
//get DeviceKey by idx
//int get_payload_by_pk_index(uint8_t* out_data, size_t* out_data_len, uint8_t* in_data, size_t in_len,  int pk_idx, enum MolTableData m) {
int get_payload_by_pk_index(uint8_t* out_data, size_t* out_data_len, uint8_t* in_data, size_t in_len,  int pk_idx) {
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
    }else {
        debug_print("verify data mol reader Success\n");
    }

    //get Data
//    switch (m) {
//        case DEP : {
//            mol = MolReader_Data_get_dep(&in_seg);
//            print_mol_seg_t(mol, "dep ");
//            break;
//        }
//        case OLD : {
//            mol = MolReader_Data_get_old(&in_seg);
//            print_mol_seg_t(mol, "old ");
//            break;
//        }
//        case NEW : {
//            mol = MolReader_Data_get_new(&in_seg);
//            print_mol_seg_t(mol, "new ");
//            break;
//        }
//    }

    //try to get Dep first, if it fails then try to get Old, if it fails again return an error
    mol = MolReader_Data_get_dep(&in_seg);
    bool isnone = MolReader_DataEntityOpt_is_none(&mol);
    if(isnone) {
        debug_print("DataEntityOpt is none, MolTableData=DEP");
        mol = MolReader_Data_get_old(&in_seg);
        isnone = MolReader_DataEntityOpt_is_none(&mol);
        if(isnone) {
            debug_print("DataEntityOpt is none, MolTableData=OLD");
            return ERROR_MOLECULE_ENCODING;
        }
        debug_print("DataEntityOpt OLD is not none");
    }else {
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
    if (pk_idx < 0 || pk_idx >= key_list_len){
        debug_print("choose public key out of bound");
        debug_print_int("choosed index = ", pk_idx);
        debug_print_int("key_list_len = ", key_list_len);
        return ERROR_MOLECULE_ENCODING;
    }

    //get key by pk_idx
    mol_seg_res_t key;
    key = MolReader_DeviceKeyList_get(&keys, pk_idx);
    if(key.errno != MOL_OK){
        debug_print_int("MolReader_DeviceKeyList_get error ", key.errno);
        return ERROR_MOLECULE_ENCODING;
    }

    mol = key.seg;
    debug_print_int("key.size ", mol.size);
    //debug_print_data("key.content ", mol.ptr, mol.size);

    //copy data
    //int cpy_len = mol.size > DAS_MAX_LOCK_ARGS_SIZE ? DAS_MAX_LOCK_ARGS_SIZE : mol.size;
    if(mol.size != 22) {
        return ERROR_MOLECULE_ENCODING;
    }
    memcpy(out_data,mol.ptr + 1, 21);
    debug_print_data("get payload = ", out_data, 21);

    //return
    *out_data_len = 21;
    return 0;
}

#endif //DAS_LOCK_KEYLIST_OPRATE_H
