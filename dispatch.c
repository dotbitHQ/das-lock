
#include "inc_def.h"

int get_args(uint8_t *lock_args) {

	debug_print("Enter get_args");
	int ret = 0;

	// Load args
	uint8_t script[SCRIPT_SIZE];
	uint64_t len = SCRIPT_SIZE;
	ret = ckb_load_script(script, &len, 0);
	NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
	if (len > SCRIPT_SIZE) {
		return ERROR_SCRIPT_TOO_LONG;
	}

	mol_seg_t script_seg;
	script_seg.ptr = (uint8_t *)script;
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

int get_plain_and_cipher(uint8_t *message, uint8_t *lock_bytes, uint8_t sign_index) {

	debug_print("Enter get_plain_and_cipher");
	int ret = 0;

	/* Load witness of first input */
	uint8_t temp[TEMP_SIZE];
	uint64_t witness_len = DAS_MAX_LOCK_BYTES_SIZE;
	ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
	debug_print_data("witness: ", temp, witness_len);
	NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
	if (witness_len > DAS_MAX_LOCK_BYTES_SIZE) {
		return ERROR_WITNESS_SIZE;
	}

	/* load signature */
	mol_seg_t lock_bytes_seg;
	ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
	NORMAL_ASSERT(CKB_SUCCESS, ERROR_ENCODING);

	debug_print_int("sign_index: ", sign_index);
	if (sign_index == 5) { // eip712
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
	else if (sign_index == 6) {
		if (lock_bytes_seg.size != ED25519_SIGNATURE_SIZE) {
			return ERROR_ARGUMENTS_LEN;
		}
	}
	*/
	else {
		if (lock_bytes_seg.size != SIGNATURE_SIZE) {
			return ERROR_ARGUMENTS_LEN;
		}
	}
	debug_print_int("lock_bytes_seg.size: ", lock_bytes_seg.size);

	memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);
	// get the offset of lock_bytes for sign
	size_t multisig_script_len = 0;
	if (sign_index == 1) {
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


	memset((void *)lock_bytes_seg.ptr + multisig_script_len, 0, lock_bytes_seg.size);
	blake2b_update(&blake2b_ctx, (uint8_t *)&witness_len, sizeof(uint64_t));
	blake2b_update(&blake2b_ctx, temp, witness_len);
	debug_print_int("witness_len: ", witness_len);

	// Digest same group witnesses
	size_t i = 1;
	while (1) {
		ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_GROUP_INPUT);
		if (ret == CKB_INDEX_OUT_OF_BOUND) {
			break;
		}
		NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
		i += 1;
	}

	// Digest witnesses that not covered by inputs
	i = ckb_calculate_inputs_len();
	while (1) {
		ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_INPUT);
		if (ret == CKB_INDEX_OUT_OF_BOUND) {
			break;
		}
		NORMAL_ASSERT(CKB_SUCCESS, ERROR_SYSCALL);
		i += 1;
	}

	blake2b_final(&blake2b_ctx, message, HASH_SIZE);
	return CKB_SUCCESS;
}

int get_lock_args_index(uint8_t* temp, uint8_t len, uint8_t* index) {
	int ret = 0;	
	// 0x646173
	if (len >= 3 && memcmp(temp, "das", 3) != 0) {
		return ERR_DAS_PREFIX_NOT_MATCH; 
	}
	*index = temp[len - 1];
	return ret;
}

int get_action_from_witness(uint8_t* temp, uint64_t* temp_len, uint8_t* action, uint64_t* action_len) {
	debug_print("Enter get_action_from_witness");
	int ret = CKB_SUCCESS;
	int pre_len = 19;
	int action_len_len = 4;
	char action_len_buf[action_len_len];
	memcpy(action_len_buf, temp + pre_len, action_len_len);
	debug_print_data("action_len_buf: ", (unsigned char*)action_len_buf, action_len_len);
	*action_len = big_endian_hex_str2int(action_len_buf, action_len_len);
	memcpy(action, temp + pre_len + action_len_len, *action_len);

	//debug_print_data("temp: ", temp, *temp_len);
	debug_print_data("action: ", action, *action_len);
	debug_print_int("action_len: ", *action_len);
	return ret;
}

int get_self_index_in_inputs(uint64_t* index) {
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

int check_cmd_match(uint8_t* temp, uint64_t* temp_len, int type) {
	debug_print("Enter check_cmd_match");
	int ret = CKB_SUCCESS;
	size_t i = calculate_inputs_len();
	ret = ckb_load_witness(temp, temp_len, 0, i, CKB_SOURCE_INPUT);
	SIMPLE_ASSERT(CKB_SUCCESS);

	uint8_t action_from_wit[1000];
	size_t action_from_wit_len;
	ret = get_action_from_witness(temp, temp_len, action_from_wit, &action_from_wit_len);
	SIMPLE_ASSERT(CKB_SUCCESS);
	// 0x646173
	char* skip_str[] = {
#include "skip_cmd_list.txt"
	};
	char* manager_only_str[] = {
#include "manager_only_cmd_list.txt"
	};

	uint8_t list_len0 = sizeof(skip_str) / sizeof(skip_str[0]);
	uint8_t list_len1 = sizeof(manager_only_str) / sizeof(manager_only_str[0]);
	uint8_t list_len = (type ? list_len0 : list_len1);
	for (int i = 0; i < list_len; i++) {
		char* standard_str;
		if (type == SKIP_CMD) {
			standard_str = skip_str[i];
		}
		else {
			standard_str = manager_only_str[i];
		}
		size_t standard_str_len = strlen(standard_str);
		//uint8_t for_cmp[standard_str_len];
		//hex2str(standard_str, for_cmp);
		//debug_print_int("temp_len: ", *temp_len);
		debug_print_int("standard_str_len: ", standard_str_len);
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
	char* balance_type_id = "ebafc1ebe95b88cac426f984ed5fce998089ecad0cd2f8b17755c9de4cb02162";
#endif
	uint8_t for_cmp[HASH_SIZE];
	hex2str(balance_type_id, for_cmp);

	int i = 0;
	while (1) {
		uint8_t buffer[100];
		uint64_t len = 100;
		ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_TYPE);
		if (ret == CKB_ITEM_MISSING) {
			i++;
			continue;
		}
		else if (ret == CKB_SUCCESS) {
			uint8_t typeid[HASH_SIZE];
			memcpy(typeid, buffer + 16, HASH_SIZE);
			debug_print_data("type id: ", typeid, HASH_SIZE);
			if (memcmp(for_cmp, typeid, HASH_SIZE) == 0) {
				i++;
				continue;
			}
			else {
				return DAS_NOT_PURE_LOCK_CELL;
			}
		}
		else if (ret == CKB_INDEX_OUT_OF_BOUND) {
			return DAS_PURE_LOCK_CELL;
		}
		else {
			return DAS_NOT_PURE_LOCK_CELL;
		}
	}
	return ret;
}

int check_skip_sign_for_buy_account(uint8_t* temp, uint64_t len, uint64_t sign_index) {
	debug_print("Enter check_skip_sign_for_buy_account");
	debug_print_int("sign_index: ", sign_index);
	if (sign_index != 5) {
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
	ret = get_action_from_witness(temp, &len, action_from_wit, &action_from_wit_len);
	SIMPLE_ASSERT(CKB_SUCCESS);

	debug_print_data("action_from_wit: ", action_from_wit, action_from_wit_len);
	char* standard_str = "buy_account";
	size_t standard_str_len = strlen(standard_str);
	if (memcmp(action_from_wit, standard_str, standard_str_len) == 0) {
		debug_print("skip check sig buy_account");
		return DAS_SKIP_CHECK_SIGN;
	}
	return DAS_NOT_SKIP_CHECK_SIGN;
}

int check_skip_sign(uint8_t* temp, uint64_t* temp_len) {
	debug_print("Enter check_skip_sign");
	int ret = CKB_SUCCESS;
	ret = check_has_pure_type_script();
	if (ret == DAS_PURE_LOCK_CELL) {
		return DAS_NOT_SKIP_CHECK_SIGN;
	}

	ret = check_cmd_match(temp, temp_len, SKIP_CMD);
	return ret == DAS_CMD_MATCH ? DAS_SKIP_CHECK_SIGN : DAS_NOT_SKIP_CHECK_SIGN;
}

int check_manager_only() {
	debug_print("Enter check_manager_only");
	uint8_t temp[MAX_WITNESS_SIZE];
	uint64_t temp_len = MAX_WITNESS_SIZE;
	int ret = check_cmd_match(temp, &temp_len, MANAGER_ONLY_CMD);
	return ret;
}

int get_lock_args(uint8_t* das_args, uint8_t index, uint8_t* lock_args, uint8_t* sign_index ) {
	int ret = CKB_SUCCESS;
	size_t args1_len = BLAKE160_SIZE;
	memcpy(sign_index, das_args, 1);
	if (*sign_index == 1) { // multi sign
		args1_len += sizeof(uint64_t);
	} 
	else if (*sign_index == 6) { // ed25519
		args1_len = HASH_SIZE;
	}

	if (0 == index) { // use first args (owner lock)
		memcpy(lock_args, das_args + 1, args1_len);
		return ret;
	}
	else if (1 == index) { // use second args (manager lock)
		if (check_manager_only() != DAS_CMD_MATCH) {
			return ERR_DAS_INVALID_PERMISSION;
		}
		size_t args2_len = BLAKE160_SIZE;
		memcpy(sign_index, das_args + 1 + args1_len, 1);
		if (*sign_index == 1) { // multi sign
			args2_len += sizeof(uint64_t);
		}
		else if (*sign_index == 6) { // ed25519
			args2_len = HASH_SIZE;
		}
		memcpy(lock_args, das_args + 2 + args1_len, args2_len);
		return ret;
	}
	else {
		debug_print("only support owner and manager");
		return ERR_DAS_INDEX_NOT_FOUND;
	}
}

int get_code_hash(uint8_t index, uint8_t* code_hash) {
	int ret = CKB_SUCCESS;
	char* code_hash_map[] = {
#ifdef CKB_C_STDLIB_PRINTF
#include "test2_so_list.txt"
#else
#include "mainnet_so_list.txt"
#endif
	};
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



int main() {
	int ret = CKB_SUCCESS;

	uint8_t witness_action[MAX_WITNESS_SIZE];
	uint64_t witness_action_len = MAX_WITNESS_SIZE;
	ret = check_skip_sign(witness_action, &witness_action_len);
	if (ret == DAS_SKIP_CHECK_SIGN) {
		return CKB_SUCCESS;
	}
	SIMPLE_ASSERT(DAS_NOT_SKIP_CHECK_SIGN);

	uint8_t args_index = 0;
	ret = get_lock_args_index(witness_action, witness_action_len, &args_index);
	SIMPLE_ASSERT(CKB_SUCCESS);
	debug_print_int("args_index: ", args_index);

	uint8_t das_args[DAS_ARGS_MAX_LEN];
	ret = get_args(das_args);
	SIMPLE_ASSERT(CKB_SUCCESS);
	debug_print("after get_args");

	uint8_t lock_args[DAS_MAX_LOCK_ARGS_SIZE];
	uint8_t sign_index = -1;
	ret = get_lock_args(das_args, args_index, lock_args, &sign_index);	
	SIMPLE_ASSERT(CKB_SUCCESS);
	debug_print_data("lock_args: ", lock_args, DAS_MAX_LOCK_ARGS_SIZE);

	ret = check_skip_sign_for_buy_account(witness_action, witness_action_len, sign_index);
	if (ret == DAS_SKIP_CHECK_SIGN) {
		return CKB_SUCCESS;
	}
	SIMPLE_ASSERT(DAS_NOT_SKIP_CHECK_SIGN);
		
	uint8_t message[HASH_SIZE];
	uint8_t lock_bytes[DAS_MAX_LOCK_BYTES_SIZE];
	ret = get_plain_and_cipher(message, lock_bytes, sign_index);
	SIMPLE_ASSERT(CKB_SUCCESS);
	debug_print_data("message: ", message, HASH_SIZE);
	debug_print("after generate digest message");

	//if (sign_index == 5) {
	//	return verify_signature(message, lock_bytes, lock_args);
	//}
	uint8_t code_so[HASH_SIZE];
	ret = get_code_hash(sign_index, code_so);
	SIMPLE_ASSERT(CKB_SUCCESS);
	debug_print_data("code so: ", code_so, HASH_SIZE);

	uint8_t code_buffer[128 * 1024] __attribute__((aligned(RISCV_PGSIZE)));
	uint64_t consumed_size = 0;
	void *handle = NULL;
	uint8_t hash_type = 0;
	ret = ckb_dlopen2(code_so, hash_type, code_buffer, 128 * 1024, &handle, &consumed_size);
	SIMPLE_ASSERT(CKB_SUCCESS);
	debug_print("after ckb_dlopen2");

	int (*validate_func)(int, uint8_t*, uint8_t*, uint8_t*);
	*(void **)(&validate_func) = ckb_dlsym(handle, "validate");
	if (validate_func == NULL) {
		return ERR_DAS_INVALID_POINT;
	}

	int type = 0;
	if (sign_index == 5) {
		type = 1;
	}
	return validate_func(type, message, lock_bytes, lock_args);
}
