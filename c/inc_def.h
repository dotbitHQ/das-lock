#ifndef INC_DEF_H
#define INC_DEF_H
#define SIGNATURE_SIZE 65
#define SIGNATURE_DOGE_SIZE 66
#define SIGNATURE_BTC_SIZE 67
#define ED25519_SIGNATURE_SIZE 64
#define CHAIN_ID_LEN 8

#define HASH_SIZE 32
#define PUBKEY_SIZE 33
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define TEMP_SIZE 32768
#define TEMP_SIZE_SMALL 256
#define RECID_INDEX 64
#define RIPEMD160_HASH_SIZE 20
#define PUBKEY_COMPRESSED_SIZE 33
#define PUBKEY_UNCOMPRESSED_SIZE 65
#define WEBAUTHN_DIGEST_LEN 69
#define WEBAUTHN_LOCK_ARGS_LEN 22
#define WEBAUTHN_PAYLOAD_LEN 20

#define SCRIPT_SIZE 32768
#define MAX_WITNESS_SIZE 32768
#define MAX_LOCK_ARGS_SIZE 1024
#define MAX_CODE_SIZE (1024 * 1024)

#define RISCV_PGSIZE 4096

#define DAS_ARGS_MAX_LEN 66
#define FLAGS_SIZE 4

#define DAS_PURE_LOCK_CELL 10000
#define DAS_NOT_PURE_LOCK_CELL 10001
#define DAS_MAX_LOCK_BYTES_SIZE 1024
#define DAS_MAX_LOCK_ARGS_SIZE 32
#define DAS_SKIP_CHECK_SIGN 1
#define DAS_NOT_SKIP_CHECK_SIGN 99999
#define DAS_CMD_MATCH	0
#define DAS_CMD_NOT_MATCH 1
#define MANAGER_ONLY_CMD 0
#define SKIP_CMD 1
#define SECP256K1_SUCCESS 1


// Other error code see common.h and deps/ckb-c-stdlib/ckb_consts.h
#define ERR_DAS_INDEX_NOT_FOUND 10
#define ERR_DAS_INDEX_OUT_OF_BOUND 11
#define ERR_DAS_PREFIX_NOT_MATCH 12
#define ERR_DAS_INVALID_POINT 13
#define ERR_DAS_INVALID_PERMISSION 14
#define ERR_DAS_INVALID_LOCK_CELL 15
#define ERR_DAS_MESSAGE_TOO_LONG 16
#define ERR_DAS_MESSAGE_LENGTH 17

#define ERROR_INVALID_RESERVE_FIELD -41
#define ERROR_INVALID_PUBKEYS_CNT -42
#define ERROR_INVALID_THRESHOLD -43
#define ERROR_INVALID_REQUIRE_FIRST_N -44
// Multi-sigining validation errors
#define ERROR_MULTSIG_SCRIPT_HASH -51
#define ERROR_VERIFICATION -52

#define COMMON_PREFIX "From .bit: "
#define COMMON_PREFIX_LENGTH 11
#define COMMON_PREFIX_AND_MESSAGE_LENGTH (11 + 64)
#define SIMPLE_ASSERT(want) 	\
	do {			\
		if ((ret) != (want)) {	\
		       	return (ret); 	\
		}			\
	}while(0)

#define NORMAL_ASSERT(want, result) 	\
	do {			\
		if ((ret) != (want)) {	\
		       	return (result); 	\
		}			\
	}while(0)





#include "blake2b.h"
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#include "keccak256.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "common.h"

#include "utils_helper.h"

#define KECCAK256(message, len, res)		\
	do {				\
		SHA3_CTX sha3_ctx;	\
		keccak_init(&sha3_ctx);		\
		keccak_update(&sha3_ctx, message, len);	\
		keccak_final(&sha3_ctx, res);	\
	}while(0)


#endif
