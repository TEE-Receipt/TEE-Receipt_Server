#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_enclave_init_t {
	sgx_sealed_data_t* ms_sealed;
	size_t ms_sealedSize;
	size_t* ms_sealedLen;
	sgx_sealed_data_t* ms_sealedcmackey;
	size_t ms_cmackeysize;
	size_t* ms_sealedcmackeylen;
	uint8_t* ms_dhPublicKey;
} ms_enclave_init_t;

typedef struct ms_enclave_registeruser_t {
	nrt_ra_context_t ms_context;
	uint8_t* ms_password;
	size_t ms_passwordlen;
	uint8_t* ms_uid;
	uint8_t* ms_cmactag;
	uint8_t* ms_s;
	uint8_t* ms_sharedkey;
} ms_enclave_registeruser_t;

typedef struct ms_enclave_login_t {
	nrt_ra_context_t ms_context;
	uint8_t* ms_password;
	size_t ms_passwordlen;
	uint8_t* ms_uid;
	uint8_t* ms_cmactag;
	uint8_t* ms_cmacuisig;
	uint8_t* ms_ct;
	size_t* ms_authenticated;
} ms_enclave_login_t;

typedef struct ms_enclave_signtransaction_t {
	nrt_ra_context_t ms_context;
	uint8_t* ms_tansactiontext;
	size_t ms_transactiontextlen;
	uint8_t* ms_browsersig;
	uint8_t* ms_uid;
	uint8_t* ms_esig;
	uint8_t* ms_pkt;
	size_t* ms_retvalue;
} ms_enclave_signtransaction_t;

typedef struct ms_ecall_enclave_init_ra_t {
	int ms_retval;
	int ms_b_pse;
	nrt_ra_context_t* ms_context;
} ms_ecall_enclave_init_ra_t;

typedef struct ms_ecall_enclave_close_ra_t {
	int ms_retval;
	nrt_ra_context_t ms_context;
} ms_ecall_enclave_close_ra_t;

typedef struct ms_nrt_ra_get_ga_t {
	sgx_status_t ms_retval;
	nrt_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_nrt_ra_get_ga_t;

typedef struct ms_nrt_ra_get_a_t {
	sgx_status_t ms_retval;
	nrt_ra_context_t ms_context;
	sgx_ec256_private_t* ms_a;
} ms_nrt_ra_get_a_t;

typedef struct ms_nrt_ra_set_gb_trusted_t {
	sgx_status_t ms_retval;
	nrt_ra_context_t ms_context;
	const sgx_ec256_public_t* ms_g_b;
} ms_nrt_ra_set_gb_trusted_t;

typedef struct ms_nrt_ra_create_report_t {
	sgx_status_t ms_retval;
	nrt_ra_context_t ms_context;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_nrt_ra_create_report_t;

typedef struct ms_nrt_ra_get_quote_trusted_t {
	sgx_status_t ms_retval;
	nrt_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	nrt_ra_msg_quote_t* ms_p_msg_quote;
	uint32_t ms_msg_quote_size;
} ms_nrt_ra_get_quote_trusted_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#pragma warning(disable: 4090)
#endif

static sgx_status_t SGX_CDECL sgx_enclave_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_init_t* ms = SGX_CAST(ms_enclave_init_t*, pms);
	ms_enclave_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_init_t), ms, sizeof(ms_enclave_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed = __in_ms.ms_sealed;
	size_t _tmp_sealedSize = __in_ms.ms_sealedSize;
	size_t _len_sealed = _tmp_sealedSize;
	sgx_sealed_data_t* _in_sealed = NULL;
	size_t* _tmp_sealedLen = __in_ms.ms_sealedLen;
	size_t _len_sealedLen = sizeof(size_t);
	size_t* _in_sealedLen = NULL;
	sgx_sealed_data_t* _tmp_sealedcmackey = __in_ms.ms_sealedcmackey;
	size_t _tmp_cmackeysize = __in_ms.ms_cmackeysize;
	size_t _len_sealedcmackey = _tmp_cmackeysize;
	sgx_sealed_data_t* _in_sealedcmackey = NULL;
	size_t* _tmp_sealedcmackeylen = __in_ms.ms_sealedcmackeylen;
	size_t _len_sealedcmackeylen = sizeof(size_t);
	size_t* _in_sealedcmackeylen = NULL;
	uint8_t* _tmp_dhPublicKey = __in_ms.ms_dhPublicKey;
	size_t _len_dhPublicKey = 64 * sizeof(uint8_t);
	uint8_t* _in_dhPublicKey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_sealedLen, _len_sealedLen);
	CHECK_UNIQUE_POINTER(_tmp_sealedcmackey, _len_sealedcmackey);
	CHECK_UNIQUE_POINTER(_tmp_sealedcmackeylen, _len_sealedcmackeylen);
	CHECK_UNIQUE_POINTER(_tmp_dhPublicKey, _len_dhPublicKey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ((_in_sealed = (sgx_sealed_data_t*)malloc(_len_sealed)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed, 0, _len_sealed);
	}
	if (_tmp_sealedLen != NULL && _len_sealedLen != 0) {
		if ( _len_sealedLen % sizeof(*_tmp_sealedLen) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedLen = (size_t*)malloc(_len_sealedLen)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedLen, 0, _len_sealedLen);
	}
	if (_tmp_sealedcmackey != NULL && _len_sealedcmackey != 0) {
		if ((_in_sealedcmackey = (sgx_sealed_data_t*)malloc(_len_sealedcmackey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedcmackey, 0, _len_sealedcmackey);
	}
	if (_tmp_sealedcmackeylen != NULL && _len_sealedcmackeylen != 0) {
		if ( _len_sealedcmackeylen % sizeof(*_tmp_sealedcmackeylen) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedcmackeylen = (size_t*)malloc(_len_sealedcmackeylen)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedcmackeylen, 0, _len_sealedcmackeylen);
	}
	if (_tmp_dhPublicKey != NULL && _len_dhPublicKey != 0) {
		if ( _len_dhPublicKey % sizeof(*_tmp_dhPublicKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_dhPublicKey = (uint8_t*)malloc(_len_dhPublicKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dhPublicKey, 0, _len_dhPublicKey);
	}
	enclave_init(_in_sealed, _tmp_sealedSize, _in_sealedLen, _in_sealedcmackey, _tmp_cmackeysize, _in_sealedcmackeylen, _in_dhPublicKey);
	if (_in_sealed) {
		if (memcpy_verw_s(_tmp_sealed, _len_sealed, _in_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedLen) {
		if (memcpy_verw_s(_tmp_sealedLen, _len_sealedLen, _in_sealedLen, _len_sealedLen)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedcmackey) {
		if (memcpy_verw_s(_tmp_sealedcmackey, _len_sealedcmackey, _in_sealedcmackey, _len_sealedcmackey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedcmackeylen) {
		if (memcpy_verw_s(_tmp_sealedcmackeylen, _len_sealedcmackeylen, _in_sealedcmackeylen, _len_sealedcmackeylen)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dhPublicKey) {
		if (memcpy_verw_s(_tmp_dhPublicKey, _len_dhPublicKey, _in_dhPublicKey, _len_dhPublicKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed) free(_in_sealed);
	if (_in_sealedLen) free(_in_sealedLen);
	if (_in_sealedcmackey) free(_in_sealedcmackey);
	if (_in_sealedcmackeylen) free(_in_sealedcmackeylen);
	if (_in_dhPublicKey) free(_in_dhPublicKey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_registeruser(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_registeruser_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_registeruser_t* ms = SGX_CAST(ms_enclave_registeruser_t*, pms);
	ms_enclave_registeruser_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_registeruser_t), ms, sizeof(ms_enclave_registeruser_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_password = __in_ms.ms_password;
	size_t _tmp_passwordlen = __in_ms.ms_passwordlen;
	size_t _len_password = _tmp_passwordlen;
	uint8_t* _in_password = NULL;
	uint8_t* _tmp_uid = __in_ms.ms_uid;
	size_t _len_uid = 8 * sizeof(uint8_t);
	uint8_t* _in_uid = NULL;
	uint8_t* _tmp_cmactag = __in_ms.ms_cmactag;
	size_t _len_cmactag = 16 * sizeof(uint8_t);
	uint8_t* _in_cmactag = NULL;
	uint8_t* _tmp_s = __in_ms.ms_s;
	size_t _len_s = 64 * sizeof(uint8_t);
	uint8_t* _in_s = NULL;
	uint8_t* _tmp_sharedkey = __in_ms.ms_sharedkey;
	size_t _len_sharedkey = 2048 * sizeof(uint8_t);
	uint8_t* _in_sharedkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_cmactag, _len_cmactag);
	CHECK_UNIQUE_POINTER(_tmp_s, _len_s);
	CHECK_UNIQUE_POINTER(_tmp_sharedkey, _len_sharedkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (uint8_t*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_uid != NULL && _len_uid != 0) {
		if ( _len_uid % sizeof(*_tmp_uid) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_uid = (uint8_t*)malloc(_len_uid)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_uid, 0, _len_uid);
	}
	if (_tmp_cmactag != NULL && _len_cmactag != 0) {
		if ( _len_cmactag % sizeof(*_tmp_cmactag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cmactag = (uint8_t*)malloc(_len_cmactag)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cmactag, 0, _len_cmactag);
	}
	if (_tmp_s != NULL && _len_s != 0) {
		if ( _len_s % sizeof(*_tmp_s) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_s = (uint8_t*)malloc(_len_s)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_s, 0, _len_s);
	}
	if (_tmp_sharedkey != NULL && _len_sharedkey != 0) {
		if ( _len_sharedkey % sizeof(*_tmp_sharedkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sharedkey = (uint8_t*)malloc(_len_sharedkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sharedkey, 0, _len_sharedkey);
	}
	enclave_registeruser(__in_ms.ms_context, _in_password, _tmp_passwordlen, _in_uid, _in_cmactag, _in_s, _in_sharedkey);
	if (_in_uid) {
		if (memcpy_verw_s(_tmp_uid, _len_uid, _in_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_cmactag) {
		if (memcpy_verw_s(_tmp_cmactag, _len_cmactag, _in_cmactag, _len_cmactag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_s) {
		if (memcpy_verw_s(_tmp_s, _len_s, _in_s, _len_s)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sharedkey) {
		if (memcpy_verw_s(_tmp_sharedkey, _len_sharedkey, _in_sharedkey, _len_sharedkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_password) free(_in_password);
	if (_in_uid) free(_in_uid);
	if (_in_cmactag) free(_in_cmactag);
	if (_in_s) free(_in_s);
	if (_in_sharedkey) free(_in_sharedkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_login(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_login_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_login_t* ms = SGX_CAST(ms_enclave_login_t*, pms);
	ms_enclave_login_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_login_t), ms, sizeof(ms_enclave_login_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_password = __in_ms.ms_password;
	size_t _tmp_passwordlen = __in_ms.ms_passwordlen;
	size_t _len_password = _tmp_passwordlen;
	uint8_t* _in_password = NULL;
	uint8_t* _tmp_uid = __in_ms.ms_uid;
	size_t _len_uid = 8 * sizeof(uint8_t);
	uint8_t* _in_uid = NULL;
	uint8_t* _tmp_cmactag = __in_ms.ms_cmactag;
	size_t _len_cmactag = 16 * sizeof(uint8_t);
	uint8_t* _in_cmactag = NULL;
	uint8_t* _tmp_cmacuisig = __in_ms.ms_cmacuisig;
	size_t _len_cmacuisig = 64 * sizeof(uint8_t);
	uint8_t* _in_cmacuisig = NULL;
	uint8_t* _tmp_ct = __in_ms.ms_ct;
	size_t _len_ct = 512 * sizeof(uint8_t);
	uint8_t* _in_ct = NULL;
	size_t* _tmp_authenticated = __in_ms.ms_authenticated;
	size_t _len_authenticated = sizeof(size_t);
	size_t* _in_authenticated = NULL;

	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_cmactag, _len_cmactag);
	CHECK_UNIQUE_POINTER(_tmp_cmacuisig, _len_cmacuisig);
	CHECK_UNIQUE_POINTER(_tmp_ct, _len_ct);
	CHECK_UNIQUE_POINTER(_tmp_authenticated, _len_authenticated);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (uint8_t*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_uid != NULL && _len_uid != 0) {
		if ( _len_uid % sizeof(*_tmp_uid) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_uid = (uint8_t*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cmactag != NULL && _len_cmactag != 0) {
		if ( _len_cmactag % sizeof(*_tmp_cmactag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cmactag = (uint8_t*)malloc(_len_cmactag);
		if (_in_cmactag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cmactag, _len_cmactag, _tmp_cmactag, _len_cmactag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cmacuisig != NULL && _len_cmacuisig != 0) {
		if ( _len_cmacuisig % sizeof(*_tmp_cmacuisig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cmacuisig = (uint8_t*)malloc(_len_cmacuisig);
		if (_in_cmacuisig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cmacuisig, _len_cmacuisig, _tmp_cmacuisig, _len_cmacuisig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ct != NULL && _len_ct != 0) {
		if ( _len_ct % sizeof(*_tmp_ct) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ct = (uint8_t*)malloc(_len_ct)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ct, 0, _len_ct);
	}
	if (_tmp_authenticated != NULL && _len_authenticated != 0) {
		if ( _len_authenticated % sizeof(*_tmp_authenticated) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_authenticated = (size_t*)malloc(_len_authenticated)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_authenticated, 0, _len_authenticated);
	}
	enclave_login(__in_ms.ms_context, _in_password, _tmp_passwordlen, _in_uid, _in_cmactag, _in_cmacuisig, _in_ct, _in_authenticated);
	if (_in_ct) {
		if (memcpy_verw_s(_tmp_ct, _len_ct, _in_ct, _len_ct)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_authenticated) {
		if (memcpy_verw_s(_tmp_authenticated, _len_authenticated, _in_authenticated, _len_authenticated)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_password) free(_in_password);
	if (_in_uid) free(_in_uid);
	if (_in_cmactag) free(_in_cmactag);
	if (_in_cmacuisig) free(_in_cmacuisig);
	if (_in_ct) free(_in_ct);
	if (_in_authenticated) free(_in_authenticated);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_signtransaction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_signtransaction_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_signtransaction_t* ms = SGX_CAST(ms_enclave_signtransaction_t*, pms);
	ms_enclave_signtransaction_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_signtransaction_t), ms, sizeof(ms_enclave_signtransaction_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_tansactiontext = __in_ms.ms_tansactiontext;
	size_t _tmp_transactiontextlen = __in_ms.ms_transactiontextlen;
	size_t _len_tansactiontext = _tmp_transactiontextlen;
	uint8_t* _in_tansactiontext = NULL;
	uint8_t* _tmp_browsersig = __in_ms.ms_browsersig;
	size_t _len_browsersig = 64 * sizeof(uint8_t);
	uint8_t* _in_browsersig = NULL;
	uint8_t* _tmp_uid = __in_ms.ms_uid;
	size_t _len_uid = 8 * sizeof(uint8_t);
	uint8_t* _in_uid = NULL;
	uint8_t* _tmp_esig = __in_ms.ms_esig;
	size_t _len_esig = 64 * sizeof(uint8_t);
	uint8_t* _in_esig = NULL;
	uint8_t* _tmp_pkt = __in_ms.ms_pkt;
	size_t _len_pkt = 64 * sizeof(uint8_t);
	uint8_t* _in_pkt = NULL;
	size_t* _tmp_retvalue = __in_ms.ms_retvalue;
	size_t _len_retvalue = sizeof(size_t);
	size_t* _in_retvalue = NULL;

	CHECK_UNIQUE_POINTER(_tmp_tansactiontext, _len_tansactiontext);
	CHECK_UNIQUE_POINTER(_tmp_browsersig, _len_browsersig);
	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_esig, _len_esig);
	CHECK_UNIQUE_POINTER(_tmp_pkt, _len_pkt);
	CHECK_UNIQUE_POINTER(_tmp_retvalue, _len_retvalue);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_tansactiontext != NULL && _len_tansactiontext != 0) {
		if ( _len_tansactiontext % sizeof(*_tmp_tansactiontext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tansactiontext = (uint8_t*)malloc(_len_tansactiontext);
		if (_in_tansactiontext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tansactiontext, _len_tansactiontext, _tmp_tansactiontext, _len_tansactiontext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_browsersig != NULL && _len_browsersig != 0) {
		if ( _len_browsersig % sizeof(*_tmp_browsersig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_browsersig = (uint8_t*)malloc(_len_browsersig);
		if (_in_browsersig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_browsersig, _len_browsersig, _tmp_browsersig, _len_browsersig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_uid != NULL && _len_uid != 0) {
		if ( _len_uid % sizeof(*_tmp_uid) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_uid = (uint8_t*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_esig != NULL && _len_esig != 0) {
		if ( _len_esig % sizeof(*_tmp_esig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_esig = (uint8_t*)malloc(_len_esig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_esig, 0, _len_esig);
	}
	if (_tmp_pkt != NULL && _len_pkt != 0) {
		if ( _len_pkt % sizeof(*_tmp_pkt) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pkt = (uint8_t*)malloc(_len_pkt)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pkt, 0, _len_pkt);
	}
	if (_tmp_retvalue != NULL && _len_retvalue != 0) {
		if ( _len_retvalue % sizeof(*_tmp_retvalue) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_retvalue = (size_t*)malloc(_len_retvalue)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_retvalue, 0, _len_retvalue);
	}
	enclave_signtransaction(__in_ms.ms_context, _in_tansactiontext, _tmp_transactiontextlen, _in_browsersig, _in_uid, _in_esig, _in_pkt, _in_retvalue);
	if (_in_esig) {
		if (memcpy_verw_s(_tmp_esig, _len_esig, _in_esig, _len_esig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pkt) {
		if (memcpy_verw_s(_tmp_pkt, _len_pkt, _in_pkt, _len_pkt)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_retvalue) {
		if (memcpy_verw_s(_tmp_retvalue, _len_retvalue, _in_retvalue, _len_retvalue)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_tansactiontext) free(_in_tansactiontext);
	if (_in_browsersig) free(_in_browsersig);
	if (_in_uid) free(_in_uid);
	if (_in_esig) free(_in_esig);
	if (_in_pkt) free(_in_pkt);
	if (_in_retvalue) free(_in_retvalue);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_init_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_init_ra_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_init_ra_t* ms = SGX_CAST(ms_ecall_enclave_init_ra_t*, pms);
	ms_ecall_enclave_init_ra_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_init_ra_t), ms, sizeof(ms_ecall_enclave_init_ra_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	nrt_ra_context_t* _tmp_context = __in_ms.ms_context;
	size_t _len_context = sizeof(nrt_ra_context_t);
	nrt_ra_context_t* _in_context = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_context, _len_context);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_context != NULL && _len_context != 0) {
		if ((_in_context = (nrt_ra_context_t*)malloc(_len_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_context, 0, _len_context);
	}
	_in_retval = ecall_enclave_init_ra(__in_ms.ms_b_pse, _in_context);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_context) {
		if (memcpy_verw_s(_tmp_context, _len_context, _in_context, _len_context)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_context) free(_in_context);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_close_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_close_ra_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_close_ra_t* ms = SGX_CAST(ms_ecall_enclave_close_ra_t*, pms);
	ms_ecall_enclave_close_ra_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_close_ra_t), ms, sizeof(ms_ecall_enclave_close_ra_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_enclave_close_ra(__in_ms.ms_context);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_nrt_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_nrt_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_nrt_ra_get_ga_t* ms = SGX_CAST(ms_nrt_ra_get_ga_t*, pms);
	ms_nrt_ra_get_ga_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_nrt_ra_get_ga_t), ms, sizeof(ms_nrt_ra_get_ga_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = __in_ms.ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	_in_retval = nrt_ra_get_ga(__in_ms.ms_context, _in_g_a);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_g_a) {
		if (memcpy_verw_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_nrt_ra_get_a(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_nrt_ra_get_a_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_nrt_ra_get_a_t* ms = SGX_CAST(ms_nrt_ra_get_a_t*, pms);
	ms_nrt_ra_get_a_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_nrt_ra_get_a_t), ms, sizeof(ms_nrt_ra_get_a_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_private_t* _tmp_a = __in_ms.ms_a;
	size_t _len_a = sizeof(sgx_ec256_private_t);
	sgx_ec256_private_t* _in_a = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_a != NULL && _len_a != 0) {
		if ((_in_a = (sgx_ec256_private_t*)malloc(_len_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_a, 0, _len_a);
	}
	_in_retval = nrt_ra_get_a(__in_ms.ms_context, _in_a);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_a) {
		if (memcpy_verw_s(_tmp_a, _len_a, _in_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_a) free(_in_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_nrt_ra_set_gb_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_nrt_ra_set_gb_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_nrt_ra_set_gb_trusted_t* ms = SGX_CAST(ms_nrt_ra_set_gb_trusted_t*, pms);
	ms_nrt_ra_set_gb_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_nrt_ra_set_gb_trusted_t), ms, sizeof(ms_nrt_ra_set_gb_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ec256_public_t* _tmp_g_b = __in_ms.ms_g_b;
	size_t _len_g_b = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_b = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_b, _len_g_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_b != NULL && _len_g_b != 0) {
		_in_g_b = (sgx_ec256_public_t*)malloc(_len_g_b);
		if (_in_g_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_g_b, _len_g_b, _tmp_g_b, _len_g_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = nrt_ra_set_gb_trusted(__in_ms.ms_context, (const sgx_ec256_public_t*)_in_g_b);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_g_b) free(_in_g_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_nrt_ra_create_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_nrt_ra_create_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_nrt_ra_create_report_t* ms = SGX_CAST(ms_nrt_ra_create_report_t*, pms);
	ms_nrt_ra_create_report_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_nrt_ra_create_report_t), ms, sizeof(ms_nrt_ra_create_report_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_target_info_t* _tmp_p_qe_target = __in_ms.ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = __in_ms.ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = __in_ms.ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	_in_retval = nrt_ra_create_report(__in_ms.ms_context, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_report) {
		if (memcpy_verw_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_verw_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_nrt_ra_get_quote_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_nrt_ra_get_quote_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_nrt_ra_get_quote_trusted_t* ms = SGX_CAST(ms_nrt_ra_get_quote_trusted_t*, pms);
	ms_nrt_ra_get_quote_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_nrt_ra_get_quote_trusted_t), ms, sizeof(ms_nrt_ra_get_quote_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = __in_ms.ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	nrt_ra_msg_quote_t* _tmp_p_msg_quote = __in_ms.ms_p_msg_quote;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = nrt_ra_get_quote_trusted(__in_ms.ms_context, __in_ms.ms_quote_size, _in_qe_report, _tmp_p_msg_quote, __in_ms.ms_msg_quote_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_enclave_init, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_registeruser, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_login, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_signtransaction, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_init_ra, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_close_ra, 0, 0},
		{(void*)(uintptr_t)sgx_nrt_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_nrt_ra_get_a, 0, 0},
		{(void*)(uintptr_t)sgx_nrt_ra_set_gb_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_nrt_ra_create_report, 0, 0},
		{(void*)(uintptr_t)sgx_nrt_ra_get_quote_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][11];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(uint32_t);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;

	CHECK_ENCLAVE_POINTER(sid, _len_sid);
	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sid != NULL) ? _len_sid : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg1 != NULL) ? _len_dh_msg1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));
	ocalloc_size -= sizeof(ms_create_session_ocall_t);

	if (sid != NULL) {
		if (memcpy_verw_s(&ms->ms_sid, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_sid = __tmp;
		if (_len_sid % sizeof(*sid) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
		ocalloc_size -= _len_sid;
	} else {
		ms->ms_sid = NULL;
	}

	if (dh_msg1 != NULL) {
		if (memcpy_verw_s(&ms->ms_dh_msg1, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dh_msg1 = __tmp;
		if (_len_dh_msg1 % sizeof(*dh_msg1) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dh_msg1_size, sizeof(ms->ms_dh_msg1_size), &dh_msg1_size, sizeof(dh_msg1_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (sid) {
			if (memcpy_s((void*)sid, _len_sid, __tmp_sid, _len_sid)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg2 != NULL) ? _len_dh_msg2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg3 != NULL) ? _len_dh_msg3 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	if (memcpy_verw_s(&ms->ms_sid, sizeof(ms->ms_sid), &sid, sizeof(sid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dh_msg2 != NULL) {
		if (memcpy_verw_s(&ms->ms_dh_msg2, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_dh_msg2 % sizeof(*dh_msg2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dh_msg2_size, sizeof(ms->ms_dh_msg2_size), &dh_msg2_size, sizeof(dh_msg2_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dh_msg3 != NULL) {
		if (memcpy_verw_s(&ms->ms_dh_msg3, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dh_msg3 = __tmp;
		if (_len_dh_msg3 % sizeof(*dh_msg3) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dh_msg3_size, sizeof(ms->ms_dh_msg3_size), &dh_msg3_size, sizeof(dh_msg3_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));
	ocalloc_size -= sizeof(ms_close_session_ocall_t);

	if (memcpy_verw_s(&ms->ms_sid, sizeof(ms->ms_sid), &sid, sizeof(sid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;

	CHECK_ENCLAVE_POINTER(pse_message_req, _len_pse_message_req);
	CHECK_ENCLAVE_POINTER(pse_message_resp, _len_pse_message_resp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pse_message_req != NULL) ? _len_pse_message_req : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pse_message_resp != NULL) ? _len_pse_message_resp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));
	ocalloc_size -= sizeof(ms_invoke_service_ocall_t);

	if (pse_message_req != NULL) {
		if (memcpy_verw_s(&ms->ms_pse_message_req, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pse_message_req % sizeof(*pse_message_req) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pse_message_req, _len_pse_message_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		ocalloc_size -= _len_pse_message_req;
	} else {
		ms->ms_pse_message_req = NULL;
	}

	if (memcpy_verw_s(&ms->ms_pse_message_req_size, sizeof(ms->ms_pse_message_req_size), &pse_message_req_size, sizeof(pse_message_req_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pse_message_resp != NULL) {
		if (memcpy_verw_s(&ms->ms_pse_message_resp, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_pse_message_resp = __tmp;
		if (_len_pse_message_resp % sizeof(*pse_message_resp) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		ocalloc_size -= _len_pse_message_resp;
	} else {
		ms->ms_pse_message_resp = NULL;
	}

	if (memcpy_verw_s(&ms->ms_pse_message_resp_size, sizeof(ms->ms_pse_message_resp_size), &pse_message_resp_size, sizeof(pse_message_resp_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (pse_message_resp) {
			if (memcpy_s((void*)pse_message_resp, _len_pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
