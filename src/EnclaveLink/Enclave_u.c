#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[9];
} ocall_table_Enclave = {
	9,
	{
		(void*)(uintptr_t)Enclave_create_session_ocall,
		(void*)(uintptr_t)Enclave_exchange_report_ocall,
		(void*)(uintptr_t)Enclave_close_session_ocall,
		(void*)(uintptr_t)Enclave_invoke_service_ocall,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_sealed_data_t* sealed, size_t sealedSize, size_t* sealedLen, sgx_sealed_data_t* sealedcmackey, size_t cmackeysize, size_t* sealedcmackeylen, uint8_t dhPublicKey[64])
{
	sgx_status_t status;
	ms_enclave_init_t ms;
	ms.ms_sealed = sealed;
	ms.ms_sealedSize = sealedSize;
	ms.ms_sealedLen = sealedLen;
	ms.ms_sealedcmackey = sealedcmackey;
	ms.ms_cmackeysize = cmackeysize;
	ms.ms_sealedcmackeylen = sealedcmackeylen;
	ms.ms_dhPublicKey = (uint8_t*)dhPublicKey;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclave_registeruser(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t s[64], uint8_t sharedkey[2048])
{
	sgx_status_t status;
	ms_enclave_registeruser_t ms;
	ms.ms_context = context;
	ms.ms_password = password;
	ms.ms_passwordlen = passwordlen;
	ms.ms_uid = (uint8_t*)uid;
	ms.ms_cmactag = (uint8_t*)cmactag;
	ms.ms_s = (uint8_t*)s;
	ms.ms_sharedkey = (uint8_t*)sharedkey;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclave_login(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t cmacuisig[64], uint8_t ct[512], size_t* authenticated)
{
	sgx_status_t status;
	ms_enclave_login_t ms;
	ms.ms_context = context;
	ms.ms_password = password;
	ms.ms_passwordlen = passwordlen;
	ms.ms_uid = (uint8_t*)uid;
	ms.ms_cmactag = (uint8_t*)cmactag;
	ms.ms_cmacuisig = (uint8_t*)cmacuisig;
	ms.ms_ct = (uint8_t*)ct;
	ms.ms_authenticated = authenticated;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclave_signtransaction(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* tansactiontext, size_t transactiontextlen, uint8_t browsersig[64], uint8_t uid[8], uint8_t esig[64], uint8_t pkt[64], size_t* retvalue)
{
	sgx_status_t status;
	ms_enclave_signtransaction_t ms;
	ms.ms_context = context;
	ms.ms_tansactiontext = tansactiontext;
	ms.ms_transactiontextlen = transactiontextlen;
	ms.ms_browsersig = (uint8_t*)browsersig;
	ms.ms_uid = (uint8_t*)uid;
	ms.ms_esig = (uint8_t*)esig;
	ms.ms_pkt = (uint8_t*)pkt;
	ms.ms_retvalue = retvalue;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_enclave_init_ra(sgx_enclave_id_t eid, int* retval, int b_pse, nrt_ra_context_t* context)
{
	sgx_status_t status;
	ms_ecall_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_context = context;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_close_ra(sgx_enclave_id_t eid, int* retval, nrt_ra_context_t context)
{
	sgx_status_t status;
	ms_ecall_enclave_close_ra_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_nrt_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_get_a(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, sgx_ec256_private_t* a)
{
	sgx_status_t status;
	ms_nrt_ra_get_a_t ms;
	ms.ms_context = context;
	ms.ms_a = a;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_set_gb_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, const sgx_ec256_public_t* g_b)
{
	sgx_status_t status;
	ms_nrt_ra_set_gb_trusted_t ms;
	ms.ms_context = context;
	ms.ms_g_b = g_b;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_create_report(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_nrt_ra_create_report_t ms;
	ms.ms_context = context;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_get_quote_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, nrt_ra_msg_quote_t* p_msg_quote, uint32_t msg_quote_size)
{
	sgx_status_t status;
	ms_nrt_ra_get_quote_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg_quote = p_msg_quote;
	ms.ms_msg_quote_size = msg_quote_size;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

