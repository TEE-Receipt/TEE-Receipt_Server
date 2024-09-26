#include "nrt_tke_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL nrt_tke_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nrt_tke_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[9];
} ocall_table_nrt_tke = {
	9,
	{
		(void*)(uintptr_t)nrt_tke_create_session_ocall,
		(void*)(uintptr_t)nrt_tke_exchange_report_ocall,
		(void*)(uintptr_t)nrt_tke_close_session_ocall,
		(void*)(uintptr_t)nrt_tke_invoke_service_ocall,
		(void*)(uintptr_t)nrt_tke_sgx_oc_cpuidex,
		(void*)(uintptr_t)nrt_tke_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)nrt_tke_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)nrt_tke_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)nrt_tke_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t nrt_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_nrt_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 0, &ocall_table_nrt_tke, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_get_a(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, sgx_ec256_private_t* a)
{
	sgx_status_t status;
	ms_nrt_ra_get_a_t ms;
	ms.ms_context = context;
	ms.ms_a = a;
	status = sgx_ecall(eid, 1, &ocall_table_nrt_tke, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nrt_ra_set_gb_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, const sgx_ec256_public_t* g_b)
{
	sgx_status_t status;
	ms_nrt_ra_set_gb_trusted_t ms;
	ms.ms_context = context;
	ms.ms_g_b = g_b;
	status = sgx_ecall(eid, 2, &ocall_table_nrt_tke, &ms);
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
	status = sgx_ecall(eid, 3, &ocall_table_nrt_tke, &ms);
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
	status = sgx_ecall(eid, 4, &ocall_table_nrt_tke, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

