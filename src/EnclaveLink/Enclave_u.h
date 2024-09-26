#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "stddef.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "nrt_key_exchange.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CREATE_SESSION_OCALL_DEFINED__
#define CREATE_SESSION_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
#endif
#ifndef EXCHANGE_REPORT_OCALL_DEFINED__
#define EXCHANGE_REPORT_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
#endif
#ifndef CLOSE_SESSION_OCALL_DEFINED__
#define CLOSE_SESSION_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
#endif
#ifndef INVOKE_SERVICE_OCALL_DEFINED__
#define INVOKE_SERVICE_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_sealed_data_t* sealed, size_t sealedSize, size_t* sealedLen, sgx_sealed_data_t* sealedcmackey, size_t cmackeysize, size_t* sealedcmackeylen, uint8_t dhPublicKey[64]);
sgx_status_t enclave_registeruser(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t s[64], uint8_t sharedkey[2048]);
sgx_status_t enclave_login(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t cmacuisig[64], uint8_t ct[512], size_t* authenticated);
sgx_status_t enclave_signtransaction(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* tansactiontext, size_t transactiontextlen, uint8_t browsersig[64], uint8_t uid[8], uint8_t esig[64], uint8_t pkt[64], size_t* retvalue);
sgx_status_t ecall_enclave_init_ra(sgx_enclave_id_t eid, int* retval, int b_pse, nrt_ra_context_t* context);
sgx_status_t ecall_enclave_close_ra(sgx_enclave_id_t eid, int* retval, nrt_ra_context_t context);
sgx_status_t nrt_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t nrt_ra_get_a(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, sgx_ec256_private_t* a);
sgx_status_t nrt_ra_set_gb_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, const sgx_ec256_public_t* g_b);
sgx_status_t nrt_ra_create_report(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t nrt_ra_get_quote_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, nrt_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, nrt_ra_msg_quote_t* p_msg_quote, uint32_t msg_quote_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
