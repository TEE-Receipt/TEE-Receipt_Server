#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_report.h"
#include "stddef.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "nrt_key_exchange.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void enclave_init(sgx_sealed_data_t* sealed, size_t sealedSize, size_t* sealedLen, sgx_sealed_data_t* sealedcmackey, size_t cmackeysize, size_t* sealedcmackeylen, uint8_t dhPublicKey[64]);
void enclave_registeruser(nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t s[64], uint8_t sharedkey[2048]);
void enclave_login(nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t cmacuisig[64], uint8_t ct[512], size_t* authenticated);
void enclave_signtransaction(nrt_ra_context_t context, uint8_t* tansactiontext, size_t transactiontextlen, uint8_t browsersig[64], uint8_t uid[8], uint8_t esig[64], uint8_t pkt[64], size_t* retvalue);
int ecall_enclave_init_ra(int b_pse, nrt_ra_context_t* context);
int ecall_enclave_close_ra(nrt_ra_context_t context);
sgx_status_t nrt_ra_get_ga(nrt_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t nrt_ra_get_a(nrt_ra_context_t context, sgx_ec256_private_t* a);
sgx_status_t nrt_ra_set_gb_trusted(nrt_ra_context_t context, const sgx_ec256_public_t* g_b);
sgx_status_t nrt_ra_create_report(nrt_ra_context_t context, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t nrt_ra_get_quote_trusted(nrt_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, nrt_ra_msg_quote_t* p_msg_quote, uint32_t msg_quote_size);

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
