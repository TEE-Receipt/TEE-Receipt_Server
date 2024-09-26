#include<tchar.h>
#include<sgx_urts.h>
#include"Enclave_u.h"
#include"EnclaveLink.h"
#include"nrt_ukey_exchange.h"
#include"nrt_tke.h"
#include"sgx_uae_service.h"
#include<sgx_tcrypto.h>
#include"ra_quote.h"
#include <stdio.h>
static sgx_enclave_id_t global_eid = 0;
static nrt_ra_context_t global_cid = 0;
//35-8F-36-9B-79-04-F6-37-4E-66-1E-F9-13-6A-B8-E4 linkable
//25-5F-50-40-4E-9E-E1-8D-EE-80-03-C6-41-0A-AA-0C unlinkable 
static const sgx_spid_t g_spid = {
    0x35, 0x8F, 0x36, 0x9B,
    0x79, 0x04, 0xF6, 0x37,
    0x4E, 0x66, 0x1E, 0xF9,
    0x13, 0x6A, 0xB8, 0xE4
};
//static const sgx_spid_t g_spid = {
//    0x0C, 0xAA, 0x0A, 0x41,
//    0xC6, 0x03, 0x80, 0xEE,
//    0x8D, 0xE1, 0x9E, 0x4E,
//    0x40, 0x50, 0x5F, 0x25
//};
int hex2bytes(const unsigned char* hex, int len, unsigned char* res) {
    for (int i = 0; i < len / 2; i++) {
        sscanf_s((char*)(&(hex[i * 2])), "%2hhx", &(res[i]));
    }

    // Each 2 hex characters is one byte
    return len / 2;
}
int getpasswordinlittleendian(unsigned char* epassword, unsigned char* pass)
{
    int dehexed_len;

    int len = strlen((char*)epassword);
    pass = (unsigned char*)malloc(len);
    memset(pass, 0, len);

    // Multiply length by 2 because 2 hex characters are 1 byte
    if (len > 2 * 64) {
        dehexed_len = hex2bytes(epassword, len, pass);
        //memcpy(&(pass[dehexed_len]), &(password[len - SALT_LENGTH]), SALT_LENGTH);
        //len = dehexed_len + SALT_LENGTH;
        len = dehexed_len;

        // The key comes with both coordinates in big endian
        // Should be in little endian for lib_tke
        for (int i = 0; i < 64 / 4; i++) {
            uint8_t t;
            t = pass[dehexed_len - 64 + i];
            pass[dehexed_len - 64 + i] = pass[dehexed_len - 1 - 64 / 2 - i];
            pass[dehexed_len - 1 - 64 / 2 - i] = t;

            t = pass[dehexed_len - 64 / 2 + i];
            pass[dehexed_len - 64 / 2 + i] = pass[dehexed_len - 1 - i];
            pass[dehexed_len - 1 - i] = t;
        }
    }
    else {
        memcpy(pass, epassword, len);
    }
    return len;
}
bool EnclaveLink_CreateEnclave()
{
    int updated;
    sgx_launch_token_t token = { 0 };
    return sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL) == SGX_SUCCESS;
}

void EnclaveLink_DestroyEnclave()
{
    sgx_destroy_enclave(global_eid);
}

int EnclaveLink_EnclaveInit(unsigned char sealed[2048], unsigned char sealedcmackey[1024], unsigned int* sealedcmackeylen, unsigned char eccPublicKey[64])
{
    size_t sealedlen = 0;
    enclave_init(global_eid, (sgx_sealed_data_t*)sealed, 2048, &sealedlen, (sgx_sealed_data_t*)sealedcmackey, 1024, sealedcmackeylen, eccPublicKey);
    return sealedlen;
}

void EnclaveLink_EnclaveRegisterUser(unsigned char* password, unsigned int passwordlen, unsigned char uid[8], unsigned char cmactag[16], unsigned char s[64], unsigned char sharedkey[2048])
{

    enclave_registeruser(global_eid, global_cid, password, passwordlen, uid, cmactag, s, sharedkey);
    /* sgx_ec256_private_t a;
     sgx_status_t ret = SGX_SUCCESS;
     nrt_ra_get_a(global_eid, &ret, global_cid, &a);
     memcpy(sharedkey + 68, &a, 32);*/
}
int EnclaveLink_EnclaveLogin( unsigned char* password, unsigned int passwordlen, unsigned char uid[8], unsigned char cmactag[16], unsigned char cmacuisig[64],
    unsigned char ct[512])
{
    int retlen = 0;
    enclave_login(global_eid, global_cid, password, passwordlen, uid, cmactag, cmacuisig, ct, (unsigned int*)(&retlen));
    return retlen;
}

int EnclaveLink_EnclaveSignTransaction(unsigned char* tansactiontext, unsigned int transactiontextlen,
   unsigned char browsersig[64], unsigned char uid[8], unsigned char esig[64], unsigned char pkt[64])
{
    size_t retvalue = 0;
    enclave_signtransaction(global_eid, global_cid, tansactiontext, transactiontextlen, browsersig, uid, esig, pkt, &retvalue);
    return retvalue;
}


bool EnclaveLink_EnclaveInitRa()
{
    int status = SGX_SUCCESS;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    unsigned int enclave_lost_retry = 1;

    // Initialize the non-interactive remote attestion
    do {
        ret = ecall_enclave_init_ra(global_eid, &status, true, &global_cid);
    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry--);

    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        return false;
    }

    return true;
}
void EnclaveLink_EnclaveCloseRa()
{
    int status = SGX_SUCCESS;
    ecall_enclave_close_ra(global_eid, &status, global_cid);

}
int EnclaveLink_ObtainQoute(unsigned char quote[5000], unsigned char ecpk[64])
{
    //return 20;
    sgx_status_t status;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    unsigned int busy_retry = 5;

    sgx_target_info_t qe_target_info;

    sgx_ec256_public_t g_power_a;

    sgx_epid_group_id_t gid = { 0 };
    uint32_t extended_epid_group_id = 0;

    uint32_t msg_quote_size = 0;
    nrt_ra_msg_quote_t* p_msg_quote = NULL;


    // Preparation for obtaining the quote
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    gid[0] = extended_epid_group_id >> 24;
    gid[1] = (extended_epid_group_id & 0x00FF0000) >> 16;
    gid[2] = (extended_epid_group_id & 0x0000FF00) >> 8;
    gid[3] = (extended_epid_group_id & 0x000000FF);

    memset(&qe_target_info, 0, sizeof(qe_target_info));
    ret = sgx_init_quote(&qe_target_info, &gid);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    // Retrieve enclave's DH ephemeral public key
    memset(&g_power_a, 0, sizeof(g_power_a));

    ret = nrt_ra_get_ga(global_eid, &status, global_cid, &g_power_a);
    // If get_ga was already called, just ignore the returned error
    if ((ret != SGX_SUCCESS) && (ret != SGX_ERROR_INVALID_STATE)) {
        return ret;
    }
    if ((status != SGX_SUCCESS) && (status != SGX_ERROR_INVALID_STATE)) {
        return (sgx_status_t)status;
    }

    do {
        ret = nrt_ra_get_quote(global_cid, global_eid, &qe_target_info, &g_spid,
            nrt_ra_create_report, nrt_ra_get_quote_trusted,
            &p_msg_quote, &msg_quote_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry--);

    if (!p_msg_quote) {
        return SGX_ERROR_UNEXPECTED;
    }

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }
    memcpy(quote, (quote_t*)p_msg_quote->quote, msg_quote_size - 336);
    //memset(ecpk, 1, 64);
  

    memcpy(ecpk, &g_power_a, 64);
    return msg_quote_size - 336;
}