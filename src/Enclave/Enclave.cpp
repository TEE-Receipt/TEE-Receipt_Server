#include "Enclave_t.h"
#include <stdio.h>
#include <stdarg.h>
#include<cstring>
#include<vector>
#include<map>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
//#include "mbedtls/bignum.h"
//#include "mbedtls/ecdsa.h"
//#include "mbedtls/ecdh.h"
#include<string.h>
#include"nrt_tke.h"
//#include"glue.h"
#define SALT_LENGTH 8
typedef std::string pswd_salt_t;

bool initialzed = false;
std::map<std::string, std::string> uidpkimap;
sgx_ec256_private_t eccprivateKey;
sgx_cmac_128bit_key_t cmackey;
void foo(char* buf, size_t len)
{
	const char* secret = "Hello world!";
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
}
bool matchedArrays(uint8_t* cmac1, uint8_t* cmac2, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (cmac1[i] != cmac2[i])
			return false;
	}
	return true;
}
int serializeuidpktmap(std::map<std::string, std::string> uidpktmap, uint8_t* buf, uint32_t* buf_len)
{
	const uint32_t required_len = 72 * uidpktmap.size();

	if (buf == NULL) {
		*buf_len = required_len;
		buf = (uint8_t*)malloc(required_len);
	}

	if (*buf_len < required_len)
		return SGX_ERROR_INVALID_PARAMETER;

	memset(buf, 0, *buf_len);
	uint32_t buf_pos = 0;
	int c = 0;
	for (std::map<std::string, std::string>::iterator it = uidpktmap.begin();
		it != uidpktmap.end(), buf_pos < *buf_len;
		++it, buf_pos += 72) {

		std::string uid = it->first;
		std::string pkt = it->second;
		const char* c_uid = uid.c_str();
		const char* c_pkt = pkt.c_str();
		memcpy(&buf[buf_pos], uid.c_str(), strlen(c_uid));
		memcpy(&buf[buf_pos + 8], pkt.c_str(), strlen(c_pkt));
		c++;
	}
	return c + 3;
}

// Deserialization of internal state
std::map<std::string, std::string> deserializeuidpktmap(uint8_t* buf, uint32_t buf_len)
{
	std::map<std::string, std::string> uidpktmap;
	std::string uid;
	std::string pkt;
	if (buf_len >= 72)
	{
		for (uint32_t buf_pos = 0; buf_pos < buf_len;
			buf_pos += 72) {

			uid.assign((char*)(buf + buf_pos), 8);
			pkt.assign((char*)(buf + buf_pos + 8), 64);
			uidpktmap[uid] = pkt;

		}
	}
	return uidpktmap;
}
sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
	uint16_t kdf_id,
	sgx_ec_key_128bit_t* smk_key,
	sgx_ec_key_128bit_t* sk_key,
	sgx_ec_key_128bit_t* mk_key,
	sgx_ec_key_128bit_t* vk_key)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_sha_state_handle_t sha_context;
	sgx_sha256_hash_t key_material;
	const char* hex = "0123456789abcdef";
	uint8_t hash_buffer[2 * sizeof(sgx_ec256_dh_shared_t)];

	if (NULL == shared_key)
		return SGX_ERROR_INVALID_PARAMETER;

	for (int i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++) {
		hash_buffer[2 * i] = hex[shared_key->s[i] / 16];
		hash_buffer[2 * i + 1] = hex[shared_key->s[i] % 16];
	}
	// memcpy(hash_buffer, shared_key, sizeof(sgx_ec256_dh_shared_t));

	sgx_ret = sgx_sha256_init(&sha_context);
	if (sgx_ret != SGX_SUCCESS)
		return sgx_ret;

	sgx_ret = sgx_sha256_update(hash_buffer, sizeof(hash_buffer), sha_context);
	if (sgx_ret != SGX_SUCCESS) {
		sgx_sha256_close(sha_context);
		return sgx_ret;
	}

	sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
	if (sgx_ret != SGX_SUCCESS) {
		sgx_sha256_close(sha_context);
		return sgx_ret;
	}
	sgx_sha256_close(sha_context);

	memcpy(sk_key, key_material, sizeof(sgx_ec_key_128bit_t));
	memset(key_material, 0, sizeof(sgx_sha256_hash_t));
	//memcpy(sk_key,shared_key->s, sizeof(sgx_ec_key_128bit_t));
	return SGX_SUCCESS;
}
void enclave_init(sgx_sealed_data_t* sealedSigningKey, size_t sealedSigningkeySize, size_t* sealedLen, sgx_sealed_data_t* sealedcmackey, size_t cmackeysize, size_t* sealedcmackeylen, uint8_t eccPublicKey[64])
{
	if (!initialzed)
	{
		sgx_ecc_state_handle_t ecc;
		sgx_ec256_public_t tmpeccpublickey;

		//set cmackey value
		sgx_read_rand(cmackey, sizeof(sgx_cmac_128bit_key_t));
		//open ecc context
		sgx_ecc256_open_context(&ecc);
		//generate ec key pair(sk,pk)
		sgx_ecc256_create_key_pair(&eccprivateKey, &tmpeccpublickey, ecc);
		//you have to close the context to release the allocated memory
		sgx_ecc256_close_context(ecc);

		//sealing the private key
		*sealedLen = sgx_calc_sealed_data_size(0, sizeof(eccprivateKey.r));
		sgx_sealed_data_t* sealedBuffer = (sgx_sealed_data_t*)malloc(*sealedLen);
		sgx_seal_data(0, NULL, sizeof(eccprivateKey.r), eccprivateKey.r, *sealedLen, sealedBuffer);
		// copy the sealed to the out sealed array
		memcpy(sealedSigningKey, sealedBuffer, *sealedLen);
		//Sealing the cmackey
		*sealedcmackeylen = sgx_calc_sealed_data_size(0, sizeof(cmackey));
		sgx_sealed_data_t* sealedBuffer2 = (sgx_sealed_data_t*)malloc(*sealedcmackeylen);
		sgx_seal_data(0, NULL, sizeof(cmackey), cmackey, *sealedcmackeylen, sealedBuffer2);
		memcpy(sealedcmackey, sealedBuffer2, *sealedcmackeylen);
		//copy the public key point (x and y) to the output eccPublicKey array
		memcpy(eccPublicKey, tmpeccpublickey.gx, 32);
		memcpy(&eccPublicKey[32], tmpeccpublickey.gy, 32);

		free(sealedBuffer);
		//free(sealedBuffer2);
	}
}

void enclave_registeruser(nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t  s[64], uint8_t sharedkey[2048])
{
	sgx_ecc_state_handle_t eccntxt;
	sgx_ra_key_128_t sk_key;
    size_t ret = nrt_ra_set_gb_trusted(context, (sgx_ec256_public_t*)(&password[passwordlen - 64]));

	if (ret != SGX_SUCCESS)
		return;

	nrt_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
	passwordlen -= 64;
	//decrypt the password
	uint8_t* pass;
	pass = (uint8_t*)malloc(passwordlen);
	memcpy(pass, password, passwordlen);
	uint8_t aes_ctr[16] = { 0 };
	aes_ctr[15] = 1;
	size_t ret4 = sgx_aes_ctr_decrypt(&sk_key, (const uint8_t*)password, passwordlen, aes_ctr, 128, pass);
	//select random UID
	sgx_read_rand(uid, 8);
	//CMAC both the password and the UID
	uint8_t* passuid;
	passuid = (uint8_t*)malloc(passwordlen + 8);
	memcpy(passuid, pass, passwordlen);
	memcpy(passuid + passwordlen, uid, 8);
	//compute the cmac for the password+UID

	sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t*)(&cmackey), passuid, passwordlen + 8, (sgx_cmac_128bit_tag_t*)cmactag);
	//sign cmac|uid

	//memcpy(sharedkey, &sk_key, 16);
	//deallocate pass
	free(pass);
	free(passuid);
}

void enclave_login(nrt_ra_context_t context, uint8_t* password, size_t passwordlen, uint8_t uid[8], uint8_t cmactag[16], uint8_t cmacuisig[64], uint8_t ct[512], size_t* authenticated)
{
	sgx_status_t ret = SGX_SUCCESS;
	*authenticated = 0;
	sgx_ecc_state_handle_t eccntxt;
    sgx_ra_key_128_t sk_key;
    ret = nrt_ra_set_gb_trusted(context, (sgx_ec256_public_t*)(&password[passwordlen - 64]));
	if (ret != SGX_SUCCESS)
		return;
	ret = nrt_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
	if (ret != SGX_SUCCESS)
		return;
	passwordlen -= 64;
	uint8_t* pass;
	pass = (uint8_t*)malloc(passwordlen);
	memcpy(pass, password, passwordlen);
	uint8_t aes_ctr[16] = { 0 };
	aes_ctr[15] = 1;
	sgx_aes_ctr_decrypt(&sk_key, (const uint8_t*)password, passwordlen,
		aes_ctr, 128, pass);
	uint8_t newcmactag[16];
	
	uint8_t* passuid;
	passuid = (uint8_t*)malloc(passwordlen + 8);
	memcpy(passuid, pass, passwordlen);
	memcpy(passuid + passwordlen, uid, 8);
	//compute the cmac for the password+uid
	sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t*)(&cmackey), passuid, passwordlen + 8, (sgx_cmac_128bit_tag_t*)newcmactag);
	if (matchedArrays(cmactag, newcmactag, 16))
	{
		//generate temporary signing key pair
		sgx_ec256_private_t tsk;
		sgx_ec256_public_t tvk;
		sgx_ecc256_open_context(&eccntxt);
		sgx_ecc256_create_key_pair(&tsk, &tvk, eccntxt);
		sgx_ecc256_close_context(eccntxt);
		uint8_t aes_ctr2[16] = { 0 };
		aes_ctr2[15] = 1;
		sgx_aes_ctr_encrypt(&sk_key, (const uint8_t*)&tsk.r, 32, aes_ctr2, 128, ct);
		std::string uidstr;
		std::string pktstr;
		uidstr.assign((char*)uid, 8);
		pktstr.assign((char*)&tvk, 64);
		uidpkimap[uidstr] = pktstr;
		*authenticated = 1;
	}
	free(pass);
	free(passuid);


}

void enclave_signtransaction(nrt_ra_context_t context, uint8_t* tansactiontext, size_t transactiontextlen, uint8_t browsersig[64], uint8_t uid[8], uint8_t esig[64], uint8_t pkt[64], size_t* retvalue)
{
	std::string uidstr;
	uidstr.assign((char*)uid, 8);
	std::map<std::string, std::string>::iterator it = uidpkimap.find(uidstr);
	*retvalue = 3;
	if (it != uidpkimap.end())
	{
		uint8_t vkt[64];
		memcpy(vkt, it->second.c_str(), 64);
		sgx_ecc_state_handle_t eccntxt;
		sgx_ecc256_open_context(&eccntxt);
		uint8_t result;
		sgx_ecdsa_verify(tansactiontext, transactiontextlen, (sgx_ec256_public_t*)(&vkt), (sgx_ec256_signature_t*)browsersig, &result, eccntxt);
		sgx_ecc256_close_context(eccntxt);
		if (result == SGX_EC_VALID)
		{
			sgx_ecc256_open_context(&eccntxt);
			uint8_t* translog;
			translog = (uint8_t*)malloc(transactiontextlen + 72);
			memcpy(translog, uid, 8);
			memcpy(translog + 8, vkt, 64);
			memcpy(translog + 72, tansactiontext, transactiontextlen);
			sgx_ec256_signature_t sig;
			sgx_ecdsa_sign(translog, transactiontextlen + 72, &eccprivateKey, &sig, eccntxt);
			sgx_ecc256_close_context(eccntxt);
			memcpy(esig, &sig, 64);
			memcpy(pkt, vkt, 64);
			free(translog);
			*retvalue = 16;
		}
	}
}

int ecall_enclave_init_ra(int b_pse, nrt_ra_context_t* p_context)
{
	sgx_status_t ret;
	if (b_pse) {
		int busy_retry = 2;
		do {
			ret = sgx_create_pse_session();
		} while (ret == SGX_ERROR_BUSY && busy_retry--);

		if (ret != SGX_SUCCESS)
			return ret;
	}
	ret = nrt_ra_init_ex(b_pse, key_derivation, p_context);
	//ret = nrt_ra_init_ex(b_pse, NULL, p_context);
	if (b_pse) {
		sgx_close_pse_session();
	}
	return ret;
}

int ecall_enclave_close_ra(nrt_ra_context_t context)
{
	sgx_status_t ret;
	ret = nrt_ra_close(context);
	return ret;
}