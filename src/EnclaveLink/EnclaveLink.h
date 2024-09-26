#pragma once
#define ENCLAVE_FILENAME _T("Enclave.signed.dll")

extern "C"
{
	__declspec(dllexport) bool EnclaveLink_CreateEnclave();
	__declspec(dllexport) void EnclaveLink_DestroyEnclave();
	__declspec(dllexport) int EnclaveLink_EnclaveInit(unsigned char sealed[2048], unsigned char sealedcmackey[1024], unsigned int* sealedcmackeylen, unsigned char eccPublicKey[64]);
	__declspec(dllexport) void EnclaveLink_EnclaveRegisterUser(unsigned char* password, unsigned int passwordlen, unsigned char uid[8], unsigned char cmactag[16], unsigned char s[64], unsigned char sharedkey[2048]);
	__declspec(dllexport) int EnclaveLink_EnclaveLogin(unsigned char* password, unsigned int passwordlen, unsigned char uid[8], unsigned char cmactag[16], unsigned char cmacuisig[64],
		unsigned char ct[512]);
	__declspec(dllexport) int EnclaveLink_EnclaveSignTransaction(unsigned char* tansactiontext, unsigned int transactiontextlen, unsigned char browsersig[64], unsigned char uid[8], unsigned char esig[64], unsigned char pkt[64]);
	__declspec(dllexport) bool EnclaveLink_EnclaveInitRa();
	__declspec(dllexport) void EnclaveLink_EnclaveCloseRa();
	__declspec(dllexport) int EnclaveLink_ObtainQoute(unsigned char qoute[5000], unsigned char ecpk[64]);
}