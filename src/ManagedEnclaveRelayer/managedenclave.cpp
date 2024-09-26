#using<System.dll>
using namespace std;

extern "C"
{
	__declspec(dllimport) bool EnclaveLink_CreateEnclave();
	__declspec(dllimport) void EnclaveLink_DestroyEnclave();
	__declspec(dllimport) int EnclaveLink_EnclaveInit(unsigned char sealed[2048], unsigned char sealedcmackey[1024], unsigned int* sealedcmackeylen, unsigned char eccPublicKey[64]);
	__declspec(dllimport) void EnclaveLink_EnclaveRegisterUser(unsigned char* password,
		unsigned int passwordlen, unsigned char uid[8], unsigned char cmactag[16], unsigned char s[64], unsigned char sharedkey[2048]);
	__declspec(dllimport) int EnclaveLink_EnclaveLogin(unsigned char* password, unsigned int passwordlen, unsigned char uid[8], unsigned char cmactag[16], unsigned char cmacuisig[64],
		unsigned char ct[512]);
	__declspec(dllimport) int EnclaveLink_EnclaveSignTransaction(unsigned char* tansactiontext, unsigned int transactiontextlen, unsigned char browsersig[64], unsigned char uid[8], unsigned char esig[64], unsigned char pkt[64]);
	__declspec(dllimport) bool EnclaveLink_EnclaveInitRa();
	__declspec(dllimport) void EnclaveLink_EnclaveCloseRa();
	__declspec(dllimport) int EnclaveLink_ObtainQoute(unsigned char qoute[5000], unsigned char ecpk[64]);
};

public ref class ManagedEnclave
{
public:
	ManagedEnclave()
	{
		bool flag = EnclaveLink_CreateEnclave();
		bool flag2 = EnclaveLink_EnclaveInitRa();
	}
	~ManagedEnclave()
	{
		EnclaveLink_EnclaveCloseRa();
		EnclaveLink_DestroyEnclave();
	}

	void SGX_Foo(array<char>^% buf, int len)
	{
		pin_ptr<char> pbuf = &buf[0];
	}

	int SGX_EnclaveInit(array<unsigned char>^% sealed, array<unsigned char>^% sealedcmackey, unsigned int% sealedcmackeylen, array<unsigned char>^% eccPublicKey)
	{
		pin_ptr<unsigned char> pSealed = &sealed[0];
		pin_ptr<unsigned char> pECCPublicKey = &eccPublicKey[0];
		pin_ptr<unsigned char> pSealedCMACKey = &sealedcmackey[0];
		pin_ptr<unsigned int> pSealedCMACKeyLen = &sealedcmackeylen;
		return EnclaveLink_EnclaveInit(pSealed, pSealedCMACKey, pSealedCMACKeyLen, pECCPublicKey);
	}
	void SGX_EnclaveRegisterUser(array<unsigned char>^% password,
		unsigned int passwordlen, array<unsigned char>^% uid, array<unsigned char>^% cmactag, array<unsigned char>^% s, array<unsigned char>^% sharedkey)
	{
		pin_ptr<unsigned char> pPassword = &password[0];
		pin_ptr<unsigned char> pUID = &uid[0];
		pin_ptr<unsigned char> pCMACTag = &cmactag[0];
		pin_ptr<unsigned char> pS = &s[0];
		pin_ptr<unsigned char> pSharedKey = &sharedkey[0];
		EnclaveLink_EnclaveRegisterUser(pPassword, passwordlen, pUID, pCMACTag, pS, pSharedKey);
	}
	int SGX_EnclaveLogin(array<unsigned char>^% password, unsigned int passwordlen, array<unsigned char>^% uid, array<unsigned char>^% cmactag, array<unsigned char>^% cmacuisig,
		array<unsigned char>^% ct)
	{
		pin_ptr<unsigned char> pPassword = &password[0];
		pin_ptr<unsigned char> pUID = &uid[0];
		pin_ptr<unsigned char> pCMACTag = &cmactag[0];
		pin_ptr<unsigned char> pCMACUISig = &cmacuisig[0];
		pin_ptr<unsigned char> pCt = &ct[0];
		return EnclaveLink_EnclaveLogin(pPassword, passwordlen, pUID, pCMACTag, pCMACUISig, pCt);
	}
	int SGX_EnclaveSignTransaction(array<unsigned char>^% tansactiontext, unsigned int transactiontextlen, array<unsigned char>^% browsersig, array<unsigned char>^% uid, array<unsigned char>^% esig, array<unsigned char>^% pkt)
	{
		pin_ptr<unsigned char> pTransactionText = &tansactiontext[0];
		pin_ptr<unsigned char> pUID = &uid[0];
		pin_ptr<unsigned char> pBrowserSig = &browsersig[0];
		pin_ptr<unsigned char> pESig = &esig[0];
		pin_ptr<unsigned char> pPkt = &pkt[0];
		return EnclaveLink_EnclaveSignTransaction(pTransactionText, transactiontextlen, pBrowserSig, pUID, pESig, pPkt);
	}
	bool SGX_EnclaveInitRA()
	{
		return EnclaveLink_EnclaveInitRa();
	}
	void SGX_EnclaveCloseRA()
	{
		EnclaveLink_EnclaveCloseRa();
	}
	int SGX_ObtainQuote(array<unsigned char>^% quote, array<unsigned char>^% ecpk)
	{
		pin_ptr<unsigned char> pQuote = &quote[0];
		pin_ptr<unsigned char> pEcpk = &ecpk[0];
		ecpk[0] = 1;
		ecpk[1] = 1;
		ecpk[2] = 1;
		ecpk[3] = 1;
		ecpk[4] = 1;
		return EnclaveLink_ObtainQoute(pQuote, pEcpk);
	}

};
