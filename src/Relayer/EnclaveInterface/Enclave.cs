using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IO;
using System.Diagnostics;
using System.Text;

namespace Relayer.EnclaveInterface
{
    public static class Enclave
    {
        private static ManagedEnclave sgx;
        private static byte[] _sealedSecret = new byte[2048], _sealedCMACKey = new byte[1024], _ECCPublicKey = new byte[64], _sealedUIDMap = new byte[72];


        public static byte[] ECCPublicKey { get { return _ECCPublicKey; } }
        private static int _numberofiterations = 100000;
        private static string _metricsoutpath = "test\\";
        public static void InitializeEnclave()
        {
            if (sgx == null)
                sgx = new ManagedEnclave();

            UInt32 sealedcmackeylen = 0;
            int n = sgx.SGX_EnclaveInit(ref _sealedSecret, ref _sealedCMACKey, ref sealedcmackeylen, ref _ECCPublicKey);
            Array.Resize(ref _sealedSecret, n);
            String EccPKey = "0X" + BitConverter.ToString(_ECCPublicKey).Replace("-", "");
            String SealedPKey = "0X" + BitConverter.ToString(_sealedSecret).Replace("-", "");
            byte[] inituidpkt = new byte[72];
            if (n != 0)
            {
                File.WriteAllBytes("ECCPublicKey", _ECCPublicKey);
                File.WriteAllBytes("sealedsigningkey", _sealedSecret);
                File.WriteAllBytes("sealeduidpktmap", inituidpkt);
                if (sealedcmackeylen != 0)
                    File.WriteAllBytes("sealedcmackey", _sealedCMACKey);
            }

        }
        public static void RegisterUser(String password, ref byte[] uid, ref byte[] cmactag, ref byte[] s)
        {
            if (sgx == null)
                sgx = new ManagedEnclave();


            byte[] passwordbytes = GetPasswordBytes(password);
            byte[] sharedkey = new byte[2048];

            sgx.SGX_EnclaveRegisterUser(ref passwordbytes, (uint)passwordbytes.Length, ref uid, ref cmactag, ref s, ref sharedkey);

         }
       
        public static bool Login(byte[] uid, String password, byte[] cmactag, byte[] s, ref byte[] ct)
        {
            if (sgx == null)
                sgx = new ManagedEnclave();

            byte[] Passwordbytes = GetPasswordBytes(password);
            int n = 0;
            n = sgx.SGX_EnclaveLogin(ref Passwordbytes, (uint)Passwordbytes.Length, ref uid, ref cmactag, ref s, ref ct);

            if (n > 0)
            {
                return true;
            }
            return false;
        }
        public static void SignTransaction(byte[] uid, String transactiontext, String bsignature, ref byte[] enclavesig, ref byte[] vkt)
        {
            if (sgx == null)
                sgx = new ManagedEnclave();
            byte[] browsersig = HexaStringToBytes(bsignature,0, 64);
            byte[] transastiontextbytes = Encoding.ASCII.GetBytes(transactiontext);
            //convert browsersig from bigend to littleend
            BigLittleConversion(ref browsersig, 2);

            int n = sgx.SGX_EnclaveSignTransaction(ref transastiontextbytes, (uint)transastiontextbytes.Length, ref browsersig, ref uid, ref enclavesig, ref vkt);
        }

        public static void BigLittleConversion(ref byte[] arr, int n)
        {
            if (arr.Length % n != 0)
                return;
            for (int i = 0; i < n; i++)
            {
                byte[] t = new byte[arr.Length / n];
                Array.Copy(arr, i * t.Length, t, 0, t.Length);
                Array.Reverse(t);
                Array.Copy(t, 0, arr, i * t.Length, t.Length);
            }
        }
        public static byte[] GetPublicKey()
        {
            return File.ReadAllBytes("ECCPublicKey");
        }

       
        public static byte[] GetPasswordBytes(String s)
        {
            byte[] sbytes = new byte[s.Length / 2];
            for (int i = 0; i < sbytes.Length; i++)
            {
                sbytes[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            }
            byte[] pk_x = new byte[32];
            byte[] pk_y = new byte[32];
            Array.Copy(sbytes, sbytes.Length - 64, pk_x, 0, 32);
            Array.Copy(sbytes, sbytes.Length - 32, pk_y, 0, 32);
            Array.Reverse(pk_x);
            Array.Reverse(pk_y);
            Array.Copy(pk_x, 0, sbytes, sbytes.Length - 64, 32);
            Array.Copy(pk_y, 0, sbytes, sbytes.Length - 32, 32);

            return sbytes;
        }
        public static byte[] GetQuote(ref byte[] ecpk)
        {
            if (sgx == null)
                sgx = new ManagedEnclave();
            byte[] quote = new byte[5000];
            int n = sgx.SGX_ObtainQuote(ref quote, ref ecpk);
            Array.Resize(ref quote, n);
            return quote;
        }
        private static byte[] HexaStringToBytes(String s)
        {
            byte[] decimalBytes = new byte[s.Length / 2];
            for (int i = 0; i < decimalBytes.Length; i++)
            {
                decimalBytes[i] = Convert.ToByte(s.Substring(2 * i, 2), 16);
            }

            return decimalBytes;
        }
        public static byte[] HexaStringToBytes(String s, int fromindex, int len)
        {
            if (len > s.Length / 2 - fromindex)
                len = s.Length / 2 - fromindex;

            byte[] decimalBytes = new byte[len];
            for (int i = 0; i < len; i++)
            {
                decimalBytes[i] = Convert.ToByte(s.Substring(2 * (i + fromindex), 2), 16);
            }

            return decimalBytes;
        }
    }
}