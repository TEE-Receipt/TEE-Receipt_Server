using System;
using System.Runtime.InteropServices;
namespace EnclaveLinkTest
{
    class Program
    {
        [DllImport(@"../Debug/EnclaveLink.dll")]
        public static extern bool EnclaveLink_CreateEnclave();
        
        [DllImport(@"../Debug/EnclaveLink.dll")]
        public static extern bool EnclaveLink_EnclaveInitRa();
        [DllImport(@"../Debug/EnclaveLink.dll")]
        public static extern int EnclaveLink_ObtainQoute( byte[] qoute,  byte[] ecpk);
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            if (EnclaveLink_CreateEnclave()==true)
            {
                if (EnclaveLink_EnclaveInitRa()==true)
                {
                    byte[] quote = new byte[5000];
                    byte[] ecpk = new byte[64];
                    int n = EnclaveLink_ObtainQoute(  quote, ecpk);
                }
            }
        }
    }
}
