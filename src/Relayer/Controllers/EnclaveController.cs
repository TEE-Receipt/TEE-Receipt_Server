using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Newtonsoft.Json;
using Relayer.EnclaveInterface;
namespace Relayer.Controllers
{
    public class EnclaveController : Controller
    {
        public ActionResult Initialize()
        {
            Enclave.InitializeEnclave();
            ViewBag.Result = true;
            return View();
        }
        [HttpGet]
        public ActionResult Quote()
        {
            byte[] ecpk = new byte[64];
            ViewBag.Result = Convert.ToBase64String(Enclave.GetQuote(ref ecpk));
            return View();
        }
        [HttpGet]
        public ActionResult GetCMAC(String password)
        {

            byte[] cmactag = new byte[16];
            byte[] s = new byte[64];
            byte[] userid = new byte[8];
            try
            {
                Enclave.RegisterUser(password, ref userid, ref cmactag, ref s);
            }
            catch (Exception)
            { 

            }
            var result = new {
                CMAC = Convert.ToBase64String(cmactag), 
                UID = Convert.ToBase64String(userid)
            };
            ViewBag.Result= JsonConvert.SerializeObject(result);
            return View();
        }


        [HttpGet]
        public ActionResult VerifyCMAC(String id, String password, String cmac)
        {
            byte[] ct = new byte[512];
            byte[] s = new byte[64];
            if (Enclave.Login(Convert.FromBase64String(id), password, Convert.FromBase64String(cmac), s, ref ct))
            {
                byte[] sentct = new byte[32];
                Array.Copy(ct, 0, sentct, 0, 32);
                ViewBag.Result = BitConverter.ToString(sentct).Replace("-", "");
            }
            else
            {
                ViewBag.Result = false;
            }
            return View();
        }

        [HttpPost]
        public ActionResult Sign(string id, String transactiontext, String bsignature)
        {
            byte[] enclavesig = new byte[64];
            byte[] verifyingkey = new byte[64];
            try
            {
                Enclave.SignTransaction(Convert.FromBase64String(id), transactiontext, bsignature, ref enclavesig, ref verifyingkey);

            }
            catch (Exception)
            { }
            ViewBag.Result = BitConverter.ToString(enclavesig).Replace("-", "");

            return View();
        }
    }
}