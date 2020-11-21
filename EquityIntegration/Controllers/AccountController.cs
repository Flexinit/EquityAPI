using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using EquityIntegration.Models;
using EquityIntegration.Providers;
using EquityIntegration.Results;
using System.Data.SqlClient;
using System.Data;
using System.Configuration;
using  System.IO;
using EquityIntegration.Student_Bank_Payments;

using EquityIntegration.StudentBankPaymentsCard;
using System.Net;

namespace EquityIntegration.Controllers
{

   

    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {

        private string DynamicsNAVServer = ConfigurationManager.AppSettings["DYNAMICSSERVER"];
        private String Port = ConfigurationManager.AppSettings["PORT"];
        private String Instance = ConfigurationManager.AppSettings["INSTANCE"];
        public static String SoapUser = ConfigurationManager.AppSettings["PORTALUSER"];
        public static String SoapPassword = ConfigurationManager.AppSettings["PORTALPASS"];
        private String Domain = ConfigurationManager.AppSettings["DOMAIN"];
        private String Company = ConfigurationManager.AppSettings["COMPANY"];

        private string dbConnection = ConfigurationManager.ConnectionStrings["DBConnectionString"].ToString();


       public string ipAddress = HttpContext.Current.Request.UserHostAddress.ToString();


        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }


            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                
                 ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }
        
        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result); 
            }
            return Ok();
        }
        public class StudentDetails
        {
            public string account { get; set; }
            public string username { get; set; }
            public string password { get; set; }

        }
        [HttpPost]
        [AllowAnonymous]
        [Route ("ValidateStudent")]

        public IHttpActionResult GetStudentBalance(StudentDetails model)
        {
            System.Net.Http.Headers.HttpRequestHeaders headers = this.Request.Headers;

            if (!((model.username.Equals("Equity")) && (model.password.Equals("Passw01d"))))
            {

                return Json(new { responseCode = "FAILED", responseMessage = "Invalid Credentials" });

            }
            try
            {

                string data = "TRANSACTION DATA: ." + " " + headers + " \n\n" +
                                   "Username: " + model.username + " \n" +
                                   "Username: " + model.account;



                // Write the string to a file.
                using (StreamWriter w = File.AppendText("C:\\EQUITY_LOGS\\IESR_Equity_logs.txt"))
                {
                    w.WriteLine(data);
                }

                AllStudentsLists.AllStudentsLists_Service service = new AllStudentsLists.AllStudentsLists_Service();
                service.UseDefaultCredentials = false;
                service.Credentials = new NetworkCredential(SoapUser, SoapPassword);
                service.Url = "http://" + DynamicsNAVServer + ":" + Port + "/" + Instance + "/WS/" + Company + "/Page/AllStudentsLists";


                List<AllStudentsLists.AllStudentsLists_Filter> filters = new List<AllStudentsLists.AllStudentsLists_Filter>();

                AllStudentsLists.AllStudentsLists_Filter  filter = new  AllStudentsLists.AllStudentsLists_Filter ();
                filter.Field = AllStudentsLists.AllStudentsLists_Fields.No;
                filter.Criteria = model.account;
                filters.Add(filter);
                var balance = service.ReadMultiple(filters.ToArray(), null, 0);
              
                string bal = balance[0].Balance.ToString();


                return Json(
                    
                    new {
                        
                    amount =bal,
                    billName = balance[0].Name,
                    billNumber = balance[0].No,
                    billerCode = balance[0].No,
                    createdOn = DateTime.Today.ToShortDateString(),
                    currencyCode = "KES",
                    customerName = balance[0].Name,
                    customerRefNumber = balance[0].No,
                    description = "School fees",
                    type = "1"
                    
                });
               

            }
            catch (Exception e)
            {
                return Json(new { responseCode = "OK", message = e.Message }); 
            }
        }

        public class PaymentDetails
        {
            public string username { get; set; }
            public string password { get; set; }
            public string billNumber { get; set; }
            public decimal billAmount { get; set; }
            public string CustomerRefNumber { get; set; }
            public string bankReference { get; set; }
            public string tranParticular { get; set; }
            public string paymentMode { get; set; }
            public DateTime transactionDate { get; set; }
            public string phonenumber { get; set; }
            public string debitaccount { get; set; }
            public string debitcustname { get; set; }

        }


        [HttpPost]
        [AllowAnonymous]
        [Route("paymentNotification")]
        public IHttpActionResult GetPaymentNotification(PaymentDetails model)
        {

            System.Net.Http.Headers.HttpRequestHeaders headers = this.Request.Headers;

            if (!((model.username.Equals("Equity"))  && (model.password.Equals("Passw01d")))) {

               return Json(new { responseCode = "FAILED", responseMessage = "Invalid Credentials" });

            }
        

            try
            {

              Student_Bank_Payments_Service payments_Service = new Student_Bank_Payments_Service();
                payments_Service.UseDefaultCredentials = false;
                payments_Service.Credentials = new NetworkCredential(SoapUser, SoapPassword);
                payments_Service.Url = "http://" + DynamicsNAVServer + ":" + Port + "/" +
                    Instance + "/WS/" + Company + "/Page/Student_Bank_Payments";

               Student_Bank_Payments.Student_Bank_Payments bank_Payments = new Student_Bank_Payments.Student_Bank_Payments();

                List<Student_Bank_Payments_Filter> filters = new List<Student_Bank_Payments_Filter>();

                Student_Bank_Payments_Filter filter = new Student_Bank_Payments_Filter();
                filter.Field = Student_Bank_Payments_Fields.bankReference;
                filter.Criteria = model.bankReference;
                filters.Add(filter);

                var payments = payments_Service.ReadMultiple(filters.ToArray(), null, 0);

                string bankRef = payments[0].bankReference;

                if (bankRef == model.bankReference) {

                    return Json(new
                    {
                        responseCode = "FALSE",
                        responseMessage = "DUPLICATE TRANSACTION"
                    });

                }

               
                if (!(model.billNumber == null ||  model.debitaccount == null))
                {
                    return Json(new
                    {
                        responseCode = "FALSE",
                        responseMessage = "bill number not found"
                    });
                }

                bank_Payments.billNumber = model.billNumber;
                bank_Payments.username = model.username;
                bank_Payments.billAmount = model.billAmount;
                bank_Payments.CustomerRefNumber = model.CustomerRefNumber;
                bank_Payments.bankReference = model.bankReference;
                bank_Payments.tranParticular = model.tranParticular;
                bank_Payments.paymentMode = model.paymentMode;
                bank_Payments.transactionDate = model.transactionDate;
                bank_Payments.phonenumber = model.phonenumber;
                bank_Payments.debitaccount = model.debitaccount;
                bank_Payments.debitcustname = model.debitcustname;

                payments_Service.Create(ref bank_Payments);

                string username = model.username;
                string billNumber = model.billNumber;
                decimal billAmount = model.billAmount;
                string CustomerRefNumber = model.CustomerRefNumber;
                string bankreference = model.bankReference;
                string tranParticular = model.tranParticular;
                string paymentMode = model.paymentMode;
                DateTime transactionDate = model.transactionDate;
                string phonenumber = model.phonenumber;
                string debitaccount = model.debitaccount;
                string debitcustname = model.debitcustname;

                string data = "TRANSACTION DATA: ." + " " + headers + " \n\n" +
                     "------+---+-----+------+-----+------+--------  \n\n" +
                    "Username: " + username + " \n" +
                "billNumber: " + billNumber + " \n" +
                "billAmount: " + billAmount + " \n" +
                "CustomerRefNumber: " + CustomerRefNumber + " \n" +
                "bankreference: " + bankreference + " \n" +
                "tranParticular: " + tranParticular + " \n" +
                "paymentMode: " + paymentMode + " \n" +
                "transactionDate: " + transactionDate + " \n" +
                "phonenumber: " + phonenumber + " \n" +
                "debitaccount: " + debitaccount + " \n" +
                "debitcustname: " + debitcustname;

                using (StreamWriter w = File.AppendText("C:\\EQUITY_LOGS\\IESR_Equity_logs.txt"))
                {
                    w.WriteLine(data);
                }

                return Json(new
                {
                    responseCode = "OK",
                    responseMessage = "SUCCESSFUL"
                });
            }
            catch (Exception e) {
                using (StreamWriter w = File.AppendText("C:\\EQUITY_LOGS\\IESR_Equity_logs.txt"))
                {
                    w.WriteLine(e.Message);
                }
                return Json(new { responseCode = "FAILED", responseMessage = e.Message });

            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                 _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }


    
}
