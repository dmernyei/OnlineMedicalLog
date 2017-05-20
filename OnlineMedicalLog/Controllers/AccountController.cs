using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using OnlineMedicalLog.Models;
using System.Web.Routing;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Collections.Generic;
using System.Data;
using System.Net;
using System.Data.Entity;

namespace OnlineMedicalLog.Controllers
{
    public enum ForcedLogOffReason { NOT_YET_CONFIRMED, LOCKED }

    [Authorize]
    public class AccountController : AuthenticatedController
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;


        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }


        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }


        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }


        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            
            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }

 
        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            ViewBag.Roles = new SelectList(_appDbContext.Roles.Where(role => !role.Name.Contains("admin")).ToList(), "Name", "Name");
            return View();
        }


        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.UserName, Email = model.Email, EmailConfirmed = true, LockoutEnabled = true, UserConfirmed = false, UserLocked = false };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent:false, rememberBrowser:false);

                    // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    await UserManager.AddToRoleAsync(user.Id, model.Role);

                    return RedirectToAction("Index", "DashBoard");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            ViewBag.Roles = new SelectList(_appDbContext.Roles.Where(role => !role.Name.Contains("admin")).ToList(), "Name", "Name");
            return View(model);
        }


        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "DashBoard");
        }


        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogInvalidAccountOff(IAuthenticationManager authenticationManager, ForcedLogOffReason? reason)
        {
            authenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            
            return RedirectToAction("Index", new RouteValueDictionary(
                new
                {
                    controller = "UnAuthenticated",
                    action = "Index",
                    reason = reason
                }
            ));
        }


        [Authorize(Roles = "admin")]
        public ActionResult ListApplications(string userName, string email, string userRoleName)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;
            
            QueryRoles();
            
            var unConfirmedUsers = _appDbContext.Users.Where(user => !user.UserConfirmed);

            if (!string.IsNullOrEmpty(userName))
                unConfirmedUsers = unConfirmedUsers.Where(user => user.UserName.Contains(userName));

            if (!string.IsNullOrEmpty(email))
                unConfirmedUsers = unConfirmedUsers.Where(user => user.Email.Contains(email));

            if (!string.IsNullOrEmpty(userRoleName))
            {
                var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_appDbContext));
                string userRoleId = roleManager.Roles.Where(role => role.Name == userRoleName).ToList()[0].Id;
                unConfirmedUsers = unConfirmedUsers.Where(user => user.Roles.Select(role => role.RoleId).Contains(userRoleId));
            }

            // Content for dropdownlist
            List<string> userRoleNames = new List<string>();
            foreach (KeyValuePair<string, string> entry in ViewBag.roleDictionary)
            {
                if (entry.Value != "admin")
                    userRoleNames.Add(entry.Value);
            }
            ViewBag.userRoleName = new SelectList(userRoleNames);

            return View(unConfirmedUsers.ToList());
        }


        [Authorize(Roles = "admin")]
        public ActionResult ManageApplication(string userId, bool? grant, string userRoleName)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(userRoleName) || null == grant)
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            
            ViewBag.grant = grant;
            ViewBag.userRoleName = userRoleName;
            
            return View(_appDbContext.Users.Find(userId));
        }


        [HttpPost]
        [Authorize(Roles = "admin")]
        public ActionResult ManageApplicationConfirmed(string userId, bool? grant)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (string.IsNullOrEmpty(userId) || null == grant)
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            // Applying changes
            ApplicationUser userToManage = _appDbContext.Users.Find(userId);
            if ((bool)grant)
            {
                userToManage.UserConfirmed = true;
                _appDbContext.Entry(userToManage).State = EntityState.Modified;
            }
            else
            {
                _appDbContext.Users.Remove(userToManage);
            }
            _appDbContext.SaveChanges();

            return RedirectToAction("ListApplications", new RouteValueDictionary(
                new
                {
                    controller = "Account",
                    action = "ListApplications"
                }
            ));
        }
        

        [Authorize(Roles = "admin")]
        public ActionResult ListLocks(string userName, string email, string userRoleName, string userStatus)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            QueryRoles();
            
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_appDbContext));
            string adminRoleId = roleManager.Roles.Where(role => role.Name == "admin").ToList()[0].Id;
            var nonAdminConfirmedUsers = _appDbContext.Users.Where(user => user.UserConfirmed && !user.Roles.Select(role => role.RoleId).Contains(adminRoleId));

            if (!string.IsNullOrEmpty(userName))
                nonAdminConfirmedUsers = nonAdminConfirmedUsers.Where(user => user.UserName.Contains(userName));

            if (!string.IsNullOrEmpty(email))
                nonAdminConfirmedUsers = nonAdminConfirmedUsers.Where(user => user.Email.Contains(email));

            if (!string.IsNullOrEmpty(userRoleName))
            {
                string userRoleId = roleManager.Roles.Where(role => role.Name == userRoleName).ToList()[0].Id;
                nonAdminConfirmedUsers = nonAdminConfirmedUsers.Where(user => user.Roles.Select(role => role.RoleId).Contains(userRoleId));
            }

            if (!string.IsNullOrEmpty(userStatus))
            {
                bool locked = userStatus == "Locked";
                nonAdminConfirmedUsers = nonAdminConfirmedUsers.Where(user => user.UserLocked == locked);
            }

            // Content for dropdownlists
            List<string> userRoleNames = new List<string>();
            foreach (KeyValuePair<string, string> entry in ViewBag.roleDictionary)
            {
                if (entry.Value != "admin")
                    userRoleNames.Add(entry.Value);
            }
            ViewBag.userRoleName = new SelectList(userRoleNames);
            
            ViewBag.userStatus = new SelectList(new List<string> { "Locked", "Unlocked" });

            return View(nonAdminConfirmedUsers.ToList());
        }

        
        [HttpPost]
        [Authorize(Roles = "admin")]
        public ActionResult LockUser(string userId, bool? enableLock)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (string.IsNullOrEmpty(userId) || null == enableLock)
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            ApplicationUser userToUpdate = _appDbContext.Users.Find(userId);
            userToUpdate.UserLocked = (bool)enableLock;

            _appDbContext.Entry(userToUpdate).State = EntityState.Modified;
            _appDbContext.SaveChanges();

            return Redirect(Request.UrlReferrer.ToString());
        }


        [Authorize(Roles = "doctor")]
        public ActionResult ListPatients(string patientName, string email)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;
            
            // Querying patients
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_appDbContext));
            string patientRoleId = roleManager.Roles.Where(role => role.Name == "patient").ToList()[0].Id;
            var patients = _appDbContext.Users.Where(user => user.Roles.Select(role => role.RoleId).Contains(patientRoleId));

            // Filtering
            if (!string.IsNullOrEmpty(patientName))
                patients = patients.Where(user => user.UserName.Contains(patientName));

            if (!string.IsNullOrEmpty(email))
                patients = patients.Where(user => user.Email.Contains(email));

            return View(patients.ToList());
        }


        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }


        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";


        private void QueryRoles()
        {
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_appDbContext));
            List<IdentityRole> roles = roleManager.Roles.ToList();

            Dictionary<string, string> roleDictionary = new Dictionary<string, string>();
            foreach (IdentityRole role in roles)
                roleDictionary[role.Id] = role.Name;
            ViewBag.roleDictionary = roleDictionary;
        }


        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }


        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }


        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "DashBoard");
        }


        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}