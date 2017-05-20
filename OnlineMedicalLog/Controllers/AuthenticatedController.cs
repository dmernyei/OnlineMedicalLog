using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using OnlineMedicalLog.Models;
using System.Web;
using System.Web.Mvc;

namespace OnlineMedicalLog.Controllers
{
    [Authorize]
    public abstract class AuthenticatedController : Controller
    {
        protected ApplicationDbContext _appDbContext = new ApplicationDbContext();
        

        protected ActionResult checkUser()
        {
            var loggedInUser = _appDbContext.Users.Find(User.Identity.GetUserId());

            if (!loggedInUser.UserConfirmed)
                return new AccountController().LogInvalidAccountOff(HttpContext.GetOwinContext().Authentication, ForcedLogOffReason.NOT_YET_CONFIRMED);
            if (loggedInUser.UserLocked)
                return new AccountController().LogInvalidAccountOff(HttpContext.GetOwinContext().Authentication, ForcedLogOffReason.LOCKED);

            ViewBag.role = GetUserRole();
            return null;
        }


        protected string GetUserRole()
        {
            ApplicationDbContext context = new ApplicationDbContext();
            var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(context));
            var roles = UserManager.GetRoles(User.Identity.GetUserId());
            return roles[0].ToString();
        }
    }
}