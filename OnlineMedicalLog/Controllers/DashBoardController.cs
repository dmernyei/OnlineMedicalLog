using Microsoft.AspNet.Identity;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace OnlineMedicalLog.Controllers
{
    [Authorize]
    public class DashBoardController : AuthenticatedController
    {        
        // GET: DashBoard
        public ActionResult Index()
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            string role = ViewBag.role;
            switch (role)
            {
                case "admin":
                    return RedirectToAction("ListApplications", new RouteValueDictionary(
                        new
                        {
                            controller = "Account",
                            action = "ListApplications"
                        }
                    ));
                case "doctor":
                    return RedirectToAction("ListPatients", new RouteValueDictionary(
                        new
                        {
                            controller = "Account",
                            action = "ListPatients"
                        }
                    ));
                case "patient":
                    return RedirectToAction("Index", new RouteValueDictionary(
                        new
                        {
                            controller = "TestResult",
                            action = "Index"
                        }
                    ));
                default:
                    return new AccountController().LogInvalidAccountOff(HttpContext.GetOwinContext().Authentication, null);
            }
        }
    }
}