using System.Web.Mvc;

namespace OnlineMedicalLog.Controllers
{
    public class UnAuthenticatedController : Controller
    {
        // GET: UnAuthenticated
        public ActionResult Index(ForcedLogOffReason? reason)
        {
            if (null == reason)
            {
                ViewBag.Message = "There has been an error during authentication.\nSorry for the inconvenience.";
            }
            else
            {
                ViewBag.Message = ForcedLogOffReason.NOT_YET_CONFIRMED == reason ?
                    "Thank You for your registration!\nAn administrator will confirm your application shortly." :
                    "Your account is currently locked out.\nSorry for the inconvenience.";
            }
            
            return View();
        }
    }
}