using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web.Mvc;
using OnlineMedicalLog.Models;
using Microsoft.AspNet.Identity;
using System.Data.Entity.Validation;
using System.Collections.Generic;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Web.Routing;
using System;

namespace OnlineMedicalLog.Controllers
{
    [Authorize(Roles = "patient,doctor")]
    public class TestResultController : AuthenticatedController
    {
        private TestResultDbContext _testResultDbContext = new TestResultDbContext();


        // GET: TestResult
        public ActionResult Index(string patientId, string doctorName, string title)
        {
            // Checking
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            bool isUserDoctor = ViewBag.role == "doctor";
            bool patientIdProvided = !string.IsNullOrEmpty(patientId);

            if (isUserDoctor && !patientIdProvided || !isUserDoctor && patientIdProvided && patientId != User.Identity.GetUserId())
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            
            // Querying the patient's test results
            if (!patientIdProvided)
                patientId = User.Identity.GetUserId();

            var patientTestResults = _testResultDbContext.TestResults.Where(testResult => testResult.patientId == patientId);

            // Filtering by title
            if (!string.IsNullOrEmpty(title))
                patientTestResults = patientTestResults.Where(testResult => testResult.title.Contains(title));

            List<TestResult> patientTestResultList = patientTestResults.ToList();

            // Querying doctors
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_appDbContext));
            string doctorRoleId = roleManager.Roles.Where(role => role.Name == "doctor").ToList()[0].Id;
            List<ApplicationUser> doctorList = _appDbContext.Users.Where(user => user.Roles.Select(role => role.RoleId).Contains(doctorRoleId)).ToList();

            // Assigning doctor names to test results
            Dictionary<string, string> doctorDictionary = new Dictionary<string, string>();
            bool filteringByDoctorName = !string.IsNullOrEmpty(doctorName);
            bool filteringForDoctorNA = filteringByDoctorName && doctorName == "N/A";

            for (int i = 0; i < patientTestResultList.Count; ++i)
            {
                if (doctorDictionary.ContainsKey(patientTestResultList[i].doctorId))
                    continue;
                
                foreach (ApplicationUser doctor in doctorList)
                {
                    if (doctor.Id != patientTestResultList[i].doctorId)
                        continue;
                    
                    if (!filteringByDoctorName || !filteringForDoctorNA && doctor.UserName.Contains(doctorName))
                    {
                        doctorDictionary[doctor.Id] = doctor.UserName;
                    }
                    else
                    {
                        patientTestResultList.RemoveAt(i);
                        --i;
                    }
                    break;
                }
            }

            if (isUserDoctor)
                ViewBag.patientName = _appDbContext.Users.Find(patientId).UserName;
            ViewBag.patientId = patientId;
            ViewBag.isUserDoctor = isUserDoctor;
            ViewBag.doctorDictionary = doctorDictionary;
            
            return View(patientTestResultList);
        }


        // GET: TestResult/Details/5
        public ActionResult Details(int? id)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (null == id)
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            TestResult testResult = _testResultDbContext.TestResults.Find(id);
            if (testResult == null)
                return HttpNotFound();

            bool isUserDoctor = ViewBag.role == "doctor";

            // Check if test result belongs to the logged in patient
            if (!isUserDoctor && testResult.patientId != User.Identity.GetUserId())
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            ViewBag.isUserDoctor = isUserDoctor;
            ViewBag.currentUserName = User.Identity.GetUserName();
            ViewBag.otherUserName = _appDbContext.Users.Find(isUserDoctor ? testResult.patientId : testResult.doctorId).UserName;
            
            return View(testResult);
        }


        // GET: TestResult/Create
        [Authorize(Roles = "doctor")]
        public ActionResult Create(string patientId)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (string.IsNullOrEmpty(patientId))
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            ViewBag.patientId = patientId;
            ViewBag.patientName = _appDbContext.Users.Find(patientId).UserName;
            ViewBag.doctorId = User.Identity.GetUserId();
            ViewBag.doctorName = User.Identity.GetUserName();

            return View();
        }


        // POST: TestResult/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "doctor")]
        public ActionResult Create([Bind(Include = "ID,date,doctorId,patientId,title,description")] TestResult testResult, string doctorId, string patientId)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (string.IsNullOrEmpty(doctorId) || string.IsNullOrEmpty(patientId))
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            testResult.date = DateTime.Now;
            testResult.doctorId = doctorId;
            testResult.patientId = patientId;

            if (ModelState.IsValid)
            {
                _testResultDbContext.TestResults.Add(testResult);
                _testResultDbContext.SaveChanges();
                return RedirectToAction("Index", new RouteValueDictionary(
                    new
                    {
                        controller = "TestResult",
                        action = "Index",
                        patientId = testResult.patientId
                    }
                ));
            }

            return View(testResult);
        }


        // GET: TestResult/Edit/5
        [Authorize(Roles = "doctor")]
        public ActionResult Edit(int? id)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TestResult testResult = _testResultDbContext.TestResults.Find(id);
            if (testResult == null)
            {
                return HttpNotFound();
            }

            ViewBag.patientName = _appDbContext.Users.Find(testResult.patientId).UserName;
            ViewBag.doctorName = User.Identity.GetUserName();

            return View(testResult);
        }


        // POST: TestResult/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "doctor")]
        public ActionResult Edit([Bind(Include = "ID,date,doctorId,patientId,title,description")] TestResult testResult)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;
            
            if (ModelState.IsValid)
            {
                _testResultDbContext.Entry(testResult).State = EntityState.Modified;
                _testResultDbContext.SaveChanges();
                return RedirectToAction("Index", new RouteValueDictionary(
                    new
                    {
                        controller = "TestResult",
                        action = "Index",
                        patientId = testResult.patientId
                    }
                ));
            }
            return View(testResult);
        }


        // GET: TestResult/Delete/5
        [Authorize(Roles = "doctor")]
        public ActionResult Delete(int? id)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TestResult testResult = _testResultDbContext.TestResults.Find(id);
            if (testResult == null)
            {
                return HttpNotFound();
            }

            ViewBag.patientName = _appDbContext.Users.Find(testResult.patientId).UserName;
            ViewBag.doctorName = User.Identity.GetUserName();

            return View(testResult);
        }


        // POST: TestResult/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "doctor")]
        public ActionResult DeleteConfirmed(int? id)
        {
            ActionResult checkResult = checkUser();
            if (null != checkResult)
                return checkResult;

            if (null == id)
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            TestResult testResult = _testResultDbContext.TestResults.Find(id);
            _testResultDbContext.TestResults.Remove(testResult);
            _testResultDbContext.SaveChanges();
            return RedirectToAction("Index", new RouteValueDictionary(
                new
                {
                    controller = "TestResult",
                    action = "Index",
                    patientId = testResult.patientId
                }
            ));
        }


        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _testResultDbContext.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
