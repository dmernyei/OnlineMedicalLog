using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin;
using OnlineMedicalLog.Models;
using Owin;

[assembly: OwinStartupAttribute(typeof(OnlineMedicalLog.Startup))]
namespace OnlineMedicalLog
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
            CreateRoles();
        }


        private void CreateRoles()
        {
            ApplicationDbContext appDbContext = new ApplicationDbContext();
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(appDbContext));

            CreateRole(roleManager, "admin");
            CreateRole(roleManager, "doctor");
            CreateRole(roleManager, "patient");
        }


        private void CreateRole(RoleManager<IdentityRole> roleManager, string roleName)
        {
            if (!roleManager.RoleExists(roleName))
            {
                var role = new IdentityRole();
                role.Name = roleName;
                roleManager.Create(role);
            }
        }
    }
}
