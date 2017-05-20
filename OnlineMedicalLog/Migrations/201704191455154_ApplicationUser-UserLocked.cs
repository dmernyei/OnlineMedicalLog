namespace OnlineMedicalLog.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class ApplicationUserUserLocked : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.AspNetUsers", "UserLocked", c => c.Boolean(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.AspNetUsers", "UserLocked");
        }
    }
}
