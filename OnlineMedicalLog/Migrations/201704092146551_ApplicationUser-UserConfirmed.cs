namespace OnlineMedicalLog.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class ApplicationUserUserConfirmed : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.AspNetUsers", "UserConfirmed", c => c.Boolean(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.AspNetUsers", "UserConfirmed");
        }
    }
}
