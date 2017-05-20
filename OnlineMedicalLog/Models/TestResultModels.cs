using System;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;

namespace OnlineMedicalLog.Models
{
    public class TestResult
    {
        public int ID { get; set; }
        [Required]
        public DateTime date { get; set; }
        [Required]
        public string doctorId { get; set; }
        [Required]
        public string patientId { get; set; }
        [Required]
        public string title { get; set; }
        [Required]
        public string description { get; set; }
    }


    public class TestResultDbContext : DbContext
    {
        public DbSet<TestResult> TestResults { get; set; }
    }
}