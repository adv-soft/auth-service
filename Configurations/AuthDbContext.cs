using AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Configurations
{
    public class AuthDbContext : DbContext
    { 
        public AuthDbContext(DbContextOptions<AuthDbContext> options)
            : base(options)
        {
        }
        // protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        // {
        //     if (!optionsBuilder.IsConfigured)
        //     {
        //         optionsBuilder
        //             .EnableSensitiveDataLogging(); // Enable sensitive data logging
        //     }
        // }
        //

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AuthModel>().HasKey(a => a.Id);
            
        }
        
        public DbSet<AuthModel> AuthModel { get; set; }
    }
}

