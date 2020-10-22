using Microsoft.EntityFrameworkCore;
using Users.Models;

namespace Users.Persisitence
{
    public class ExpenseTrackerDBContext : DbContext
    {
        public ExpenseTrackerDBContext(DbContextOptions<ExpenseTrackerDBContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {


            base.OnModelCreating(modelBuilder);
        }

    }
}
