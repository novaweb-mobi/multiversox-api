using Microsoft.EntityFrameworkCore;
using Models;

namespace Data
{
    public class GameDbContext : DbContext
    {
        public GameDbContext(DbContextOptions<GameDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<Profile> Profiles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>()
                .HasMany(u => u.Profiles)
                .WithOne(p => p.User)
                .HasForeignKey(p => p.UserId);
        }
    }
} 