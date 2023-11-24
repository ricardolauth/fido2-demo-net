using fido2_demo.Model.Entity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata;

namespace fido2_demo.Model
{
    public class FidoDemoContext(DbContextOptions<FidoDemoContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Credential> Credentials { get; set; }

        public override int SaveChanges()
        {
            OnBeforeSaving();
            return base.SaveChanges();
        }

        public override int SaveChanges(bool acceptAllChangesOnSuccess)
        {
            OnBeforeSaving();
            return base.SaveChanges(acceptAllChangesOnSuccess);
        }

        public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
        {
            OnBeforeSaving();
            return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
        }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            OnBeforeSaving();
            return base.SaveChangesAsync(cancellationToken);
        }

        private void OnBeforeSaving()
        {
            IEnumerable<EntityEntry> entityEntries = ChangeTracker.Entries();
            var now = DateTime.UtcNow;
            foreach (EntityEntry entry in entityEntries)
            {
                if(!(entry.Entity is BaseModel entity))
                {
                    continue;
                }

                switch (entry.State)
                {
                    case EntityState.Modified:
                        entity.UpdatedOn = now;
                        entry.Property(nameof(entity.CreatedOn)).IsModified = false;
                        break;
                    case EntityState.Added:
                        entity.UpdatedOn = now;
                        entity.CreatedOn = now;
                        break;
                }
            }
        }
    }
}
