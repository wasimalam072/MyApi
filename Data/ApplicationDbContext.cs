namespace MyApi.Data;

public sealed class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(
    ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(
            entity =>
            {
                // Identity searches using normalized values.
                // Enforcing uniqueness at database level protects
                // against race conditions during user creation.
                entity.HasIndex(
                        user =>
                            user.NormalizedEmail)
                    .IsUnique()
                    .HasFilter(
                        "[NormalizedEmail] IS NOT NULL");

                entity.HasMany(
                        user =>
                            user.RefreshTokens)
                    .WithOne(
                        token =>
                            token.User)
                    .HasForeignKey(
                        token =>
                            token.UserId)
                    .OnDelete(
                        DeleteBehavior.Cascade);
            });

        builder.Entity<RefreshToken>(
            entity =>
            {
                entity.HasKey(
                    token =>
                        token.Id);

                entity.HasIndex(
                        token =>
                            token.TokenHash)
                    .IsUnique();
            });
    }
}