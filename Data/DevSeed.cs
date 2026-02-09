using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;


namespace boilerplate.Api.Data;

public static class DevSeed
{
    public static async Task SeedDevAdminAsync(IServiceProvider services, IConfiguration config)
    {
        var enabled = config.GetValue("BootstrapAdmin:Enabled", false);
        if (!enabled) return;

        using var scope = services.CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Ensure roles exist
        var roles = new[] { "User", "Admin", "Subscriber" };
        foreach (var role in roles)
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));

        var email = config["BootstrapAdmin:Email"];
        var password = config["BootstrapAdmin:Password"];

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return;

        var existing = await userManager.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (existing is null)
        {
            var user = new AppUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true // dev convenience
            };

            var create = await userManager.CreateAsync(user, password);
            if (!create.Succeeded)
                throw new Exception("Failed to create bootstrap admin: " +
                                    string.Join("; ", create.Errors.Select(e => e.Description)));

            await userManager.AddToRoleAsync(user, "Admin");
        }
        else
        {
            // Ensure admin role is present
            if (!await userManager.IsInRoleAsync(existing, "Admin"))
                await userManager.AddToRoleAsync(existing, "Admin");
        }
    }
}
