using Microsoft.AspNetCore.Identity;

namespace boilerplate.Api.Data;

public static class Seed
{
    public static async Task SeedRolesAsync(IServiceProvider sp)
    {
        using var scope = sp.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        string[] roles = ["User", "Admin", "Subscriber"];

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}
