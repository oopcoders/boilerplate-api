using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using boilerplate.Api.Data;
using static boilerplate.Api.Dtos.AdminDto;

namespace boilerplate.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class AdminController : ControllerBase
{
    private readonly UserManager<AppUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AdminController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [HttpPost("roles/add")]
    public async Task<ActionResult> AddRole(AddRoleRequest req)
    {
        var role = req.Role?.Trim();
        var email = req.UserEmail?.Trim();

        if (string.IsNullOrWhiteSpace(role) || string.IsNullOrWhiteSpace(email))
            return BadRequest(new { message = "UserEmail and Role are required." });

        if (!await _roleManager.RoleExistsAsync(role))
            return BadRequest(new { message = $"Role '{role}' does not exist." });

        var user = await _userManager.FindByEmailAsync(email);
        if (user is null) return NotFound(new { message = "User not found." });

        // Prevent self-escalation to Admin (optional but recommended)
        var isSelf = string.Equals(User.Identity?.Name, user.UserName, StringComparison.OrdinalIgnoreCase);
        if (isSelf && role.Equals("Admin", StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { message = "You cannot grant yourself Admin role." });

        var result = await _userManager.AddToRoleAsync(user, role);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(new { message = $"Added role '{role}' to '{email}'." });
    }

    [HttpPost("roles/remove")]
    public async Task<ActionResult> RemoveRole(RemoveRoleRequest req)
    {
        var role = req.Role?.Trim();
        var email = req.UserEmail?.Trim();

        if (string.IsNullOrWhiteSpace(role) || string.IsNullOrWhiteSpace(email))
            return BadRequest(new { message = "UserEmail and Role are required." });

        var user = await _userManager.FindByEmailAsync(email);
        if (user is null) return NotFound(new { message = "User not found." });

        // Prevent removing your own Admin role (optional guard)
        var isSelf = string.Equals(User.Identity?.Name, user.UserName, StringComparison.OrdinalIgnoreCase);
        if (isSelf && role.Equals("Admin", StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { message = "You cannot remove your own Admin role." });

        var result = await _userManager.RemoveFromRoleAsync(user, role);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(new { message = $"Removed role '{role}' from '{email}'." });
    }

    [HttpGet("users/{email}/roles")]
    public async Task<ActionResult> GetRoles(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null) return NotFound(new { message = "User not found." });

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new { email, roles });
    }
}
