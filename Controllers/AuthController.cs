using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using boilerplate.Api.Data;
using boilerplate.Api.Dtos;
using boilerplate.Api.Services;
using Microsoft.Extensions.Options;
using boilerplate.Api.Configuration;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace boilerplate.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<AppUser> _userManager;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly AppDbContext _db;
    private readonly JwtTokenService _jwt;
    private readonly IMessageSender _sender;
    private readonly ClientAppOptions _clientApp;
    private readonly VerificationOptions _verification;
    private readonly JwtOptions _jwtOptions;

    public AuthController(
        UserManager<AppUser> userManager,
        SignInManager<AppUser> signInManager,
        AppDbContext db,
        JwtTokenService jwt,
        IMessageSender sender,
        IOptions<ClientAppOptions> clientAppOptions,
        IOptions<VerificationOptions> verificationOptions,
        IOptions<JwtOptions> jwtOptions)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _db = db;
        _jwt = jwt;
        _sender = sender;
        _clientApp = clientAppOptions.Value;
        _verification = verificationOptions.Value;
        _jwtOptions = jwtOptions.Value;
    }

    [HttpPost("register")]
    public async Task<ActionResult> Register(RegisterRequest req)
    {
        var user = new AppUser { UserName = req.Email, Email = req.Email };

        var result = await _userManager.CreateAsync(user, req.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);

        // default role
        await _userManager.AddToRoleAsync(user, "User");

        // email confirm token
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var link = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={Uri.EscapeDataString(user.Id)}&token={Uri.EscapeDataString(token)}";

        await _sender.SendEmailAsync(user.Email!, "Confirm your email", $"Click to confirm: {link}");

        return Ok(new { message = "Registered. Check dev logs for confirmation link." });
    }

    [HttpGet("confirm-email")]
    public async Task<ActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null) return NotFound();

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(new { message = "Email confirmed." });
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login(LoginRequest req)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == req.Email);
        if (user is null) return Unauthorized(new { message = "Invalid credentials." });

        if (_verification.RequireConfirmedEmail && !user.EmailConfirmed)
            return Unauthorized(new { message = "Email not confirmed." });

        var passOk = await _signInManager.CheckPasswordSignInAsync(user, req.Password, lockoutOnFailure: true);
        if (!passOk.Succeeded) return Unauthorized(new { message = "Invalid credentials." });

        var accessToken = await _jwt.CreateAccessTokenAsync(user);

        // refresh token
        var refreshPlain = _jwt.CreateRefreshTokenPlain();
        var refreshHash = JwtTokenService.Sha256(refreshPlain);

        var days = _jwtOptions.RefreshTokenDays;

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshHash,
            ExpiresUtc = DateTime.UtcNow.AddDays(days)
        });

        await _db.SaveChangesAsync();

        var roles = await _userManager.GetRolesAsync(user);

        var response = new AuthResponse(
            AccessToken: accessToken,
            RefreshToken: refreshPlain,
            User: new UserDto(
                Id: user.Id,
                Username: user.UserName ?? "",
                Email: user.Email ?? "",
                Roles: roles.ToArray()
            )
        );

        return Ok(response);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult> Refresh([FromBody] string refreshToken)
    {
        var hash = JwtTokenService.Sha256(refreshToken);

        var stored = await _db.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.TokenHash == hash);

        if (stored is null || !stored.IsActive) return Unauthorized(new { message = "Invalid refresh token." });

        // rotate refresh token
        stored.RevokedUtc = DateTime.UtcNow;

        var newPlain = _jwt.CreateRefreshTokenPlain();
        var newHash = JwtTokenService.Sha256(newPlain);

        var days = _jwtOptions.RefreshTokenDays;

        stored.ReplacedByTokenHash = newHash;

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = stored.UserId,
            TokenHash = newHash,
            ExpiresUtc = DateTime.UtcNow.AddDays(days)
        });

        var newAccess = await _jwt.CreateAccessTokenAsync(stored.User);

        await _db.SaveChangesAsync();

        return Ok(new
        {
            accessToken = newAccess,
            refreshToken = newPlain
        });
    }

    [HttpPost("forgot-password")]
    public async Task<ActionResult> ForgotPassword(ForgotPasswordRequest req)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == req.Email);

        // Always return OK to prevent email enumeration
        if (user is null) return Ok(new { message = "If that email exists, a reset link was sent." });


        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        var baseUrl = _clientApp.BaseUrl.TrimEnd('/');
        var link = $"{baseUrl}/auth/reset-password" +
                $"?email={Uri.EscapeDataString(user.Email!)}" +
                $"&token={Uri.EscapeDataString(token)}";

        await _sender.SendEmailAsync(user.Email!, "Reset your password", $"Reset link: {link}");


        return Ok(new { message = "If that email exists, a reset link was sent. Check dev logs." });
    }

    [HttpPost("reset-password")]
    public async Task<ActionResult> ResetPassword(ResetPasswordRequest req)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == req.Email);
        if (user is null) return BadRequest(new { message = "Invalid request." });

        var token = req.Token ?? "";

        // If the client sent an encoded token (contains %2F, %2B, etc), decode once.
        if (token.Contains('%'))
            token = Uri.UnescapeDataString(token);

        // If + turned into space anywhere, revert it.
        token = token.Replace(" ", "+");

        var result = await _userManager.ResetPasswordAsync(user, token, req.NewPassword);


        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(new { message = "Password reset successful." });
    }

    [Authorize(Policy = "AdminOnly")]
    [HttpGet("admin-only-test")]
    public ActionResult AdminOnlyTest() => Ok(new { message = "You are Admin." });

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserDto>> Me()
    {
        var userId =
            User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);

        if (string.IsNullOrWhiteSpace(userId))
            return Unauthorized(new { message = "Missing user id claim." });

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null) return Unauthorized(new { message = "User not found." });

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new UserDto(
            Id: user.Id,
            Username: user.UserName ?? "",
            Email: user.Email ?? "",
            Roles: roles.ToArray()
        ));
    }
}
