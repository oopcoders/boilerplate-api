namespace boilerplate.Api.Dtos;

public record RegisterRequest(string Email, string Password);
public record LoginRequest(string Email, string Password);

public record UserDto(
    string Id,
    string Username,
    string Email,
    IReadOnlyList<string> Roles
);

public record AuthResponse(
    string AccessToken,
    string RefreshToken,
    UserDto User
);

public record ForgotPasswordRequest(string Email);
public record ResetPasswordRequest(string Email, string Token, string NewPassword);

public record ConfirmEmailRequest(string UserId, string Token);
