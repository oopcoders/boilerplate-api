namespace boilerplate.Api.Dtos;

public record RegisterRequest(string Email, string Password);
public record LoginRequest(string Email, string Password);

public record AuthResponse(string AccessToken);

public record ForgotPasswordRequest(string Email);
public record ResetPasswordRequest(string Email, string Token, string NewPassword);

public record ConfirmEmailRequest(string UserId, string Token);
