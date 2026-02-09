using System;

namespace boilerplate.Api.Data;

public class RefreshToken
{
    public int Id { get; set; }

    public string TokenHash { get; set; } = default!;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresUtc { get; set; }

    public DateTime? RevokedUtc { get; set; }
    public string? ReplacedByTokenHash { get; set; }

    public string UserId { get; set; } = default!;
    public AppUser User { get; set; } = default!;

    public bool IsActive => RevokedUtc is null && DateTime.UtcNow < ExpiresUtc;
}
