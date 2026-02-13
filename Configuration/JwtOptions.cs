using System;

namespace boilerplate.Api.Configuration;

public sealed class JwtOptions
{
    public int RefreshTokenDays { get; init; } = 7;
    // later: Issuer, Audience, Key, AccessTokenMinutes, etc.
}