using System;

namespace boilerplate.Api.Configuration;

public sealed class VerificationOptions
{
    public bool RequireConfirmedEmail { get; init; } = true;
}
