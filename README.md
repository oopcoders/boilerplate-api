# BOILERPLATE-API (.NET 10)

A reusable **ASP.NET Core (.NET 10) Web API boilerplate** featuring **ASP.NET Core Identity**, **JWT authentication**, **rotating refresh tokens**, password reset flows, and **policy-based admin authorization**.

This repository is **public and safe to share**.  
**No secrets are committed to source control.**

---

## Tech Stack

- .NET 10 (ASP.NET Core Web API)
- ASP.NET Core Identity
- Entity Framework Core
- SQLite (local development)
- JWT Access Tokens
- Rotating Refresh Tokens
- Authorization Policies (`AdminOnly`)

---

## Run Locally
```bash
dotnet run

### Prerequisites
- .NET SDK 10 installed

Verify:
```bash
dotnet --version

##Entity Framework Core
```bash
dotnet ef database update
