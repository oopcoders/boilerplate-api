using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using boilerplate.Api.Data;
using boilerplate.Api.Services;
using boilerplate.Api.Configuration;

var builder = WebApplication.CreateBuilder(args);


builder.Services.Configure<ClientAppOptions>(builder.Configuration.GetSection("ClientApp"));
builder.Services.Configure<VerificationOptions>(builder.Configuration.GetSection("Verification"));
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));


builder.Services.AddControllers();

builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity
builder.Services
    .AddIdentity<AppUser, IdentityRole>(opt =>
    {
        opt.User.RequireUniqueEmail = true;
        opt.SignIn.RequireConfirmedEmail =
            builder.Configuration.GetValue("Verification:RequireConfirmedEmail", true);

        opt.Password.RequiredLength = 8;
        opt.Lockout.MaxFailedAccessAttempts = 5;
        opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// JWT
var jwtSection = builder.Configuration.GetSection("Jwt");
var signingKey = jwtSection["SigningKey"]
                 ?? throw new InvalidOperationException("Jwt:SigningKey is missing.");
var keyBytes = Encoding.UTF8.GetBytes(signingKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(opt =>
{
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSection["Issuer"],
        ValidAudience = jwtSection["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
    opt.AddPolicy("SubscriberOnly", p => p.RequireRole("Subscriber"));
});

// App services
builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddSingleton<IMessageSender, DevMessageSender>();


//CORS
var corsPolicyName = "SpaDevCors";

builder.Services.AddCors(options =>
{
    options.AddPolicy(corsPolicyName, policy =>
    {
        policy
            .WithOrigins("http://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials(); // only if you use cookies; safe to keep off otherwise
    });
});

var app = builder.Build();

// Swagger (dev only)
if (app.Environment.IsDevelopment())
{

    await DevSeed.SeedDevAdminAsync(app.Services, app.Configuration);
}

app.UseHttpsRedirection();

app.UseCors(corsPolicyName);


app.UseAuthentication();
app.UseAuthorization();

// Seed roles before mapping endpoints
await Seed.SeedRolesAsync(app.Services);

app.MapControllers();

app.Run();
