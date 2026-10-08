using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();

        builder.Services.AddAuthorization();

        // Cookie профілю
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        // обмеження частоти запитів (Добрий рівень)
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("login-limit", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 50,
                        Window = TimeSpan.FromSeconds(10),
                        QueueLimit = 0
                    }));
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.UseRateLimiter();

        // Register (T-01, T-02, Duplicate 409)
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrWhiteSpace(input.Email)
                || string.IsNullOrWhiteSpace(input.DisplayName) || string.IsNullOrEmpty(input.Password))
                return Results.BadRequest(new { message = "Усі поля є обов'язковими." });

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName.Trim(),
                Email = input.Email.Trim(),
                DisplayName = input.DisplayName.Trim()
            };

            var result = await users.CreateAsync(user, input.Password);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(e => e.Code).ToList();
                if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
                    return Results.Conflict(new { message = "Користувач з таким ім'ям або email вже існує." });

                return Results.BadRequest(new { message = "Помилка валідації пароля або даних.", errors = codes });
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me", new UserDto(user.Id, user.UserName, user.DisplayName));
        });

        // Login (A-07, Rate Limit, Audit Events)
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn, ILogger<Program> logger, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, isPersistent: false, lockoutOnFailure: false);

            logger.LogInformation("Auth Event: Type={EventType}, User={User}, Result={Result}, Trace={TraceId}",
                "LoginAttempt", input.UserName, result.Succeeded ? "Success" : "Failed", context.TraceIdentifier);

            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting("login-limit");

        // Get Profile (A-01, A-02, A-03)
        app.MapGet("/api/me", (HttpContext context) =>
        {
            var userIdString = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userIdString, out var verifiedUserId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            var userName = context.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;

            return Results.Ok(new UserDto(verifiedUserId, userName, userName));
        }).RequireAuthorization();

        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();

        // Logout (A-06)
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        }).RequireAuthorization();
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record UserDto(Guid Id, string UserName, string DisplayName);