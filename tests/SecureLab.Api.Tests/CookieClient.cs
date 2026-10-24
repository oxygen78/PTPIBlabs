using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    public static async Task<HttpClient> LoginAsync(
        this WebApplicationFactory<Program> factory,
        string userName,
        string? password = null)
    {
        var actualPassword = password
            ?? Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        using var response = await client.PostAsJsonAsync(
            "/api/auth/login",
            new { userName, password = actualPassword });

        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }

        // Одразу отримуємо антифорджері-токен у тій самій cookie-сесії і додаємо в заголовок X-CSRF-TOKEN:
        using var tokenRes = await client.GetAsync("/api/antiforgery/token");
        tokenRes.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await tokenRes.Content.ReadAsStringAsync());
        var token = doc.RootElement.GetProperty("token").GetString();

        if (!string.IsNullOrWhiteSpace(token))
        {
            client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token);
        }

        return client;
    }
}