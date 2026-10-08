using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationMechanicsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword => Environment.GetEnvironmentVariable("SeedUsers__Password") ?? throw new InvalidOperationException("Set password.");

    [Fact]
    public async Task A01_AnonymousRequest_Returns401()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task A02_Login_GetsProfileSuccessfully()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A03_SpoofedHeader_DoesNotChangeProfile()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = await client.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("alice", content);
    }

    [Fact]
    public async Task A04_A05_CreateIncident_SetsOwnerToPrincipal_IgnoresPayloadOwner()
    {
        using var bobClient = await factory.LoginAsync("bob", StudyPassword);
        var payload = new
        {
            title = $"Test {Guid.NewGuid()}",
            description = "Test Description 1234567890123456789012345678901234567890",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = DbSeeder.AliceId // A-05 Forged owner
        };

        using var response = await bobClient.PostAsJsonAsync("/api/incidents", payload);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.OrderByDescending(i => i.CreatedAtUtc).FirstAsync();

        // Власник повинен бути Bob, незважаючи на AliceId у пейлоаді
        Assert.Equal(DbSeeder.BobId, incident.OwnerUserId);
    }

    [Fact]
    public async Task A06_Logout_Returns401OnSubsequentRequests()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        await client.PostAsync("/api/auth/logout", null);
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUser_And_BadPassword_ReturnIdenticalResponse()
    {
        using var client = factory.CreateClient();
        using var badUser = await client.PostAsJsonAsync("/api/auth/login", new { userName = "nobody", password = "BadPassword1!" });
        using var badPass = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password = "BadPassword1!" });

        Assert.Equal(HttpStatusCode.Unauthorized, badUser.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, badPass.StatusCode);
        Assert.Equal(badUser.Content.Headers.ContentType?.MediaType, badPass.Content.Headers.ContentType?.MediaType);
    }
}