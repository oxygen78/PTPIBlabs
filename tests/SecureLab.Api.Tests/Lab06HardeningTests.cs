using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SecureLab.Api.Tests;

public sealed class Lab06HardeningTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private sealed record TokenResponse(string Token);

    [Fact]
    public async Task REG_CSRF_01_MutationWithoutTokenIsRejected_StateUnchanged_ThenValidPairSucceeds()
    {
        using var client = await factory.LoginAsync("alice");
        client.DefaultRequestHeaders.Remove(AntiforgeryTestExtensions.HeaderName);
        // 1. Читаємо початковий стан списку інцидентів
        var beforeList = await client.GetFromJsonAsync<JsonElement>("/api/incidents");
        int countBefore = beforeList.GetArrayLength();

        var payload = new
        {
            title = "CSRF Regression Test Incident",
            description = "Created only when valid antiforgery token pair is present.",
            severity = "Medium",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };
        // 2. Негативна перевірка: активна auth-cookie є, але request header X-CSRF-TOKEN відсутній
        using var rejected = await client.PostAsJsonAsync("/api/incidents", payload);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);

        // 3. Перевірка незмінності стану після відмови
        var afterRejectedList = await client.GetFromJsonAsync<JsonElement>("/api/incidents");
        Assert.Equal(countBefore, afterRejectedList.GetArrayLength());

        // 4. Негативна перевірка з невалідним токеном
        using var badRequestMsg = new HttpRequestMessage(HttpMethod.Post, "/api/incidents")
        {
            Content = JsonContent.Create(payload)
        };
        badRequestMsg.Headers.Add(AntiforgeryTestExtensions.HeaderName, "invalid-synthetic-token");
        using var rejectedInvalid = await client.SendAsync(badRequestMsg);
        Assert.Equal(HttpStatusCode.BadRequest, rejectedInvalid.StatusCode);

        // 5. Позитивна перевірка: отримуємо валідний токен тією самою сесією і повторюємо запит
        var tokenDto = await client.GetFromJsonAsync<TokenResponse>(AntiforgeryTestExtensions.TokenRoute);
        Assert.False(string.IsNullOrWhiteSpace(tokenDto?.Token));

        using var validRequestMsg = new HttpRequestMessage(HttpMethod.Post, "/api/incidents")
        {
            Content = JsonContent.Create(payload)
        };
        validRequestMsg.Headers.Add(AntiforgeryTestExtensions.HeaderName, tokenDto!.Token);
        using var accepted = await client.SendAsync(validRequestMsg);
        Assert.True(
            accepted.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK,
            $"Expected 201/200, got {accepted.StatusCode}");

        // 6. Перевірка зміни стану після легітимного запиту
        var afterAcceptedList = await client.GetFromJsonAsync<JsonElement>("/api/incidents");
        Assert.Equal(countBefore + 1, afterAcceptedList.GetArrayLength());
    }

    [Fact]
    public async Task REG_RL_01_SearchRateLimiter_EnforcesQuotaPerUserPartition_AndIsolatesOtherUsers()
    {
        using var aliceClient = await factory.LoginAsync("alice");
        using var bobClient = await factory.LoginAsync("bob");

        // Вичерпуємо квоту (5 запитів за 15 с) для partition користувача alice
        for (int i = 0; i < 5; i++)
        {
            using var okResponse = await aliceClient.GetAsync("/api/incidents/search?q=test");
            Assert.Equal(HttpStatusCode.OK, okResponse.StatusCode);
        }

        // 6-й запит alice має повернути 429 Too Many Requests
        using var throttledResponse = await aliceClient.GetAsync("/api/incidents/search?q=test");
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResponse.StatusCode);

        // Незалежний partition користувача bob не заблоковано — повертає 200 OK
        using var bobResponse = await bobClient.GetAsync("/api/incidents/search?q=test");
        Assert.Equal(HttpStatusCode.OK, bobResponse.StatusCode);
    }

    [Fact]
    public async Task ProductionProfile_Preserves4xxSemantics_HidesOpenApi_AndIncludesSecurityHeaders()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting(
                "ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;Password=local-study-password;Include Error Detail=false");
        });

        Assert.Equal(
            "Production",
            production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);

        using var client = await production.LoginAsync("alice");

        // OpenAPI вимкнено у Production
        using var openApiResp = await client.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.NotFound, openApiResp.StatusCode);

        // Validation 400
        using var invalidStatusResp = await client.GetAsync("/api/incidents?status=Unknown");
        Assert.Equal(HttpStatusCode.BadRequest, invalidStatusResp.StatusCode);
        Assert.True(invalidStatusResp.Headers.TryGetValues("X-Content-Type-Options", out var nosniff)
                    && nosniff.Contains("nosniff"));

        // Unknown resource 404
        using var notFoundResp = await client.GetAsync("/api/incidents/99999999-9999-9999-9999-999999999999");
        Assert.Equal(HttpStatusCode.NotFound, notFoundResp.StatusCode);
    }
}