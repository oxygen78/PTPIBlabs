using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public static class AntiforgeryTestExtensions
{
    public const string TokenRoute = "/api/antiforgery/token";
    public const string HeaderName = "X-CSRF-TOKEN";

    private sealed record TokenResponse(string Token);

    public static async Task<string> UseAntiforgeryTokenAsync(
        this HttpClient client,
        string tokenRoute = TokenRoute,
        string headerName = HeaderName)
    {
        client.DefaultRequestHeaders.Remove(headerName);
        using var response = await client.GetAsync(tokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
        {
            throw new InvalidOperationException("Missing request token.");
        }

        client.DefaultRequestHeaders.Add(headerName, body.Token);
        return body.Token;
    }
}