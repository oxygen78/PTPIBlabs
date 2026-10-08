using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Search_ReturnsUsbSeed_AndHandlesApostrophe()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=USB");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = await response.Content.ReadFromJsonAsync<List<IncidentSearchResponse>>();
        Assert.NotNull(items);
        Assert.Single(items);

        var aposQuery = Uri.EscapeDataString("комп'ютерного");
        using var aposResponse = await _client.GetAsync($"/api/incidents/search?q={aposQuery}");
        Assert.Equal(HttpStatusCode.OK, aposResponse.StatusCode);
        var aposItems = await aposResponse.Content.ReadFromJsonAsync<List<IncidentSearchResponse>>();
        Assert.NotNull(aposItems);
        Assert.Single(aposItems);
    }

    [Fact]
    public async Task Search_ControlledSqliAndWildcards_DoNotExpandResults()
    {
        var sqliQuery = Uri.EscapeDataString("zz-no-match' OR TRUE --");
        using var sqliResponse = await _client.GetAsync($"/api/incidents/search?q={sqliQuery}");
        Assert.Equal(HttpStatusCode.OK, sqliResponse.StatusCode);
        var sqliItems = await sqliResponse.Content.ReadFromJsonAsync<List<IncidentSearchResponse>>();
        Assert.NotNull(sqliItems);
        Assert.Empty(sqliItems);

        using var percentResponse = await _client.GetAsync("/api/incidents/search?q=%25");
        Assert.Equal(HttpStatusCode.OK, percentResponse.StatusCode);
        var percentItems = await percentResponse.Content.ReadFromJsonAsync<List<IncidentSearchResponse>>();
        Assert.NotNull(percentItems);
        Assert.Empty(percentItems);
    }

    [Fact]
    public async Task Search_DefaultAndUnknownSortBy_BehavesAccordingToAllowlist()
    {
        using var defaultSortResponse = await _client.GetAsync("/api/incidents/search?q=USB");
        Assert.Equal(HttpStatusCode.OK, defaultSortResponse.StatusCode);

        using var invalidSortResponse = await _client.GetAsync("/api/incidents/search?q=USB&sortBy=unknownColumn");
        Assert.Equal(HttpStatusCode.BadRequest, invalidSortResponse.StatusCode);
        Assert.Equal("application/problem+json", invalidSortResponse.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Create_ValidAndDuplicateActiveTitle_Returns201Then409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var payload = new
        {
            title,
            description = new string('A', 45),
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        using var firstResponse = await _client.PostAsJsonAsync("/api/incidents", payload);
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

        using var secondResponse = await _client.PostAsJsonAsync("/api/incidents", payload);
        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
        Assert.Equal("application/problem+json", secondResponse.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Create_InvalidSeverity7_AndCrossFieldBoundaries_ReturnExpectedStatuses()
    {
        var invalidSev = new
        {
            title = $"Sev7-{Guid.NewGuid():N}",
            description = "Valid description for low severity.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow
        };
        using var sevRes = await _client.PostAsJsonAsync("/api/incidents", invalidSev);
        Assert.Equal(HttpStatusCode.BadRequest, sevRes.StatusCode);

        var cross39 = new
        {
            title = $"Cross39-{Guid.NewGuid():N}",
            description = "  " + new string('X', 39) + "  ",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow
        };
        using var res39 = await _client.PostAsJsonAsync("/api/incidents", cross39);
        Assert.Equal(HttpStatusCode.BadRequest, res39.StatusCode);

        var cross40 = new
        {
            title = $"Cross40-{Guid.NewGuid():N}",
            description = "  " + new string('X', 40) + "  ",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow
        };
        using var res40 = await _client.PostAsJsonAsync("/api/incidents", cross40);
        Assert.Equal(HttpStatusCode.Created, res40.StatusCode);
    }

    [Fact]
    public async Task Create_StaleOccurredAtUtc_Returns400_AndMassAssignmentIsIgnored()
    {
        var stalePayload = new
        {
            title = $"Stale-{Guid.NewGuid():N}",
            description = "Valid description text.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-400)
        };
        using var staleRes = await _client.PostAsJsonAsync("/api/incidents", stalePayload);
        Assert.Equal(HttpStatusCode.BadRequest, staleRes.StatusCode);

        var overpostPayload = new
        {
            title = $"Overpost-{Guid.NewGuid():N}",
            description = "Valid description text.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = Guid.NewGuid(),
            status = "Closed"
        };
        using var overpostRes = await _client.PostAsJsonAsync("/api/incidents", overpostPayload);
        Assert.Equal(HttpStatusCode.Created, overpostRes.StatusCode);
        using var doc = JsonDocument.Parse(await overpostRes.Content.ReadAsStringAsync());
        Assert.Equal("New", doc.RootElement.GetProperty("status").GetString());
        Assert.False(doc.RootElement.TryGetProperty("ownerUserId", out _));
    }
}