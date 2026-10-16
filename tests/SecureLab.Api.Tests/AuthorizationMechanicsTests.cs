using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class AuthorizationMechanicsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private async Task<Guid> CreateFixtureIncidentAsync(HttpClient client, string titlePrefix)
    {
        var payload = new
        {
            title = $"{titlePrefix}-{Guid.NewGuid():N}",
            description = "Навчальний тестовий опис інциденту достатньої довжини для перевірки.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var response = await client.PostAsJsonAsync("/api/incidents", payload);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        Assert.NotNull(created);
        return created.Id;
    }

    private async Task CleanupIncidentAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentComments.Where(c => c.IncidentId == incidentId).ExecuteDeleteAsync();
        await db.IncidentStatusHistory.Where(h => h.IncidentId == incidentId).ExecuteDeleteAsync();
        await db.Incidents.Where(i => i.Id == incidentId).ExecuteDeleteAsync();
    }

    [Fact]
    public async Task A01_AnonymousRequests_ToProtectedEndpoints_Return401WithoutRedirect()
    {
        using var anon = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var listRes = await anon.GetAsync("/api/incidents");
        using var detailsRes = await anon.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var updateRes = await anon.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = "Anon Update" });
        using var deleteRes = await anon.DeleteAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var triageRes = await anon.PostAsync(
            $"/api/incidents/{DbSeeder.SafeTextIncidentId}/triage",
            content: null);
        using var commentRes = await anon.GetAsync($"/api/incident-comments/{DbSeeder.AliceCommentId}");

        foreach (var response in new[] { listRes, detailsRes, updateRes, deleteRes, triageRes, commentRes })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
        }
    }

    [Fact]
    public async Task A02_Owner_CanReadAndUpdateOwnIncident()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        // Read own seeded incident
        using var readRes = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, readRes.StatusCode);
        var details = await readRes.Content.ReadFromJsonAsync<IncidentDetailsResponse>();
        Assert.NotNull(details);
        Assert.Equal(DbSeeder.AliceIncidentId, details.Id);
        Assert.Equal("Підозрілий лист із вкладенням", details.Title);

        // Update own created fixture incident
        var fixtureId = await CreateFixtureIncidentAsync(alice, "A02-OwnUpdate");
        try
        {
            var newTitle = $"Updated-{Guid.NewGuid():N}";
            using var updateRes = await alice.PutAsJsonAsync(
                $"/api/incidents/{fixtureId}",
                new { title = newTitle, description = "Оновлений опис власного інциденту." });

            Assert.Equal(HttpStatusCode.NoContent, updateRes.StatusCode);

            var updated = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{fixtureId}");
            Assert.NotNull(updated);
            Assert.Equal(newTitle, updated.Title);
            Assert.Equal("Оновлений опис власного інциденту.", updated.Description);
        }
        finally
        {
            await CleanupIncidentAsync(fixtureId);
        }
    }

    [Fact]
    public async Task A03_A10_ReadForeignIncident_ReturnsIdentical404ToUnknownId_WithoutDataDisclosure()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());

        var foreignRaw = await foreign.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Невідома спроба входу", foreignRaw, StringComparison.Ordinal);
        Assert.DoesNotContain("Боб Мельник", foreignRaw, StringComparison.Ordinal);
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), foreignRaw, StringComparison.OrdinalIgnoreCase);

        var foreignBody = JsonNode.Parse(foreignRaw)?.AsObject();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        Assert.NotNull(foreignBody);
        Assert.NotNull(unknownBody);

        foreignBody.Remove("traceId");
        foreignBody.Remove("requestId");
        unknownBody.Remove("traceId");
        unknownBody.Remove("requestId");

        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    [Fact]
    public async Task A03R_Analyst_CanReadForeignDetails_ButCannotUpdateOrDelete()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var before = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.NotNull(before);

        // Analyst reads Alice's incident for analysis (Entry-contract Lab 5)
        using var readRes = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, readRes.StatusCode);
        var analystView = await readRes.Content.ReadFromJsonAsync<IncidentDetailsResponse>();
        Assert.NotNull(analystView);
        Assert.Equal(DbSeeder.AliceIncidentId, analystView.Id);

        // Analyst cannot arbitrarily modify or delete Alice's incident
        using var updateRes = await morgan.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = "Changed by Analyst", description = "Forbidden edit" });
        Assert.Equal(HttpStatusCode.Forbidden, updateRes.StatusCode);

        using var deleteRes = await morgan.DeleteAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.Forbidden, deleteRes.StatusCode);

        var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.NotNull(after);
        Assert.Equal(before.Title, after.Title);
        Assert.Equal(before.Description, after.Description);
    }

    [Fact]
    public async Task A04_NonOwner_UpdateAndDelete_AreDeniedWith404_AndDoNotChangeState()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        var before = await bob.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.NotNull(before);

        using var updateRes = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "Hacked by Alice", description = "Tampered description" });
        Assert.Equal(HttpStatusCode.NotFound, updateRes.StatusCode);

        using var deleteRes = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, deleteRes.StatusCode);

        var after = await bob.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.NotNull(after);
        Assert.Equal(before.Title, after.Title);
        Assert.Equal(before.Description, after.Description);
        Assert.Equal(before.Status, after.Status);
    }

    [Fact]
    public async Task A05_GetList_ScopesIncidentsByOwnerForReporter_AndAllowsAllForAnalyst()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        var aliceList = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        Assert.NotNull(aliceList);
        Assert.Contains(aliceList, i => i.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(aliceList, i => i.Id == DbSeeder.SafeTextIncidentId);
        Assert.DoesNotContain(aliceList, i => i.Id == DbSeeder.BobIncidentId);

        var bobList = await bob.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        Assert.NotNull(bobList);
        Assert.Contains(bobList, i => i.Id == DbSeeder.BobIncidentId);
        Assert.DoesNotContain(bobList, i => i.Id == DbSeeder.AliceIncidentId);

        var morganList = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        Assert.NotNull(morganList);
        Assert.Contains(morganList, i => i.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(morganList, i => i.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task A06_A09_Reporter_TriageAttempt_Returns403WithTraceId_AndDoesNotChangeStatus()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var before = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.SafeTextIncidentId}");
        Assert.NotNull(before);
        Assert.Equal("New", before.Status);

        using var response = await alice.PostAsJsonAsync(
            $"/api/incidents/{DbSeeder.SafeTextIncidentId}/triage",
            new
            {
                note = "Attempted vertical escalation",
                role = "Analyst",
                status = "Triaged",
                isTransitionAllowed = true
            });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.NotNull(problem);
        Assert.True(problem.ContainsKey("traceId"));
        Assert.False(string.IsNullOrWhiteSpace(problem["traceId"]?.GetValue<string>()));

        var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.SafeTextIncidentId}");
        Assert.NotNull(after);
        Assert.Equal("New", after.Status);
    }

    [Fact]
    public async Task A07_Analyst_CanTriageNewIncident_AndRepeatedTriageIsDenied()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        var fixtureId = await CreateFixtureIncidentAsync(alice, "A07-Triage");
        try
        {
            using var triageRes = await morgan.PostAsJsonAsync(
                $"/api/incidents/{fixtureId}/triage",
                new { note = "Класифіковано аналітиком у тесті A-07." });
            Assert.Equal(HttpStatusCode.NoContent, triageRes.StatusCode);

            var afterTriage = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
                $"/api/incidents/{fixtureId}");
            Assert.NotNull(afterTriage);
            Assert.Equal("Triaged", afterTriage.Status);

            // Повторний перехід зі статусу Triaged не дозволений (тільки New -> Triaged)
            using var secondTriageRes = await morgan.PostAsJsonAsync(
                $"/api/incidents/{fixtureId}/triage",
                new { note = "Повторний triage" });
            Assert.Equal(HttpStatusCode.Forbidden, secondTriageRes.StatusCode);
        }
        finally
        {
            await CleanupIncidentAsync(fixtureId);
        }
    }

    [Fact]
    public async Task A08a_RegularUpdate_IgnoresForgedOwnerStatusAndRoleFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var fixtureId = await CreateFixtureIncidentAsync(alice, "A08a-Overpost");
        try
        {
            var updatedTitle = $"SafeTitle-{Guid.NewGuid():N}";
            var forgedPayload = new
            {
                title = updatedTitle,
                description = "Дозволене оновлення опису без зміни захищених полів.",
                ownerUserId = DbSeeder.BobId,
                status = "Closed",
                severity = "Critical",
                role = "Analyst"
            };

            using var response = await alice.PutAsJsonAsync($"/api/incidents/{fixtureId}", forgedPayload);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var entity = await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == fixtureId);

            Assert.Equal(updatedTitle, entity.Title);
            Assert.Equal(DbSeeder.AliceId, entity.OwnerUserId);
            Assert.Equal(IncidentStatus.New, entity.Status);
            Assert.Equal(IncidentSeverity.Low, entity.Severity);
        }
        finally
        {
            await CleanupIncidentAsync(fixtureId);
        }
    }

    [Fact]
    public async Task A12_ChildCommentEndpoint_AndDetailsProjection_EnforceParentOwnershipAndInternalRule()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        // 1. Alice (Reporter) не може прочитати коментар до чужого інциденту Bob (comment-2)
        using var foreignCommentRes = await alice.GetAsync($"/api/incident-comments/{DbSeeder.BobCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, foreignCommentRes.StatusCode);

        // 2. Alice (Reporter, навіть власниця інциденту) не може прочитати internal comment-3 напряму
        using var internalCommentAsAlice = await alice.GetAsync($"/api/incident-comments/{DbSeeder.InternalCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, internalCommentAsAlice.StatusCode);

        // 3. Alice бачить публічний comment-1 до власного інциденту, але не бачить internal comment-3 у details
        var aliceDetails = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.NotNull(aliceDetails);
        Assert.Contains(aliceDetails.Comments, c => c.Id == DbSeeder.AliceCommentId);
        Assert.DoesNotContain(aliceDetails.Comments, c => c.Id == DbSeeder.InternalCommentId);

        // 4. Morgan (Analyst) бачить internal comment-3 і в details, і за прямим маршрутом
        var morganDetails = await morgan.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.NotNull(morganDetails);
        Assert.Contains(morganDetails.Comments, c => c.Id == DbSeeder.InternalCommentId);

        using var internalCommentAsMorgan = await morgan.GetAsync($"/api/incident-comments/{DbSeeder.InternalCommentId}");
        Assert.Equal(HttpStatusCode.OK, internalCommentAsMorgan.StatusCode);
    }
}