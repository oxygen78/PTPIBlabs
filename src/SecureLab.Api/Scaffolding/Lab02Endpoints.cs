using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    // Екранування спецсимволів шаблону ILIKE (\, %, _)
    private static string EscapeLikePattern(string input)
    {
        return input
            .Replace(@"\", @"\\", StringComparison.Ordinal)
            .Replace("%", @"\%", StringComparison.Ordinal)
            .Replace("_", @"\_", StringComparison.Ordinal);
    }

    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var normalizedSortBy = string.IsNullOrWhiteSpace(sortBy)
                ? "createdAtUtc"
                : sortBy.Trim();

            if (normalizedSortBy is not ("createdAtUtc" or "severity" or "status"))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення sortBy: createdAtUtc, severity, status."]
                });
            }

            IQueryable<Incident> query = db.Incidents.AsNoTracking();

            if (!string.IsNullOrWhiteSpace(q))
            {
                var escaped = EscapeLikePattern(q.Trim());
                var pattern = $"%{escaped}%";

                query = query.Where(incident =>
                    EF.Functions.ILike(incident.Title, pattern, @"\") ||
                    EF.Functions.ILike(incident.Description, pattern, @"\"));
            }
            query = normalizedSortBy switch
            {
                "severity" => query
                    .OrderBy(incident =>
                        incident.Severity == IncidentSeverity.Critical ? 1 :
                        incident.Severity == IncidentSeverity.High ? 2 :
                        incident.Severity == IncidentSeverity.Medium ? 3 : 4)
                    .ThenByDescending(incident => incident.CreatedAtUtc),

                "status" => query
                    .OrderBy(incident =>
                        incident.Status == IncidentStatus.New ? 1 :
                        incident.Status == IncidentStatus.Triaged ? 2 :
                        incident.Status == IncidentStatus.InProgress ? 3 :
                        incident.Status == IncidentStatus.Resolved ? 4 : 5)
                    .ThenByDescending(incident => incident.CreatedAtUtc),

                _ => query.OrderByDescending(incident => incident.CreatedAtUtc)
            };

            var rows = await query
                .Take(50)
                .Select(row => new IncidentSearchResponse(
                    row.Id,
                    row.Title,
                    row.Description,
                    row.Severity.ToString(),
                    row.Status.ToString(),
                    row.CreatedAtUtc))
                .ToListAsync(ct);

            return Results.Ok(rows);
        });

        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, HttpContext context, CancellationToken ct) =>
         {
             var userIdString = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
             if (!Guid.TryParse(userIdString, out var verifiedUserId))
             {
                 return Results.Unauthorized();
             }

             var now = DateTimeOffset.UtcNow;
             var errors = new Dictionary<string, string[]>();

             var trimmedTitle = request.Title?.Trim() ?? string.Empty;
             var trimmedDescription = request.Description?.Trim() ?? string.Empty;

             if (string.IsNullOrEmpty(trimmedTitle))
             {
                 errors["title"] = ["Поле title є обов'язковим."];
             }
             else if (trimmedTitle.Length > 160)
             {
                 errors["title"] = ["Максимальна довжина title становить 160 символів."];
             }

             if (string.IsNullOrEmpty(trimmedDescription))
             {
                 errors["description"] = ["Поле description є обов'язковим."];
             }
             else if (trimmedDescription.Length > 4000)
             {
                 errors["description"] = ["Максимальна довжина description становить 4000 символів."];
             }

             IncidentSeverity severity = default;
             var isSeverityValid = !string.IsNullOrWhiteSpace(request.Severity)
                 && Enum.TryParse<IncidentSeverity>(request.Severity.Trim(), ignoreCase: true, out severity)
                 && Enum.IsDefined(severity);

             if (!isSeverityValid)
             {
                 errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
             }

             if (request.OccurredAtUtc is null)
             {
                 errors["occurredAtUtc"] = ["Поле occurredAtUtc є обов'язковим."];
             }
             else if (request.OccurredAtUtc.Value > now.AddMinutes(5))
             {
                 errors["occurredAtUtc"] = ["Час виникнення не може випереджати поточний UTC-час сервера більш ніж на 5 хвилин."];
             }

             if (isSeverityValid
                 && (severity is IncidentSeverity.High or IncidentSeverity.Critical)
                 && !errors.ContainsKey("description")
                 && trimmedDescription.Length < 40)
             {
                 errors["description"] = ["Для рівнів High та Critical опис після Trim() має містити щонайменше 40 символів."];
             }

             if (request.OccurredAtUtc is not null
                 && !errors.ContainsKey("occurredAtUtc")
                 && request.OccurredAtUtc.Value < now.AddDays(-365))
             {
                 errors["occurredAtUtc"] = ["Дата виникнення інциденту не може бути старішою за 365 днів."];
             }

             if (errors.Count > 0)
             {
                 return Results.ValidationProblem(errors);
             }

             var hasActiveDuplicate = await db.Incidents
                 .AsNoTracking()
                 .AnyAsync(
                     i => i.Title == trimmedTitle && i.Status != IncidentStatus.Closed,
                     ct);

             if (hasActiveDuplicate)
             {
                 return Results.Problem(
                     title: "Конфлікт створення інциденту",
                     detail: "Активний інцидент із таким заголовком уже існує.",
                     statusCode: StatusCodes.Status409Conflict);
             }

             var incident = new Incident
             {
                 Id = Guid.NewGuid(),
                 OwnerUserId = verifiedUserId,
                 Title = trimmedTitle,
                 Description = trimmedDescription,
                 Severity = severity,
                 Status = IncidentStatus.New,
                 OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                 CreatedAtUtc = now,
                 UpdatedAtUtc = now
             };

             db.Incidents.Add(incident);
             await db.SaveChangesAsync(ct);

             var response = new CreatedIncidentResponse(
                 incident.Id,
                 incident.Title,
                 incident.Severity.ToString(),
                 incident.Status.ToString(),
                 incident.OccurredAtUtc,
                 incident.CreatedAtUtc,
                 incident.UpdatedAtUtc);

             return Results.Created($"/api/incidents/{incident.Id}", response);
         }).RequireAuthorization();
    }
}

public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record IncidentSearchResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset CreatedAtUtc);