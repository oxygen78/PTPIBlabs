using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var order = sortBy switch
            {
                null or "" or "createdAtUtc" => "created_at_utc DESC",
                "severity" => "severity",
                "status" => "status",
                _ => sortBy
            };
            var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "")
                + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";
            var rows = await db.Incidents.FromSqlRaw(sql).AsNoTracking().ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id,
                row.Title,
                row.Description,
                Severity = row.Severity.ToString(),
                Status = row.Status.ToString(),
                row.CreatedAtUtc
            }));
        });

        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
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
                errors["occurredAtUtc"] = ["Час виникнення інциденту не може випереджати поточний UTC-час сервера більш ніж на 5 хвилин."];
            }

            if (isSeverityValid
                && (severity is IncidentSeverity.High or IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && trimmedDescription.Length < 40)
            {
                errors["description"] = ["Для рівнів High або Critical опис після Trim() має містити щонайменше 40 символів."];
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
                OwnerUserId = DbSeeder.AliceId,
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
        });
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