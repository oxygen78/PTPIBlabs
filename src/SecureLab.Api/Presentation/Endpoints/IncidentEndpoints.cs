using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", async (IncidentQueries queries, CancellationToken cancellationToken) =>
        {
            var result = await queries.GetSeveritySummaryAsync(cancellationToken);
            return Results.Ok(result);
        })
        .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();

        group.MapPut("/{id:guid}", async (Guid id, UpdateIncidentRequest request, SecureLabDbContext dbContext, CancellationToken ct) =>
        {
            // ВРАЗЛИВІСТЬ IDOR: шукаємо лише за ID без перевірки власника
            var incident = await dbContext.Incidents.SingleOrDefaultAsync(i => i.Id == id, ct);
            if (incident is null)
            {
                return Results.NotFound();
            }

            if (!string.IsNullOrWhiteSpace(request.Title))
            {
                incident.Title = request.Title.Trim();
            }
            if (!string.IsNullOrWhiteSpace(request.Description))
            {
                incident.Description = request.Description.Trim();
            }
            if (!string.IsNullOrWhiteSpace(request.Severity) && Enum.TryParse<IncidentSeverity>(request.Severity, true, out var parsedSeverity))
            {
                incident.Severity = parsedSeverity;
            }

            incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await dbContext.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        group.MapDelete("/{id:guid}", async (Guid id, SecureLabDbContext dbContext, CancellationToken ct) =>
        {
            var incident = await dbContext.Incidents.SingleOrDefaultAsync(i => i.Id == id, ct);
            if (incident is null)
            {
                return Results.NotFound();
            }

            dbContext.Incidents.Remove(incident);
            await dbContext.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }
}
