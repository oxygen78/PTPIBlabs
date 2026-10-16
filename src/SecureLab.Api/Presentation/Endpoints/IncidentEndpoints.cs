using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", async (IncidentQueries queries, CancellationToken cancellationToken) =>
        {
            var result = await queries.GetSeveritySummaryAsync(cancellationToken);
            return Results.Ok(result);
        })
        .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .WithTags("IncidentComments")
            .RequireAuthorization()
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static void AuditDenied(
        HttpContext httpContext,
        Guid resourceId,
        string action,
        ILogger logger)
    {
        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} "
            + "resource={ResourceId} result={Result} "
            + "occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
            action,
            resourceId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
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

        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var ownerId))
        {
            return Results.Challenge();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var isReporter = httpContext.User.IsInRole(DbSeeder.ReporterRole);

        return Results.Ok(await queries.GetListAsync(
            parsedStatus,
            ownerId,
            isAnalyst,
            isReporter,
            cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out _))
        {
            return Results.Challenge();
        }

        var incident = await queries.FindEntityAsync(id, asTracking: false, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Read);
        if (!decision.Succeeded)
        {
            return IncidentNotFound();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var dto = await queries.GetDetailsDtoAsync(
            id,
            includeInternalComments: isAnalyst,
            cancellationToken);

        return dto is null
            ? IncidentNotFound()
            : Results.Ok(dto);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out _))
        {
            return Results.Challenge();
        }

        var incident = await queries.FindEntityAsync(id, asTracking: true, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canUpdate = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Update);
        if (!canUpdate.Succeeded)
        {
            AuditDenied(httpContext, incident.Id, "incident.update", logger);
            return Results.Forbid();
        }

        var errors = new Dictionary<string, string[]>();
        var trimmedTitle = request.Title?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(trimmedTitle))
        {
            errors["title"] = ["Поле title є обов'язковим."];
        }
        else if (trimmedTitle.Length > 160)
        {
            errors["title"] = ["Максимальна довжина title становить 160 символів."];
        }

        string? trimmedDescription = null;
        if (request.Description is not null)
        {
            trimmedDescription = request.Description.Trim();
            if (string.IsNullOrEmpty(trimmedDescription))
            {
                errors["description"] = ["Поле description не може бути порожнім."];
            }
            else if (trimmedDescription.Length > 4000)
            {
                errors["description"] = ["Максимальна довжина description становить 4000 символів."];
            }
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        incident.Title = trimmedTitle;
        if (trimmedDescription is not null)
        {
            incident.Description = trimmedDescription;
        }
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out _))
        {
            return Results.Challenge();
        }

        var incident = await queries.FindEntityAsync(id, asTracking: true, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canDelete = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Delete);
        if (!canDelete.Succeeded)
        {
            AuditDenied(httpContext, incident.Id, "incident.delete", logger);
            return Results.Forbid();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] TriageIncidentRequest? request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var changedByUserId))
        {
            return Results.Challenge();
        }

        var incident = await queries.FindEntityAsync(id, asTracking: true, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canTriage = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Triage);
        if (!canTriage.Succeeded)
        {
            AuditDenied(httpContext, incident.Id, "incident.triage", logger);
            return Results.Forbid();
        }

        var now = DateTimeOffset.UtcNow;
        var oldStatus = incident.Status;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;

        var note = string.IsNullOrWhiteSpace(request?.Note)
            ? "Переведено у статус Triaged аналітиком."
            : request.Note.Trim();
        if (note.Length > 1000)
        {
            note = note[..1000];
        }

        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = changedByUserId,
            OldStatus = oldStatus,
            NewStatus = IncidentStatus.Triaged,
            Note = note,
            CreatedAtUtc = now
        });

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Results.Challenge();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var isReporter = httpContext.User.IsInRole(DbSeeder.ReporterRole);

        var comment = await queries.GetCommentByIdAsync(
            id,
            userId,
            isAnalyst,
            isReporter,
            cancellationToken);

        return comment is null
            ? IncidentNotFound()
            : Results.Ok(comment);
    }
}