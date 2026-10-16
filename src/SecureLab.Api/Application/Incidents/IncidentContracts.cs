using System.Text.Json.Serialization;

namespace SecureLab.Api.Application.Incidents;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateIncidentRequest(string Title, string Description, string Severity);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record TriageIncidentRequest(string Severity);