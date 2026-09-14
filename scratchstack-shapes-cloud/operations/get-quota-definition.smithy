$version: "2"
namespace net.scratchstack.cloud

/// Retrieves a quota definition for a service.
@http(method: "GET", uri: "/Quota/{ServiceId}/{QuotaName}")
@readonly
@unstable
operation GetQuotaDefinition {
    input: GetQuotaDefinitionRequest
    output: GetQuotaDefinitionResponse
}

/// Input parameters to the GetQuotaDefinition endpoint.
@input
@unstable
structure GetQuotaDefinitionRequest {
    /// The service this quota is scoped to.
    @required
    @httpLabel
    ServiceId: serviceIdType

    /// The quota being defined.
    @required
    @httpLabel
    QuotaName: quotaNameType
}

/// Response from the GetQuotaDefinition endpoint.
@output
@unstable
structure GetQuotaDefinitionResponse {
    @required
    QuotaDefinition: QuotaDefinition
}
