$version: "2"
namespace net.scratchstack.cloud

/// Deletes a quota definition for a service.
@http(method: "DELETE", uri: "/Quota/{ServiceId}/{QuotaName}")
@idempotent
@unstable
operation DeleteQuotaDefinition {
    input: DeleteQuotaDefinitionRequest
    output: smithy.api#Unit
}

/// Input parameters to the CreateQuotaDefinition endpoint.
@input
@unstable
structure DeleteQuotaDefinitionRequest {
    /// The service this quota is scoped to.
    @required
    @httpLabel
    ServiceId: serviceIdType

    /// The quota being deleted.
    @required
    @httpLabel
    QuotaName: quotaNameType
}
