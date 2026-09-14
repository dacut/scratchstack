$version: "2"
namespace net.scratchstack.cloud

/// Creates a quota definition for a service.
@http(method: "PUT", uri: "/Quota/{ServiceId}/{QuotaName}")
@idempotent
@unstable
operation CreateQuotaDefinition {
    input: CreateQuotaDefinitionRequest
    output: CreateQuotaDefinitionResponse
}

/// Input parameters to the CreateQuotaDefinition endpoint.
@input
@unstable
structure CreateQuotaDefinitionRequest {
    /// The service this quota is scoped to.
    @required
    @httpLabel
    ServiceId: serviceIdType

    /// The quota being defined.
    @required
    @httpLabel
    QuotaName: quotaNameType

    /// The scope of the quota.
    @required
    Scope: QuotaScope

    /// A description of the quota.
    Description: descriptionType

    /// The default value of the quota.
    DefaultValue: quotaValueType

    /// The unit of quota values.
    Unit: quotaUnitType

    /// The minimum value of the quota.
    MinValue: quotaValueType

    /// The maximum value of the quota.
    MaxValue: quotaValueType
}

/// Response from the CreateQuotaDefinition endpoint.
@output
@unstable
structure CreateQuotaDefinitionResponse {
    @required
    QuotaDefinition: QuotaDefinition
}
