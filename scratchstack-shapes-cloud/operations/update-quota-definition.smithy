$version: "2"
namespace net.scratchstack.cloud

/// Updates a quota definition for a service.
@http(method: "PATCH", uri: "/Quota/{ServiceId}/{QuotaName}")
@idempotent
@unstable
operation UpdateQuotaDefinition {
    input: UpdateQuotaDefinitionRequest
    output: UpdateQuotaDefinitionResponse
}

/// Input parameters to the UpdateQuotaDefinition endpoint.
@input
@unstable
structure UpdateQuotaDefinitionRequest {
    /// The service this quota is scoped to.
    @required
    @httpLabel
    ServiceId: serviceIdType

    /// The quota being defined.
    @required
    @httpLabel
    QuotaName: quotaNameType

    /// The description of the quota. If unset, the definition is unchanged.
    Description: descriptionType

    /// The default value of the quota. If unset, the default value is unchanged.
    DefaultValue: quotaValueType

    /// The unit of quota values. If unset, the unit is unchanged.
    ///
    /// # Note
    /// This does not translate existing quota values into the new units; they will naïvely take
    /// their numeric value and apply it to the new unit.
    Unit: quotaUnitType

    /// The minimum value of the quota. If unset, the minimum value is unchanged.
    ///
    /// # Note
    /// This does not update existing quotas. If a minimum value is specified that is greater than
    /// an existing quota, that quota is unaffected.
    MinValue: quotaValueType

    /// The maximum value of the quota. If unset, the maximum value is unchanged.
    ///
    /// # Note
    /// This does not update existing quotas. If a maximum value is specified that is less than
    /// an existing quota, that quota is unaffected.
    MaxValue: quotaValueType
}

/// Response from the UpdateQuotaDefinition endpoint.
@output
@unstable
structure UpdateQuotaDefinitionResponse {
    @required
    QuotaDefinition: QuotaDefinition
}
