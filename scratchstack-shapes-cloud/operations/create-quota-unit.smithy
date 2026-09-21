$version: "2"
namespace net.scratchstack.cloud

/// Creates a unit that can be used in quota definitions.
@http(method: "PUT", uri: "/QuotaUnit/{Unit}")
@idempotent
@unstable
operation CreateQuotaUnit {
    input: CreateQuotaUnitRequest
    output: CreateQuotaUnitResponse
}

/// Input parameters to the CreateQuotaUnit endpoint.
@input
@unstable
structure CreateQuotaUnitRequest {
    /// The name of the unit.
    @required
    @httpLabel
    Unit: quotaUnitType
}

/// Response from the CreateQuotaUnit endpoint.
@output
@unstable
structure CreateQuotaUnitResponse {
    /// The resulting quota unit.
    @required
    QuotaUnit: QuotaUnit
}
