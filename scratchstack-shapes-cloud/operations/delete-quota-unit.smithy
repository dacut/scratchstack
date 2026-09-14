$version: "2"
namespace net.scratchstack.cloud

/// Deletes a quota unit.
@http(method: "DELETE", uri: "/QuotaUnit/{Unit}")
@idempotent
@unstable
operation DeleteQuotaUnit {
    input: DeleteQuotaUnitRequest
    output: smithy.api#Unit
}

/// Input parameters to the DeleteQuotaUnit endpoint.
@input
@unstable
structure DeleteQuotaUnitRequest {
    /// The name of the unit.
    @required
    @httpLabel
    Unit: quotaUnitType
}
