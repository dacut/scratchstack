$version: "2"
namespace net.scratchstack.cloud

/// Deletes a quota for an account.
@http(method: "DELETE", uri: "/Quota/{ServiceId}/{QuotaName}/{RegionName}/{AccountId}")
@idempotent
@unstable
operation DeleteQuota {
    input: DeleteQuotaRequest
    output: smithy.api#Unit
}

/// Input parameters to the DeleteQuota endpoint.
@input
@unstable
structure DeleteQuotaRequest {
    /// The service this quota is scoped to.
    @required
    @httpLabel
    ServiceId: serviceIdType

    /// The quota being created.
    @required
    @httpLabel
    QuotaName: quotaNameType

    /// The region the quota is scoped to, or `"global"` if this is a global quota.
    @required
    @httpLabel
    RegionName: regionNameType

    /// The 12-digit account id this quota applies to.
    @required
    @httpLabel
    AccountId: accountIdType
}
