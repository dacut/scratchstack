$version: "2"
namespace net.scratchstack.cloud

/// Retrieves a quota for an account.
@http(method: "GET", uri: "/Quota/{ServiceId}/{QuotaName}/{RegionName}/{AccountId}")
@readonly
@unstable
operation GetQuota {
    input: GetQuotaRequest
    output: GetQuotaResponse
}

/// Input parameters to the GetQuota endpoint.
@input
@unstable
structure GetQuotaRequest {
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

/// Response from the GetQuota endpoint.
@output
@unstable
structure GetQuotaResponse {
    /// The quota for the service.
    @required
    Quota: Quota
}
