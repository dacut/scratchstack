$version: "2"
namespace net.scratchstack.cloud

/// Creates or updates a quota for an account.
@http(method: "PUT", uri: "/Quota/{ServiceId}/{QuotaName}/{RegionName}/{AccountId}")
@idempotent
@unstable
operation SetQuota {
    input: SetQuotaRequest
    output: SetQuotaResponse
}

/// Input parameters to the SetQuota endpoint.
@input
@unstable
structure SetQuotaRequest {
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

    /// The value of the quota.
    @required
    Value: quotaValueType

    /// The unit of the quota value. This must be consistent with the unit the quota was defined with.
    @required
    Unit: quotaUnitType
}

/// Response from the SetQuota endpoint.
@output
@unstable
structure SetQuotaResponse {
    /// The resulting quota.
    @required
    Quota: Quota
}
