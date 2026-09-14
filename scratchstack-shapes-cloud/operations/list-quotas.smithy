$version: "2"
namespace net.scratchstack.cloud

/// Lists quotas.
@http(method: "GET", uri: "/Quotas")
@paginated(inputToken: "NextToken", outputToken: "NextToken", pageSize: "MaxItems", items: "Quotas")
@readonly
@unstable
operation ListQuotas {
    input: ListQuotasRequest
    output: ListQuotasResponse
}

/// Input parameters to the ListQuotas endpoint.
@input
@unstable
structure ListQuotasRequest {
    /// If specified, results will only contain quotas for the given service.
    @httpQuery("ServiceId")
    ServiceId: serviceIdType

    /// If specified, results will only contain quotas for the given name.
    @httpQuery("QuotaName")
    QuotaName: quotaNameType

    /// If specified, results will only contain quotas for the given region.
    @httpQuery("RegionName")
    RegionName: regionNameType

    /// If specified, results will only contain quotas for the given account id.
    @httpQuery("AccountId")
    AccountId: accountIdType

    /// A pagination token to start listing from.
    @httpQuery("NextToken")
    NextToken: paginationTokenType

    /// The maximum number of results to return.
    @httpQuery("MaxItems")
    MaxItems: maxItemsType
}

/// Response from the ListQuotas endpoint.
@output
@unstable
structure ListQuotasResponse {
    /// The next page of quotas.
    @required
    Quotas: quotaListType,

    /// A boolean indicating whether more results are available.
    @required
    Truncated: smithy.api#Boolean

    /// The pagination token if more results are available.
    NextToken: paginationTokenType
}
