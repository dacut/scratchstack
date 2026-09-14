$version: "2"
namespace net.scratchstack.cloud

/// Lists units that can be used in quota definitions.
@http(method: "GET", uri: "/QuotaUnits")
@paginated(inputToken: "NextToken", outputToken: "NextToken", pageSize: "MaxItems", items: "Units")
@readonly
@unstable
operation ListQuotaUnits {
    input: ListQuotaUnitsRequest
    output: ListQuotaUnitsResponse
}

/// Input parameters to the ListQuotaUnits endpoint.
@input
@unstable
structure ListQuotaUnitsRequest {
    /// A pagination token to start listing from.
    @httpQuery("NextToken")
    NextToken: paginationTokenType

    /// The maximum number of results to return.
    @httpQuery("MaxItems")
    MaxItems: maxItemsType
}

/// Response from the ListQuotaUnits endpoint.
@output
@unstable
structure ListQuotaUnitsResponse {
    /// The next page of quota units.
    @required
    Units: quotaUnitListType

    /// A boolean indicating whether more results are available.
    @required
    Truncated: smithy.api#Boolean

    /// The pagination token if more results are available.
    NextToken: paginationTokenType
}
