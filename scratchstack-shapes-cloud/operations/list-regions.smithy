$version: "2"
namespace net.scratchstack.cloud

/// Lists available regions.
@http(method: "GET", uri: "/Regions")
@paginated(inputToken: "NextToken", outputToken: "NextToken", pageSize: "MaxItems", items: "Regions")
@readonly
@unstable
operation ListRegions {
    input: ListRegionsRequest
    output: ListRegionsResponse
}

/// Input parameters to the ListRegions endpoint.
@input
@unstable
structure ListRegionsRequest {
    /// A pagination token to start listing from.
    @httpQuery("NextToken")
    NextToken: paginationTokenType

    /// The maximum number of results to return.
    @httpQuery("MaxItems")
    MaxItems: maxItemsType
}

/// Response from the ListRegions endpoint.
@output
@unstable
structure ListRegionsResponse {
    /// The next page of regions.
    @required
    Regions: regionListType

    /// A boolean indicating whether more results are available.
    @required
    Truncated: smithy.api#Boolean

    /// The pagination token if more results are available.
    NextToken: paginationTokenType
}
