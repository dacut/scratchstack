$version: "2"
namespace net.scratchstack.cloud

/// Lists quota definitions.
@http(method: "GET", uri: "/QuotaDefinitions")
@paginated(inputToken: "NextToken", outputToken: "NextToken", pageSize: "MaxItems", items: "QuotaDefinitions")
@readonly
@unstable
operation ListQuotaDefinitions {
    input: ListQuotaDefinitionsRequest
    output: ListQuotaDefinitionsResponse
}

/// Input parameters to the ListQuotaDefinitions endpoint.
@input
@unstable
structure ListQuotaDefinitionsRequest {
    /// If specified, results will only contain quota definitions for the given service.
    @httpQuery("ServiceId")
    ServiceId: serviceIdType

    /// If specified, results will only contain quota definitions for the given scope.
    @httpQuery("Scope")
    Scope: QuotaScope

    /// A pagination token to start listing from.
    @httpQuery("NextToken")
    NextToken: paginationTokenType

    /// The maximum number of results to return.
    @httpQuery("MaxItems")
    MaxItems: maxItemsType
}

/// Response from the ListQuotaDefinitions endpoint.
@output
@unstable
structure ListQuotaDefinitionsResponse {
    /// The next page of quota definitions.
    @required
    QuotaDefinitions: quotaDefinitionListType

    /// A boolean indicating whether more results are available.
    @required
    Truncated: smithy.api#Boolean

    /// The pagination token if more results are available.
    NextToken: paginationTokenType
}
