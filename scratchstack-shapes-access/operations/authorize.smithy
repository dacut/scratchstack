$version: "2"
namespace net.scratchstack.access

/// Checks whether an HTTP request made to a service is valid.
///
/// If the request is valid, this returns the principal making the request.
@http(method: "POST", uri: "/Authorize/{Service}/{Region}/{Action}")
@unstable
operation Authorize {
    input: AuthorizeRequest
    output: AuthorizeResponse
}

/// Input parameters to the Authorize endpoint.
@input
@unstable
structure AuthorizeRequest {
    /// The service the request is being authorized for.
    @required
    @httpLabel
    Service: serviceNameType

    /// The region where the request is being made.
    @required
    @httpLabel
    Region: regionType

    /// The action for which the request is being authorized.
    @required
    @httpLabel
    Action: actionNameType

    /// The HTTP request method from the client.
    @required
    RequestMethod: requestMethodType

    /// The HTTP request path send by the client.
    RequestPath: requestPathType

    /// The HTTP query parameters sent by the client.
    RequestQueryParameters: requestQueryParametersType

    /// The HTTP request headers sent by the client.
    @required
    RequestHeaders: requestHeaderListType

    /// The hexadecimal SHA-256 hash of the HTTP request body sent by the caller.
    ///
    /// If no body was sent, this field should be omitted.
    RequestBodySha256: requestBodyHashType

    /// The resources being accessed.
    Resources: resourceListType
}

/// Output result from the Authorize endpoint.
@output
@unstable
structure AuthorizeResponse {
    /// The decision for this request.
    @required
    Decision: Decision

    /// If the request was denied, this provides the reason for the authorization decision.
    Reason: reasonType

    /// The principal identified as the caller, if available.
    ///
    /// This may be present on denied authorizations. Presence of this field does not indicate
    /// an authorization was successful.
    Principal: Principal
}

