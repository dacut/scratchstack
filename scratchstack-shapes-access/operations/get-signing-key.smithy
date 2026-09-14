$version: "2"
namespace net.scratchstack.access

/// Retrieves the signing key for a credential, allowing a service to perform authentication and
/// authorization checks locally.
@http(method: "POST", uri: "/SigningKey/{Service}/{Region}")
@unstable
operation GetSigningKey {
    input: GetSigningKeyRequest
    output: GetSigningKeyResponse
}

/// Input parameters to the GetSigningKey endpoint.
@input
@unstable
structure GetSigningKeyRequest {
    /// The service the request is being authorized for.
    @required
    @httpLabel
    Service: serviceNameType

    /// The region where the request is being made.
    @required
    @httpLabel
    Region: regionType

    /// The credential for which the signing key is being requested. This must be in
    /// <code><i>access-key</i>/<i>yyyymmdd</i>/<i>region</i>/<i>service</i>/aws4_request</code>
    /// format.
    @required
    Credential: credentialType

    /// The session token sent by the client. If the client did not send a session token, this
    /// field must be omitted.
    SessionToken: sessionTokenType
}

/// Output result from the GetSigningKey endpoint.
@output
@unstable
structure GetSigningKeyResponse {
    /// The signing key corresponding to the requested credential.
    SigningKey: signingKeyType

    /// The expiration time when the signing key should no longer be used. This is typically
    /// five minutes after the request was made.
    NotValidAfter: dateType

    /// The principal associated with the signing key.
    Principal: Principal
}

