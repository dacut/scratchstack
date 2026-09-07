$version: "2"
namespace net.scratchstack.access
// use aws.api#service
// use aws.auth#sigv4
use aws.protocols#awsJson1_1

/// The Scratchstack Access Service provides authentication and authorization capabilities to
/// services implementing AWS SigV4 signature authentication.
// @auth([sigv4])
// @sigv4(name: "access")
@awsJson1_1
@unstable
service Access {
    version: "2026-09-03"
    operations: [Authorize, GetSigningKey]
}

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

/// The decision made on an authorization request.
enum Decision {
    /// The request was allowed: an explicit `Allow` statement applied to the request with no
    /// applicable `Deny` statements.
    ALLOW = "Allow"

    /// The request was denied: an explicit `Deny` statement applied to the request.
    DENY = "Deny"

    /// The request was denied by default: no statements applied to the request
    DEFAULT_DENY = "DefaultDeny"
}

/// The identifiers for a federated user.
@unstable
structure FederatedUser {
    /// The ARN specifying the federated user.
    @required
    Arn: arnType

    /// The 12-digit account id associated with the federated user.
    @required
    AccountId: accountIdType

    /// The string that identifies the federated user associated with the credentials, similar to
    /// the unique ID of an IAM user.
    @required
    FederatedUserId: federatedIdType,
}

/// An acting principal for a given request.
@unstable
structure Principal {
    /// The source of the principal, one of `Aws`, `Federated`, or `Service`.
    @required
    PrincipalSource: PrincipalSource

    /// The type of the principal, one of `AssumedRole`, `FederatedUser`, `Service`, or `User`.
    @required
    PrincipalType: PrincipalType
}

/// A policy attached to a principal
@unstable
structure PrincipalPolicy {
    /// The type of the policy, either `Attached`, `Inline`, or `Session`.
    @required
    PolicyType: PrincipalPolicyType

    /// The name of the policy, if this is an attached policy.
    PolicyName: policyNameType

    /// The text of the policy document.
    @required
    PolicyDocument: policyDocumentType
}

/// The type of a principal policy
@unstable
enum PrincipalPolicyType {
    /// A managed policy attached to the principal.
    ATTACHED = "Attached"

    /// An inline policy on the principal.
    INLINE = "Inline"

    /// A session policy passed through an `AssumeRole`-style call.
    SESSION = "Session"
}

/// The source of a principal.
@unstable
enum PrincipalSource {
    /// The source is an AWS IAM entity, either an `AssumedRole`, `RootUser`, or `User`.
    AWS = "Aws"

    /// The source is from a federated identity source.
    FEDERATED = "Federated"

    /// The source is an AWS-like service.
    SERVICE = "Service"
}

/// The type of a principal.
@unstable
enum PrincipalType {
    /// The principal is an AWS IAM assumed role.
    ASSUMED_ROLE = "AssumedRole"

    /// The principal is a federated identity.
    FEDERATED_USER = "FederatedUser"

    /// The principal is an AWS root user.
    ///
    /// Note that Scratchstack does not (and never will) issue root user credentials; however,
    /// this is included for compatibility with AWS.
    ROOT_USER = "RootUser"

    /// The principal is an AWS-like service.
    SERVICE = "Service"

    /// The principal is an AWS IAM user.
    USER = "User"
}

/// A single HTTP request header.
@unstable
structure RequestHeader {
    /// The header name
    @required
    HeaderName: requestHeaderNameType

    /// The header value
    @required
    HeaderValue: requestHeaderValueType
}

/// A single resource being accessed.
@unstable
structure Resource {
    /// The ARN of the resource being accessed.
    @required
    Arn: arnType

    /// Tags of the resource being accessed.
    Tags: tagListType
}

/// The identity details of an AWS-like service.
@unstable
structure Service {
    /// The global DNS name of the service, without a region identifier.
    ServiceGlobalName: serviceDnsNameType

    /// The regional DNS name of the service.
    ServiceRegionalname: serviceDnsNameType
}

/// A single tag, either specified in a request or applied to a resource.
structure Tag {
    /// The key for a tag.
    @required
    Key: tagKeyType

    /// The value for a tag.
    @required
    Value: tagValueType
}

/// The identity details of an AWS IAM user.
@unstable
structure User {
    /// The ARN of the user
    @required
    Arn: arnType

    /// The AWS account ID of the user.
    @required
    AccountId: accountIdType

    /// The path of the user
    @required
    Path: userPathType

    /// The name of the user
    @required
    UserName: userNameType

    /// Tags applied to the user
    Tags: tagListType
}

@length(min: 16, max: 128)
@pattern("^[\\w]*$")
string accessKeyIdType

@pattern("^[0-9]{12}$")
string accountIdType

string actionNameType

@length(min: 20, max: 2048)
string arnType

string credentialType

timestamp dateType

@length(min: 2, max: 193)
@pattern("^[\\w+=,.@\\:-]*$")
string federatedIdType

@length(min: 1)
@pattern("^[\\u0009\\u000A\\u000D\\u0020-\\u00FF]+$")
string policyDocumentType

string policyNameType

list principalPolicyListType {
    member: PrincipalPolicy
}

string reasonType

@pattern("^(local|([a-z]+-)+[0-9]+(-[a-z]+-[0-9]+)?)$")
string regionType

@length(min: 8, max: 1024)
@pattern("^[a-f0-9]+$")
string requestBodyHashType

list requestHeaderListType {
    member: RequestHeader
}

string requestHeaderNameType

string requestHeaderValueType

@pattern("^[A-Z]+$")
string requestMethodType

string requestPathType

string requestQueryParametersType

list resourceListType {
    member: Resource
}

string serviceDnsNameType

@pattern("^[a-z0-9](-[a-z0-9]|[a-z0-9])*$")
string serviceNameType

string sessionNameType

@sensitive
string sessionTokenType

@sensitive
string signingKeyType

@length(min: 1)
string tagKeyType

list tagListType {
    member: Tag
}

@length(min: 1, max: 256)
@pattern("^[\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*$")
string tagValueType

string userIdType

@length(min: 1, max: 512)
@pattern("^/(.+/)?$")
string userPathType

@length(min: 1, max: 32)
@pattern("^[\\w+,.@-]*$")
string userNameType