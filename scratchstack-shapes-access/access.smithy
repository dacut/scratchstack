$version: "2"
namespace net.scratchstack.access
use aws.protocols#awsJson1_1

/// The Scratchstack Access Service provides authentication and authorization capabilities to
/// services implementing AWS SigV4 signature authentication.
@awsJson1_1
@unstable
service Access {
    version: "2026-09-03"
    operations: [Authorize, GetSigningKey]
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

/// The identity details of an assumed IAM role.
@unstable
structure AssumedRole {
    /// The ARN of the assumed-role session.
    @required
    Arn: arnType

    /// The AWS account ID the role belongs to.
    @required
    AccountId: accountIdType

    /// The name of the role that was assumed.
    @required
    RoleName: roleNameType

    /// The session name supplied when the role was assumed.
    @required
    SessionName: sessionNameType

    /// Tags applied to the session.
    Tags: tagListType
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
///
/// `PrincipalSource` and `PrincipalType` say which kind of identity this is; exactly one of the
/// detail members below is populated, the one `PrincipalType` names. A caller that only needs to
/// branch on the kind can read the discriminators alone, and one that needs to know *who* the
/// caller is reads the matching detail.
@unstable
structure Principal {
    /// The source of the principal, one of `Aws`, `Federated`, or `Service`.
    @required
    PrincipalSource: PrincipalSource

    /// The type of the principal, one of `AssumedRole`, `FederatedUser`, `RootUser`, `Service`,
    /// or `User`.
    @required
    PrincipalType: PrincipalType

    /// The assumed-role session, set when `PrincipalType` is `AssumedRole`.
    AssumedRole: AssumedRole

    /// The federated user, set when `PrincipalType` is `FederatedUser`.
    FederatedUser: FederatedUser

    /// The account root user, set when `PrincipalType` is `RootUser`.
    RootUser: RootUser

    /// The service, set when `PrincipalType` is `Service`.
    Service: Service

    /// The IAM user, set when `PrincipalType` is `User`.
    User: User
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

/// The identity details of an AWS account root user.
///
/// Scratchstack does not issue root user credentials; this exists so that a principal arriving
/// from a system that does can still be described.
@unstable
structure RootUser {
    /// The ARN of the root user.
    @required
    Arn: arnType

    /// The AWS account ID of the root user.
    @required
    AccountId: accountIdType
}

/// The identity details of an AWS-like service.
@unstable
structure Service {
    /// The global DNS name of the service, without a region identifier.
    ServiceGlobalName: serviceDnsNameType

    /// The regional DNS name of the service.
    ServiceRegionalName: serviceDnsNameType
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

@length(min: 12, max: 12)
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

@length(min: 1, max: 64)
@pattern("^[\\w+=,.@-]*$")
string roleNameType

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