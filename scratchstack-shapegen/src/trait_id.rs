use {
    serde::{
        Deserialize, Serialize,
        de::{Deserializer, Visitor},
        ser::Serializer,
    },
    std::fmt::{Formatter, Result as FmtResult},
    strum_macros::{Display, EnumString},
};

/// Trait identifiers.
#[derive(Clone, Copy, Debug, Display, EnumString, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TraitId {
    /// Defines an ARN of a Smithy resource shape: `aws.api#arn`
    #[strum(serialize = "aws.api#arn")]
    AwsApiArn,

    /// Specifies that a string shape contains a fully formed AWS ARN: `aws.api#arnReference`
    #[strum(serialize = "aws.api#arnReference")]
    AwsApiArnReference,

    /// Indicates that the streaming blob supports aws-chunked content encoding:
    /// `aws.api#awsChunked`
    #[strum(serialize = "aws.api#awsChunked")]
    AwsApiAwsChunked,

    /// Indicates that the target operation should use the client's endpoint discovery logic:
    /// `aws.api#clientDiscoveredEndpoint`
    #[strum(serialize = "aws.api#clientDiscoveredEndpoint")]
    AwsApiClientDiscoveredEndpoint,

    /// Indicates the operation that the client should use to discover endpoints for the service and
    /// the error returned when the endpoint being accessed has expired:
    /// `aws.api#clientEndpointDiscovery`
    #[strum(serialize = "aws.api#clientEndpointDiscovery")]
    AwsApiClientEndpointDiscovery,

    /// Indicates which member(s) of the operation input should be used to discover an endpoint for
    /// the service: `aws.api#clientEndpointDiscoveryId`
    #[strum(serialize = "aws.api#clientEndpointDiscoveryId")]
    AwsApiClientEndpointDiscoveryId,

    /// Indicates that a service, resource, or operation is considered part of the control plane:
    /// `aws.api#controlPlane`
    #[strum(serialize = "aws.api#controlPlane")]
    AwsApiControlPlane,

    /// Indicates that the target contains data of the specified classification: `aws.api#data`
    #[strum(serialize = "aws.api#data")]
    AwsApiData,

    /// Indicates that a service, resource, or operation is considered part of the data plane:
    /// `aws.api#dataPlane`
    #[strum(serialize = "aws.api#dataPlane")]
    AwsApiDataPlane,

    /// Provides information about the service like the name used to generate AWS SDK client classes
    /// and the namespace used in ARNs: `aws.api#service`
    #[strum(serialize = "aws.api#service")]
    AwsApiService,

    /// Indicates the service supports resource level tagging consistent with AWS services:
    /// `aws.api#tagEnabled`
    #[strum(serialize = "aws.api#tagEnabled")]
    AwsApiTagEnabled,

    /// Indicates the resource supports AWS tag associations and identifies resource specific
    /// operations that perform CRUD on the associated tags: `aws.api#taggable`
    #[strum(serialize = "aws.api#taggable")]
    AwsApiTaggable,

    /// Adds support for Amazon Cognito User Pools to a service: `aws.api#cognitoUserPools`
    #[strum(serialize = "aws.api#cognitoUserPools")]
    AwsApiCognitoUserPools,

    /// Indicates that an operation requires an API key for API Gateway usage plan enforcement:
    /// `aws.apigateway#apiKeyRequired`
    #[strum(serialize = "aws.apigateway#apiKeyRequired")]
    AwsApigatewayApiKeyRequired,

    /// Specifies the source of the caller identifier that will be used to throttle API methods that
    /// require a key: `aws.apigateway#apiKeySource`
    #[strum(serialize = "aws.apigateway#apiKeySource")]
    AwsApigatewayApiKeySource,

    /// Defines the TLS security policy and endpoint access mode for an API Gateway REST API:
    /// `aws.apigateway#apiTlsPolicy`
    #[strum(serialize = "aws.apigateway#apiTlsPolicy")]
    AwsApigatewayApiTlsPolicy,

    /// Applies a Lambda authorizer to a service, resource, or operation: `aws.apigateway#authorizer`
    #[strum(serialize = "aws.apigateway#authorizer")]
    AwsApigatewayAuthorizer,

    /// Lambda authorizers to attach to the authentication schemes defined on this service:
    /// `aws.apigateway#authorizers`
    #[strum(serialize = "aws.apigateway#authorizers")]
    AwsApigatewayAuthorizers,

    /// Defines the endpoint configuration for an API Gateway REST API, including the endpoint type,
    /// Virtual Private Cloud (VPC) endpoint IDs, and whether the default execute-api endpoint is
    /// disabled: `aws.apigateway#endpointConfiguration`
    #[strum(serialize = "aws.apigateway#endpointConfiguration")]
    AwsApigatewayEndpointConfiguration,

    /// Defines custom gateway responses for an API Gateway REST API:
    /// `aws.apigateway#gatewayResponses`
    #[strum(serialize = "aws.apigateway#gatewayResponses")]
    AwsApigatewayGatewayResponses,

    /// Defines an API Gateway integration that integrates with an actual backend:
    /// `aws.apigateway#integration`
    #[strum(serialize = "aws.apigateway#integration")]
    AwsApigatewayIntegration,

    /// Defines the minimum payload size in bytes at which compression is applied on an API Gateway
    /// REST API: `aws.apigateway#minimumCompressionSize`
    #[strum(serialize = "aws.apigateway#minimumCompressionSize")]
    AwsApigatewayMinimumCompressionSize,

    /// Defines an API Gateway integration that returns a mock response:
    /// `aws.apigateway#mockIntegration`
    #[strum(serialize = "aws.apigateway#mockIntegration")]
    AwsApigatewayMockIntegration,

    /// Opts-in to Amazon API Gateway request validation for a service or operation:
    /// `aws.apigateway#requestValidator`
    #[strum(serialize = "aws.apigateway#requestValidator")]
    AwsApigatewayRequestValidator,

    /// Defines a resource policy for an API Gateway REST API: `aws.apigateway#resourcePolicy`
    #[strum(serialize = "aws.apigateway#resourcePolicy")]
    AwsApigatewayResourcePolicy,

    /// Defines the list of OAuth scopes required to invoke an operation that uses an
    /// `aws.auth#cognitoUserPools` trait authorizer: `aws.auth#cognitoUserPoolsScopes`
    #[strum(serialize = "aws.auth#cognitoUserPoolsScopes")]
    AwsAuthCognitoUserPoolsScopes,

    /// Adds support for AWS signature version 4 to a service.: `aws.auth#sigv4`
    #[strum(serialize = "aws.auth#sigv4")]
    AwsAuthSigV4,

    /// Adds support for AWS Signature Version 4 Asymmetric (SigV4A), an extension of AWS signature
    /// version 4 (SigV4), to a service: `aws.auth#sigv4a`
    #[strum(serialize = "aws.auth#sigv4a")]
    AwsAuthSigV4a,

    /// Indicates that the payload of an operation is not to be part of the signature computed for
    /// the request of an operation: `aws.auth#unsignedPayload`
    #[strum(serialize = "aws.auth#unsignedPayload")]
    AwsAuthUnsignedPayload,

    /// Indicates that the CloudFormation property generated from this member is an additional
    /// identifier for the resource: `aws.cloudformation#cfnAdditionalIdentifier`
    #[strum(serialize = "aws.cloudformation#cfnAdditionalIdentifier")]
    AwsCloudformationCfnAdditionalIdentifier,

    /// Indicates that the member annotated has a default value for that property of the
    /// CloudFormation resource: `aws.cloudformation#cfnDefaultValue`
    #[strum(serialize = "aws.cloudformation#cfnDefaultValue")]
    AwsCloudformationCfnDefaultValue,

    /// Indicates that structure member should not be included as a property in generated
    /// CloudFormation resource definitions: `aws.cloudformation#cfnExcludeProperty`
    #[strum(serialize = "aws.cloudformation#cfnExcludeProperty")]
    AwsCloudformationCfnExcludeProperty,

    /// Indicates an explicit CloudFormation mutability of the structure member when part of a
    /// CloudFormation resource: `aws.cloudformation#cfnMutability`
    #[strum(serialize = "aws.cloudformation#cfnMutability")]
    AwsCloudformationCfnMutability,

    /// Allows a CloudFormation resource property name to differ from a structure member name used
    /// in the model: `aws.cloudformation#cfnName`
    #[strum(serialize = "aws.cloudformation#cfnName")]
    AwsCloudformationCfnName,

    /// Indicates that a Smithy resource is a CloudFormation resource:
    /// `aws.cloudformation#cfnResource`
    #[strum(serialize = "aws.cloudformation#cfnResource")]
    AwsCloudformationCfnResource,

    /// Indicates that a service has only dual stack endpoints, does not support IPV4 only
    /// endpoints, and should not have the useDualStackEndpoint endpoint parameter:
    /// `aws.endpoints#dualStackOnlyEndpoints`
    #[strum(serialize = "aws.endpoints#dualStackOnlyEndpoints")]
    AwsEndpointsDualStackOnlyEndpoints,

    /// Marks a trait as an endpoint modifier: `aws.endpoints#endpointsModifier`
    #[strum(serialize = "aws.endpoints#endpointsModifier")]
    AwsEndpointsEndpointsModifier,

    /// Indicates that a service has hand written endpoint rules:
    /// `aws.endpoints#rulesBasedEndpoints`
    #[strum(serialize = "aws.endpoints#rulesBasedEndpoints")]
    AwsEndpointsRulesBasedEndpoints,

    /// Indicates that a service is partitional and a single endpoint should be resolved per
    /// partition: `aws.endpoints#standardPartitionalEndpoints`
    #[strum(serialize = "aws.endpoints#standardPartitionalEndpoints")]
    AwsEndpointsStandardPartitionalEndpoints,

    /// Indicates that a service's endpoints should be resolved using the standard AWS regional
    /// patterns: `aws.endpoints#standardRegionalEndpoints`
    #[strum(serialize = "aws.endpoints#standardRegionalEndpoints")]
    AwsEndpointsStandardRegionalEndpoints,

    /// Provides a custom IAM action name: `aws.iam#actionName`
    ///
    /// This trait is deprecated. The name property of the aws.iam#iamAction trait should be used
    /// instead.
    #[strum(serialize = "aws.iam#actionName")]
    AwsIamActionName,

    /// A brief description of what granting the user permission to invoke an operation would
    /// entail: `aws.iam#actionPermissionDescription`
    ///
    /// This trait is deprecated. The documentation property of the aws.iam#iamAction trait should
    /// be used instead.
    #[strum(serialize = "aws.iam#actionPermissionDescription")]
    AwsIamActionPermissionDescription,

    /// Applies condition keys, by name, to a resource or operation: `aws.iam#conditionKeys`
    #[strum(serialize = "aws.iam#conditionKeys")]
    AwsIamConditionKeys,

    /// Uses the associated member’s value for the specified condition key:
    /// `aws.iam#conditionKeyValue`
    #[strum(serialize = "aws.iam#conditionKeyValue")]
    AwsIamConditionKeyValue,

    /// Defines the set of condition keys that appear within a service in addition to inferred and
    /// global condition keys: `aws.iam#defineConditionKeys`
    #[strum(serialize = "aws.iam#defineConditionKeys")]
    AwsIamDefineConditionKeys,

    /// Declares that the condition keys of a resource should not be inferred:
    /// `aws.iam#disableConditionKeyInference`
    #[strum(serialize = "aws.iam#disableConditionKeyInference")]
    AwsIamDisableConditionKeyInference,

    /// Indicates properties of a Smithy operation in AWS IAM: `aws.iam#iamAction`
    #[strum(serialize = "aws.iam#iamAction")]
    AwsIamIamAction,

    /// Indicates properties of a Smithy resource in AWS IAM: `aws.iam#iamResource`
    #[strum(serialize = "aws.iam#iamResource")]
    AwsIamIamResource,

    /// Other actions that the invoker must be authorized to perform when executing the targeted
    /// operation: `aws.iam#requiredActions`
    #[strum(serialize = "aws.iam#requiredActions")]
    AwsIamRequiredActions,

    /// Specifies the list of IAM condition keys which must be resolved by the service, as opposed
    /// to the value being pulled from the request: `aws.iam#serviceResolvedConditionKeys`
    #[strum(serialize = "aws.iam#serviceResolvedConditionKeys")]
    AwsIamServiceResolvedConditionKeys,

    /// The IAM principal types that can use the service or operation: `aws.iam#principalTypes`
    #[strum(serialize = "aws.iam#principalTypes")]
    AwsIamPrincipalTypes,

    /// Adds support for an HTTP protocol that sends "POST" requests and responses with JSON
    /// documents: `aws.protocols#awsJson1_0`
    #[strum(serialize = "aws.protocols#awsJson1_0")]
    AwsProtocolsAwsJson1_0,

    /// Adds support for an HTTP protocol that sends "POST" requests and responses with JSON
    /// documents: `aws.protocols#awsJson1_1`
    #[strum(serialize = "aws.protocols#awsJson1_1")]
    AwsProtocolsAwsJson1_1,

    /// Adds support for the awsQuery protocol to a service: `aws.protocols#awsQuery`
    #[strum(serialize = "aws.protocols#awsQuery")]
    AwsProtocolsAwsQuery,

    /// Allows services to backward compatibly migrate from awsQuery to other wire protocols without
    /// removing values defined in the awsQueryError trait: `aws.protocols#awsQueryCompatible`
    #[strum(serialize = "aws.protocols#awsQueryCompatible")]
    AwsProtocolsAwsQueryCompatible,

    /// Provides a custom "Code" value for awsQuery errors and an HTTP response code:
    /// `aws.protocols#awsQueryError`
    #[strum(serialize = "aws.protocols#awsQueryError")]
    AwsProtocolsAwsQueryError,

    /// Adds support for an HTTP protocol that sends requests in an
    /// `application/x-www-form-url-encoded` body and responses in XML documents:
    /// `aws.protocols#ec2Query`
    #[strum(serialize = "aws.protocols#ec2Query")]
    AwsProtocolsEc2Query,

    /// Allows a serialized query key to differ from a structure member name when used in the model:
    /// `aws.protocols#ec2QueryName`
    #[strum(serialize = "aws.protocols#ec2QueryName")]
    AwsProtocolsEc2QueryName,

    /// Indicates that an operation's HTTP request or response supports checksum validation:
    /// `aws.protocols#httpChecksum`
    #[strum(serialize = "aws.protocols#httpChecksum")]
    AwsProtocolsHttpChecksum,

    /// Configures a service to support the RestJson1 protocol:
    /// `aws.protocols#restJson1`
    #[strum(serialize = "aws.protocols#restJson1")]
    AwsProtocolsRestJson1,

    /// Adds support for an HTTP-based protocol that sends XML requests and responses:
    /// `aws.protocols#restXml`
    #[strum(serialize = "aws.protocols#restXml")]
    AwsProtocolsRestXml,

    /// Defines prompt templates that provide contextual guidance to LLMs for understanding when and
    /// how to use operations or services: `smithy.ai#prompts`
    #[strum(serialize = "smithy.ai#prompts")]
    SmithyAiPrompts,

    /// Indicates that the default trait was added to a structure member after initially publishing
    /// the member: `smithy.api#addedDefault`
    #[strum(serialize = "smithy.api#addedDefault")]
    SmithyApiAddedDefault,

    /// Defines the priority ordered authentication schemes supported by a service or operation:
    /// `smithy.api#auth`
    #[strum(serialize = "smithy.api#auth")]
    SmithyApiAuth,

    /// Marks a trait as an authentication scheme: `smithy.api#authDefinition`
    #[strum(serialize = "smithy.api#authDefinition")]
    SmithyApiAuthDefinition,

    /// Requires that non-authoritative generators like clients treat a structure member as optional
    /// regardless of if the member is also marked with the required trait or default trait:
    /// `smithy.api#clientOptional`
    #[strum(serialize = "smithy.api#clientOptional")]
    SmithyApiClientOptional,

    /// Defines how a service supports cross-origin resource sharing: `smithy.api#cors`
    #[strum(serialize = "smithy.api#cors")]
    SmithyApiCors,

    /// Provides a structure member with a default value: `smithy.api#default`
    #[strum(serialize = "smithy.api#default")]
    SmithyApiDefault,

    /// Marks a shape or member as deprecated: `smithy.api#deprecated`
    #[strum(serialize = "smithy.api#deprecated")]
    SmithyApiDeprecated,

    /// Adds documentation to a shape or member using the CommonMark format:
    /// `smithy.api#documentation`
    #[strum(serialize = "smithy.api#documentation")]
    SmithyApiDocumentation,

    /// Configures a custom operation endpoint: `smithy.api#endpoint`
    #[strum(serialize = "smithy.api#endpoint")]
    SmithyApiEndpoint,

    /// Constrains the acceptable values of a string to a fixed set: `smithy.api#enum`
    ///
    /// This trait is deprecated. An enum shape should be used instead.
    #[strum(serialize = "smithy.api#enum")]
    SmithyApiEnum,

    /// Defines the value of an `enum` or `intEnum`: `smithy.api#enumValue`
    #[strum(serialize = "smithy.api#enumValue")]
    SmithyApiEnumValue,

    /// Indicates that a structure shape represents an error: `smithy.api#error`
    #[strum(serialize = "smithy.api#error")]
    SmithyApiError,

    /// Binds a member of a structure to be serialized as an event header when sent through an event
    /// stream: `smithy.api#eventHeader`
    #[strum(serialize = "smithy.api#eventHeader")]
    SmithyApiEventHeader,

    /// Binds a member of a structure to be serialized as the payload of an event sent through an
    /// event stream: `smithy.api#eventPayload`
    #[strum(serialize = "smithy.api#eventPayload")]
    SmithyApiEventPayload,

    /// Provides example inputs and outputs for operations: `smithy.api#examples`
    #[strum(serialize = "smithy.api#examples")]
    SmithyApiExamples,

    /// Provides named links to external documentation for a shape:
    /// `smithy.api#externalDocumentation`
    #[strum(serialize = "smithy.api#externalDocumentation")]
    SmithyApiExternalDocumentation,

    /// Binds a top-level operation input structure member to a label in the hostPrefix of an
    /// endpoint trait: `smithy.api#hostLabel`
    #[strum(serialize = "smithy.api#hostLabel")]
    SmithyApiHostLabel,

    /// Configures the HTTP bindings of an operation: `smithy.api#http`
    #[strum(serialize = "smithy.api#http")]
    SmithyApiHttp,

    /// Indicates that a service supports HTTP-specific authentication using an API key sent in a
    /// header or query string parameter: `smithy.api#httpApiKeyAuth`
    #[strum(serialize = "smithy.api#httpApiKeyAuth")]
    SmithyApiHttpApiKeyAuth,

    /// Indicates that a service supports HTTP Basic Authentication as defined in RFC 2617:
    /// `smithy.api#httpBasicAuth`
    #[strum(serialize = "smithy.api#httpBasicAuth")]
    SmithyApiHttpBasicAuth,

    /// Indicates that a service supports HTTP Bearer Authentication as defined in RFC 6750:
    /// `smithy.api#httpBearerAuth`
    #[strum(serialize = "smithy.api#httpBearerAuth")]
    SmithyApiHttpBearerAuth,

    /// Indicates that an operation requires a checksum in its HTTP request:
    /// `smithy.api#httpChecksumRequired`
    #[strum(serialize = "smithy.api#httpChecksumRequired")]
    SmithyApiHttpChecksumRequired,

    /// Indicates that a service supports HTTP Digest Authentication as defined in RFC 2617:
    /// `smithy.api#httpDigestAuth`
    #[strum(serialize = "smithy.api#httpDigestAuth")]
    SmithyApiHttpDigestAuth,

    /// Defines an HTTP response code for an operation error: `smithy.api#httpError`
    #[strum(serialize = "smithy.api#httpError")]
    SmithyApiHttpError,

    /// Binds a structure member to an HTTP header: `smithy.api#httpHeader`
    #[strum(serialize = "smithy.api#httpHeader")]
    SmithyApiHttpHeader,

    /// Binds an operation input structure member to an HTTP label so that it is used as part of an
    /// HTTP request URI: `smithy.api#httpLabel`
    #[strum(serialize = "smithy.api#httpLabel")]
    SmithyApiHttpLabel,

    /// Binds a single structure member to the body of an HTTP message: `smithy.api#httpPayload`
    #[strum(serialize = "smithy.api#httpPayload")]
    SmithyApiHttpPayload,

    /// Binds a map of key-value pairs to prefixed HTTP headers: `smithy.api#httpPrefixHeaders`
    #[strum(serialize = "smithy.api#httpPrefixHeaders")]
    SmithyApiHttpPrefixHeaders,

    /// Binds an operation input structure member to a query string parameter:
    /// `smithy.api#httpQuery`
    #[strum(serialize = "smithy.api#httpQuery")]
    SmithyApiHttpQuery,

    /// Binds a map of key-value pairs to query string parameters: `smithy.api#httpQueryParams`
    #[strum(serialize = "smithy.api#httpQueryParams")]
    SmithyApiHttpQueryParams,

    /// Binds a structure member to the HTTP response status code so that an HTTP response status
    /// code can be set dynamically at runtime to something other than code of the http trait:
    /// `smithy.api#httpResponseCode`
    #[strum(serialize = "smithy.api#httpResponseCode")]
    SmithyApiHttpResponseCode,

    /// Indicates that a string value MUST contain a valid absolute shape ID: `smithy.api#idRef`
    #[strum(serialize = "smithy.api#idRef")]
    SmithyApiIdRef,

    /// Defines the input member of an operation that is used by the server to identify and discard
    /// replayed requests: `smithy.api#idempotencyToken`
    #[strum(serialize = "smithy.api#idempotencyToken")]
    SmithyApiIdempotencyToken,

    /// Indicates that the intended effect on the server of multiple identical requests with an
    /// operation is the same as the effect for a single such request: `smithy.api#idempotent`
    #[strum(serialize = "smithy.api#idempotent")]
    SmithyApiIdempotent,

    /// Specializes a structure for use only as the input of a single operation, providing relaxed
    /// backward compatibility requirements for structure members: `smithy.api#input`
    #[strum(serialize = "smithy.api#input")]
    SmithyApiInput,

    /// Indicates that the shape is meant only for internal use: `smithy.api#internal`
    #[strum(serialize = "smithy.api#internal")]
    SmithyApiInternal,

    /// Allows a serialized object property name in a JSON document to differ from a structure or
    /// union member name used in the model: `smithy.api#jsonName`
    #[strum(serialize = "smithy.api#jsonName")]
    SmithyApiJsonName,

    /// Constrains a shape to minimum and maximum number of elements or size: `smithy.api#length`
    #[strum(serialize = "smithy.api#length")]
    SmithyApiLength,

    /// Indicates that the service may not respond immediately to requests for the targeted
    /// operation: `smithy.api#longPoll`
    #[strum(serialize = "smithy.api#longPoll")]
    SmithyApiLongPoll,

    /// Describes the contents of a blob or string shape using a design-time media type as defined
    /// by RFC 6838 (for example, `application/json`): `smithy.api#mediaType`
    #[strum(serialize = "smithy.api#mediaType")]
    SmithyApiMediaType,

    /// Allows model authors define a type for a metadata key: `smithy.api#metadata`
    #[strum(serialize = "smithy.api#metadata")]
    SmithyApiMetadata,

    /// Indicates that the targeted shape is a mixin: `smithy.api#mixin`
    #[strum(serialize = "smithy.api#mixin")]
    SmithyApiMixin,

    /// Allows the binding of resource properties to occur within a nested structure deeper than the
    /// lifecycle operation's input or output shape: `smithy.api#nestedProperties`
    #[strum(serialize = "smithy.api#nestedProperties")]
    SmithyApiNestedProperties,

    /// Indicates that the put lifecycle operation of a resource can only be used to create a
    /// resource and cannot replace an existing resource: `smithy.api#noReplace`
    #[strum(serialize = "smithy.api#noReplace")]
    SmithyApiNoReplace,

    /// Indicates that a top-level input or output shape member is not bound to a resource property:
    /// `smithy.api#notProperty`
    #[strum(serialize = "smithy.api#notProperty")]
    SmithyApiNotProperty,

    /// Indicates that an operation MAY be invoked without authentication, regardless of any
    /// authentication traits applied to the operation: `smithy.api#optionalAuth`
    #[strum(serialize = "smithy.api#optionalAuth")]
    SmithyApiOptionalAuth,

    /// Specializes a structure for use only as the output of a single operation:
    /// `smithy.api#output`
    #[strum(serialize = "smithy.api#output")]
    SmithyApiOutput,

    /// Indicates that an operation intentionally limits the number of results returned in a single
    /// response and that multiple invocations might be necessary to retrieve all results:
    /// `smithy.api#paginated`
    #[strum(serialize = "smithy.api#paginated")]
    SmithyApiPaginated,

    /// Restricts string shape values to a specified regular expression: `smithy.api#pattern`
    #[strum(serialize = "smithy.api#pattern")]
    SmithyApiPattern,

    /// Prevents models defined in a different namespace from referencing the targeted shape:
    /// `smithy.api#private`
    #[strum(serialize = "smithy.api#private")]
    SmithyApiPrivate,

    /// Binds a top-level input or output structure member to a resource property with a different
    /// name: `smithy.api#property`
    #[strum(serialize = "smithy.api#property")]
    SmithyApiProperty,

    /// Marks a trait as a protocol definition trait: `smithy.api#protocolDefinition`
    #[strum(serialize = "smithy.api#protocolDefinition")]
    SmithyApiProtocolDefinition,

    /// Restricts allowed values of number shapes within an acceptable lower and upper bound:
    /// `smithy.api#range`
    #[strum(serialize = "smithy.api#range")]
    SmithyApiRange,

    /// Indicates that an operation is effectively read-only: `smithy.api#readonly`
    #[strum(serialize = "smithy.api#readonly")]
    SmithyApiReadonly,

    /// Indicates that a structure member SHOULD be set: `smithy.api#recommended`
    #[strum(serialize = "smithy.api#recommended")]
    SmithyApiRecommended,

    /// Defines a design-time reference to Resource shapes: `smithy.api#references`
    #[strum(serialize = "smithy.api#references")]
    SmithyApiReferences,

    /// Indicates that an operation supports compressing requests from clients to services:
    /// `smithy.api#requestCompression`
    #[strum(serialize = "smithy.api#requestCompression")]
    SmithyApiRequestCompression,

    /// Marks a structure member as required, meaning a value for the member MUST be present:
    /// `smithy.api#required`
    #[strum(serialize = "smithy.api#required")]
    SmithyApiRequired,

    /// Indicates that the streaming blob MUST be finite and have a known size when sending data
    /// from a client to a server: `smithy.api#requiresLength`
    #[strum(serialize = "smithy.api#requiresLength")]
    SmithyApiRequiresLength,

    /// Indicates that the targeted structure member provides an identifier for a resource:
    /// `smithy.api#resourceIdentifier`
    #[strum(serialize = "smithy.api#resourceIdentifier")]
    SmithyApiResourceIdentifier,

    /// Indicates that an error MAY be retried by the client: `smithy.api#retryable`
    #[strum(serialize = "smithy.api#retryable")]
    SmithyApiRetryable,

    /// Indicates that the data stored in the shape is sensitive and MUST be handled with care:
    /// `smithy.api#sensitive`
    #[strum(serialize = "smithy.api#sensitive")]
    SmithyApiSensitive,

    /// Defines the version or date in which a shape or member was added to the model:
    /// `smithy.api#since`
    #[strum(serialize = "smithy.api#since")]
    SmithyApiSince,

    /// Indicates that lists and maps MAY contain null values: `smithy.api#sparse`
    #[strum(serialize = "smithy.api#sparse")]
    SmithyApiSparse,

    /// Indicates that the data represented by the shape needs to be streamed:
    /// `smithy.api#streaming`
    #[strum(serialize = "smithy.api#streaming")]
    SmithyApiStreaming,

    /// Suppress validation events(s) for a specific shape: `smithy.api#suppress`
    #[strum(serialize = "smithy.api#suppress")]
    SmithyApiSuppress,

    /// Tags a shape with arbitrary tag names that can be used to filter and group shapes in the
    /// model: `smithy.api#tags`
    #[strum(serialize = "smithy.api#tags")]
    SmithyApiTags,

    /// Defines a custom timestamp serialization format: `smithy.api#timestampFormat`
    #[strum(serialize = "smithy.api#timestampFormat")]
    SmithyApiTimestampFormat,

    /// Defines a proper name for a shape: `smithy.api#title`
    #[strum(serialize = "smithy.api#title")]
    SmithyApiTitle,

    /// Marks a shape as a trait: `smithy.api#trait`
    #[strum(serialize = "smithy.api#trait")]
    SmithyApiTrait,

    /// A meta-trait used to limit the kinds of shapes that can be referenced by a shape when a
    /// trait is applied to the shape: `smithy.api#traitValidators`
    #[strum(serialize = "smithy.api#traitValidators")]
    SmithyApiTraitValidators,

    /// Requires the items in a list to be unique based on Value equality: `smithy.api#uniqueItems`
    #[strum(serialize = "smithy.api#uniqueItems")]
    SmithyApiUniqueItems,

    /// Indicates a shape is unstable and MAY change in the future: `smithy.api#unstable`
    #[strum(serialize = "smithy.api#unstable")]
    SmithyApiUnstable,

    /// Serializes an object property as an XML attribute rather than a nested XML element:
    /// `smithy.api#xmlAttribute`
    #[strum(serialize = "smithy.api#xmlAttribute")]
    SmithyApiXmlAttribute,

    /// Unwraps the values of a list or map into the containing structure: `smithy.api#xmlFlattened`
    #[strum(serialize = "smithy.api#xmlFlattened")]
    SmithyApiXmlFlattened,

    /// Changes the serialized element or attribute name of a structure, union, or member:
    /// `smithy.api#xmlName`
    #[strum(serialize = "smithy.api#xmlName")]
    SmithyApiXmlName,

    /// Adds an XML namespace to an XML element: `smithy.api#xmlNamespace`
    #[strum(serialize = "smithy.api#xmlNamespace")]
    SmithyApiXmlNamespace,

    /// Restricts shape values to those which satisfy the given JMESPath expressions:
    /// `smithy.contracts#conditions`
    #[strum(serialize = "smithy.contracts#conditions")]
    SmithyContractsConditions,

    /// Binds an operation to send a PUBLISH control packet via the MQTT protocol:
    /// `smithy.mqtt#publish`
    #[strum(serialize = "smithy.mqtt#publish")]
    SmithyMqttPublish,

    /// Binds an operation to send one or more SUBSCRIBE control packets via the MQTT protocol:
    /// `smithy.mqtt#subscribe`
    #[strum(serialize = "smithy.mqtt#subscribe")]
    SmithyMqttSubscribe,

    /// Binds a structure member to an MQTT topic label: `smithy.mqtt#topicLabel`
    #[strum(serialize = "smithy.mqtt#topicLabel")]
    SmithyMqttTopicLabel,

    /// Indicates a trait shape should be converted into an OpenAPI specification extension:
    /// `smithy.openapi#specificationExtension`
    #[strum(serialize = "smithy.openapi#specificationExtension")]
    SmithyOpenapiSpecificationExtension,

    /// Adds support for an RPC-based protocol over HTTP that sends requests and responses with
    /// CBOR payloads: `smithy.protocols#rpcv2Cbor`
    #[strum(serialize = "smithy.protocols#rpcv2Cbor")]
    SmithyProtocolsRpcv2Cbor,

    /// Adds support for an RPC-based protocol over HTTP that sends requests and responses with JSON
    /// payloads: `smithy.protocols#rpcv2Json`
    #[strum(serialize = "smithy.protocols#rpcv2Json")]
    SmithyProtocolsRpcv2Json,

    /// Defines one or more rule set parameters that MUST be generated as configurable client
    /// configuration parameters: `smithy.rules#clientContextParams`
    #[strum(serialize = "smithy.rules#clientContextParams")]
    SmithyRulesClientContextParams,

    /// Binds a top-level operation input structure member to a rule set parameter:
    /// `smithy.rules#contextParam`
    #[strum(serialize = "smithy.rules#contextParam")]
    SmithyRulesContextParam,

    /// A Binary Decision Diagram (BDD) representation of endpoint rules that is more compact and
    /// efficient at runtime than the decision-tree-based EndpointRuleSet trait:
    /// `smithy.rules#endpointBdd`
    #[strum(serialize = "smithy.rules#endpointBdd")]
    SmithyRulesEndpointBdd,

    /// Defines a rule set for deriving service endpoints at runtime: `smithy.rules#endpointRuleSet`
    #[strum(serialize = "smithy.rules#endpointRuleSet")]
    SmithyRulesEndpointRuleSet,

    /// Defines endpoint test cases for validating a client's endpoint rule-set:
    /// `smithy.rules#endpointTests`
    #[strum(serialize = "smithy.rules#endpointTests")]
    SmithyRulesEndpointTests,

    /// Defines one or more rule set parameters that MUST be bound to values specified in the
    /// operation input: `smithy.rules#operationContextParams`
    #[strum(serialize = "smithy.rules#operationContextParams")]
    SmithyRulesOperationContextParams,

    /// Defines one or more rule set parameters that MUST be bound to the specified values:
    /// `smithy.rules#staticContextParams`
    #[strum(serialize = "smithy.rules#staticContextParams")]
    SmithyRulesStaticContextParams,

    /// Defines how an event stream is serialized and deserialized given a specific protocol and set
    /// of events: `smithy.test#eventStreamTests`
    #[strum(serialize = "smithy.test#eventStreamTests")]
    SmithyTestEventStreamTests,

    /// Defines how a malformed HTTP request is rejected given a specific protocol and HTTP message:
    /// `smithy.test#httpMalformedRequestTests`
    #[strum(serialize = "smithy.test#httpMalformedRequestTests")]
    SmithyTestHttpMalformedRequestTests,

    /// Defines how an HTTP request is serialized given a specific protocol, authentication scheme,
    /// and set of input parameters: `smithy.test#httpRequestTests`
    #[strum(serialize = "smithy.test#httpRequestTests")]
    SmithyTestHttpRequestTests,

    /// Defines how an HTTP response is serialized given a specific protocol, authentication scheme,
    /// and set of output or error parameters: `smithy.test#httpResponseTests`
    #[strum(serialize = "smithy.test#httpResponseTests")]
    SmithyTestHttpResponseTests,

    /// Defines a set of test cases to send to a live service to ensure that a client can
    /// successfully connect to a service and receives the right kind of response:
    /// `smithy.test#smokeTests`
    #[strum(serialize = "smithy.test#smokeTests")]
    SmithyTestSmokeTests,

    /// Indicates that an operation has various named "waiters" that can be used to poll a resource
    /// until it enters a desired state: `smithy.waiters#waitable`
    #[strum(serialize = "smithy.waiters#waitable")]
    SmithyWaitersWaitable,
}

struct TraitIdVisitor;
impl<'de> Visitor<'de> for TraitIdVisitor {
    type Value = TraitId;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("an integer between -2^31 and 2^31")
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        match s.parse() {
            Ok(trait_id) => Ok(trait_id),
            Err(e) => {
                log::error!("Failed to parse trait ID from string '{s}': {e}");
                Err(serde::de::Error::custom(e))
            }
        }
    }
}

impl<'de> Deserialize<'de> for TraitId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(TraitIdVisitor)
    }
}

impl Serialize for TraitId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
