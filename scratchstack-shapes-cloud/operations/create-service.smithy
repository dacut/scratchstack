$version: "2"
namespace net.scratchstack.cloud

/// Creates a service.
@http(method: "PUT", uri: "/Service/{ServiceId}")
@idempotent
@unstable
operation CreateService {
    input: CreateServiceRequest
    output: CreateServiceResponse
}

/// Input parameters to the CreateService endpoint.
@input
@unstable
structure CreateServiceRequest {
    /// The identifier for the service. This is the short name used in Aspen documents, e.g. `iam`
    /// for the Identity and Access Management service.
    @required
    @httpLabel
    ServiceId: serviceIdType

    /// The global DNS name for the service (which is not required to be an actual HTTP endpoint),
    /// e.g. `iam.amazonaws.com` for the AWS Identity and Access Management service.
    @required
    ServiceDnsName: dnsNameType

    /// A description of the service.
    Description: descriptionType
}

/// Response from the CreateService endpoint.
@output
@unstable
structure CreateServiceResponse {
    /// The resulting service.
    @required
    Service: Service
}
