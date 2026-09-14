$version: "2"
namespace net.scratchstack.cloud

/// Deletes a service.
@http(method: "DELETE", uri: "/Service/{ServiceId}")
@idempotent
@unstable
operation DeleteService {
    input: DeleteServiceRequest
    output: smithy.api#Unit
}

/// Input parameters to the DeleteService endpoint.
@input
@unstable
structure DeleteServiceRequest {
    /// The identifier for the service. This is the short name used in Aspen documents, e.g. `iam`
    /// for the Identity and Access Management service.
    @required
    @httpLabel
    ServiceId: serviceIdType
}
