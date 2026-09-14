$version: "2"
namespace net.scratchstack.cloud

/// Deletes a region.
@http(method: "DELETE", uri: "/Region/{RegionName}")
@idempotent
@unstable
operation DeleteRegion {
    input: DeleteRegionRequest
    output: smithy.api#Unit
}

/// Input parameters to the DeleteRegion endpoint.
@input
@unstable
structure DeleteRegionRequest {
    /// The name of the region
    @required
    @httpLabel
    RegionName: regionNameType
}
