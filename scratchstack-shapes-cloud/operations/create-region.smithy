$version: "2"
namespace net.scratchstack.cloud

/// Creates a region.
@http(method: "PUT", uri: "/Region/{RegionName}")
@idempotent
@unstable
operation CreateRegion {
    input: CreateRegionRequest
    output: CreateRegionResponse
}

/// Input parameters to the CreateRegion endpoint.
@input
@unstable
structure CreateRegionRequest {
    /// The name of the region
    @required
    @httpLabel
    RegionName: regionNameType
}

/// Response from the CreateRegion endpoint.
@output
@unstable
structure CreateRegionResponse {
    /// The resulting region
    @required
    Region: Region
}
