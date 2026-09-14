$version: "2"
namespace net.scratchstack.cloud

/// Gets the current partition of this cloud.
@http(method: "GET", uri: "/Partition")
@readonly
@unstable
operation GetCurrentPartition {
    input: smithy.api#Unit
    output: GetCurrentPartitionResponse
}

/// Response from the GetCurrentPartition endpoint.
@output
@unstable
structure GetCurrentPartitionResponse {
    /// The partition of this cloud.
    @required
    Partition: partitionType
}
