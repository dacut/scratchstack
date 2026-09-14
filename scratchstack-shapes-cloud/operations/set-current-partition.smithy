$version: "2"
namespace net.scratchstack.cloud

/// Sets the current partition of this cloud.
@http(method: "PUT", uri: "/Partition")
@idempotent
@unstable
operation SetCurrentPartition {
    input: SetCurrentPartitionRequest
    output: SetCurrentPartitionResponse
}

/// Input parameters to the SetCurrentPartition endpoint.
@input
@unstable
structure SetCurrentPartitionRequest {
    /// The partition of this cloud.
    @required
    Partition: partitionType
}

/// Response from the SetCurrentPartition endpoint.
@output
@unstable
structure SetCurrentPartitionResponse {
    /// The partition of this cloud.
    @required
    Partition: partitionType
}
