//! Partition test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_core::{ProvideRequestId as _, RequestId},
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::operation::{GetCurrentPartitionRequest, SetCurrentPartitionRequest},
};

pub async fn test_set_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest::builder()
        .partition("test-partition")
        .build()
        .expect("Failed to build SetCurrentPartitionRequest");
    assert_eq!(req.partition, "test-partition");

    let resp = req.execute(&mut tx, RequestId::new()).await.expect("Failed to set current partition");
    assert_eq!(resp.partition, "test-partition");
    tx.commit().await.expect("Failed to commit transaction");
}

pub async fn test_invalid_set_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest {
        partition: "".to_string(),
    };
    // The request id handed to execute must come back on the error so callers can correlate the
    // failure with the service logs.
    let request_id = RequestId::new();
    let err = req.execute(&mut tx, request_id).await.expect_err("Setting an invalid partition ID should fail");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    tx.rollback().await.expect("Failed to rollback transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest {
        partition: "-".to_string(),
    };
    let result = req.execute(&mut tx, RequestId::new()).await;
    assert!(result.is_err(), "Setting an invalid partition ID should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_get_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    let resp = GetCurrentPartitionRequest::builder()
        .build()
        .unwrap()
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get current partition");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.partition.as_deref(), Some("test-partition"));
}
