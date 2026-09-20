//! Region test suite.
use {
    chrono::{DateTime, Utc},
    pretty_assertions::assert_eq,
    scratchstack_central_database::RequestExecutor,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::operation::CreateRegionRequest,
    sqlx::{PgPool, Row as _, query},
};

/// Builds a `CreateRegion` request for `region_name`.
fn request(region_name: &str) -> CreateRegionRequest {
    CreateRegionRequest::builder().region_name(region_name).build().expect("the request should build")
}

/// A region that does not exist yet is inserted, and reported back with the timestamps the
/// database assigned it.
///
/// The row is read back on a pooled connection *after* the caller's transaction commits, and that
/// is the point of the test rather than an afterthought. The insert happens inside a savepoint,
/// and a savepoint that is never committed is rolled back when it drops -- taking the new row with
/// it while the outer commit succeeds and the response still describes exactly the region the
/// caller asked for. Asserting only on the response passes against a database that kept nothing.
pub async fn test_create_region(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = request("us-test-1").execute(&mut tx, RequestId::new()).await.expect("Failed to create region");
    tx.commit().await.expect("Failed to commit transaction");

    let region = resp.region;
    assert_eq!(region.region_name, "us-test-1");
    let created_at = region.created_at.expect("the response should carry a creation time");
    let updated_at = region.updated_at.expect("the response should carry an update time");
    assert_eq!(created_at, updated_at, "a region that was just created should not report a later update");

    let row = query("SELECT created_at, updated_at FROM cloud.regions WHERE region_name = $1")
        .bind("us-test-1")
        .fetch_optional(pool)
        .await
        .expect("the lookup should run")
        .expect("the region should still be in the database after the transaction committed");
    assert_eq!(row.get::<DateTime<Utc>, _>("created_at"), created_at);
    assert_eq!(row.get::<DateTime<Utc>, _>("updated_at"), updated_at);
}

/// Creating a region that already exists hands back what is stored instead of failing: the unique
/// violation rolls the savepoint back and the original row is read through the outer transaction.
/// The timestamps are the first call's, since nothing was rewritten.
pub async fn test_create_region_duplicate(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let first = request("us-test-2").execute(&mut tx, RequestId::new()).await.expect("Failed to create region").region;
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let second = request("us-test-2")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Recreating an existing region should return the stored one")
        .region;
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(second.region_name, first.region_name);
    assert_eq!(second.created_at, first.created_at, "a duplicate should report the original creation time");
    assert_eq!(second.updated_at, first.updated_at, "a duplicate should not have touched the region");

    // And the rollback left exactly one row behind, which is what regions_pkey is for.
    let count: i64 = query("SELECT COUNT(*) FROM cloud.regions WHERE region_name = $1")
        .bind("us-test-2")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 1, "recreating a region should not have inserted a second row");
}
