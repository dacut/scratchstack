//! Quota unit test suite.
use {
    chrono::{DateTime, Utc},
    pretty_assertions::assert_eq,
    scratchstack_central_database::RequestExecutor,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{operation::CreateQuotaUnitRequest, types::QuotaUnit},
    sqlx::{PgPool, Row as _, query},
};

/// Builds a `CreateQuotaUnit` request for `unit`.
fn request(unit: &str) -> CreateQuotaUnitRequest {
    CreateQuotaUnitRequest::builder().unit(unit).build().expect("the request should build")
}

/// Runs a `CreateQuotaUnit` request in its own transaction and returns the unit it reports.
async fn create(pool: &PgPool, unit: &str) -> QuotaUnit {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = request(unit).execute(&mut tx, RequestId::new()).await.expect("Failed to create quota unit");
    tx.commit().await.expect("Failed to commit transaction");
    resp.quota_unit
}

/// Reads the stored timestamps for `unit` on a pooled connection, outside whatever transaction
/// wrote them. `None` if no such unit is stored.
async fn stored(pool: &PgPool, unit: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    query("SELECT created_at, updated_at FROM cloud.quota_units WHERE unit = $1")
        .bind(unit)
        .fetch_optional(pool)
        .await
        .expect("the lookup should run")
        .map(|row| (row.get("created_at"), row.get("updated_at")))
}

/// A unit that does not exist yet is inserted and reported back with the timestamps the database
/// assigned it.
///
/// As with regions, the row is read back after the caller's transaction commits: the insert runs
/// inside a savepoint, and a savepoint left uncommitted is rolled back on drop while the response
/// still describes the unit the caller asked for.
pub async fn test_create_quota_unit(pool: &PgPool) {
    let unit = create(pool, "widgets").await;

    assert_eq!(unit.unit, "widgets");
    let created_at = unit.created_at.expect("the response should carry a creation time");
    let updated_at = unit.updated_at.expect("the response should carry an update time");
    assert_eq!(created_at, updated_at, "a unit that was just created should not report a later update");

    let (stored_created_at, stored_updated_at) = stored(pool, "widgets")
        .await
        .expect("the unit should still be in the database after the transaction committed");
    assert_eq!(stored_created_at, created_at);
    assert_eq!(stored_updated_at, updated_at);
}

/// `CreateQuotaUnit` is `@idempotent`: the same request twice reports the same unit both times and
/// leaves one row behind. The second call must hand back what is stored rather than rewriting it,
/// so the timestamps are the first call's.
pub async fn test_create_quota_unit_idempotent(pool: &PgPool) {
    let first = create(pool, "gadgets").await;
    let second = create(pool, "gadgets").await;

    assert_eq!(second.unit, first.unit);
    assert_eq!(second.created_at, first.created_at, "a repeated request should report the original creation time");
    assert_eq!(second.updated_at, first.updated_at, "a repeated request should not have touched the unit");

    let count: i64 = query("SELECT COUNT(*) FROM cloud.quota_units WHERE unit = $1")
        .bind("gadgets")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 1, "a repeated request should not have inserted a second row");
}

/// The units migration 0017 seeds are ordinary rows as far as this operation is concerned, and
/// recreating one has to leave it exactly as it was. `requests` is what the quota definition suite
/// hangs its definitions off, so rewriting it here would be felt elsewhere.
pub async fn test_create_quota_unit_already_seeded(pool: &PgPool) {
    let before = stored(pool, "requests").await.expect("migration 0017 should have seeded the requests unit");

    let unit = create(pool, "requests").await;
    assert_eq!(unit.unit, "requests");
    assert_eq!(unit.created_at, Some(before.0), "recreating a seeded unit should report its original creation time");
    assert_eq!(unit.updated_at, Some(before.1), "recreating a seeded unit should report its original update time");

    let after = stored(pool, "requests").await.expect("the seeded unit should still be there");
    assert_eq!(after, before, "recreating a seeded unit should not have rewritten it");
}
