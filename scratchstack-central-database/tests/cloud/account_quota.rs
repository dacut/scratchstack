//! Account quota schema test suite.
//!
//! `cloud.account_quotas` has no operations behind it yet, so these drive the table directly. The
//! keys it carries are what decide whether a global quota can be stored at all, and whether a
//! regional one can name a region its service was never enabled in -- neither of which any Rust
//! code is in a position to check.
use {
    pretty_assertions::assert_eq,
    sqlx::{Error as SqlxError, PgPool, Row as _, query},
};

/// The account the rows in this suite belong to.
const ACCOUNT_ID: &str = "000000000001";

/// The service the rows in this suite hang off; seeded by [tests/cloud.sql](../cloud.sql).
const SERVICE_ID: &str = "example";

/// A region `example` is *not* enabled in, so a quota that names it has to be refused.
const UNAVAILABLE_REGION: &str = "test-region-2";

/// The region `example` is enabled in; seeded by [tests/cloud.sql](../cloud.sql).
const AVAILABLE_REGION: &str = "test-region-1";

/// SQLSTATE for a foreign key violation.
const SQLSTATE_FOREIGN_KEY_VIOLATION: &str = "23503";

/// SQLSTATE for a unique violation.
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";

/// Defines a quota on the `example` service so account quotas have something to reference.
async fn define_quota(pool: &PgPool, quota_id: &str, quota_name: &str, global: bool) {
    query(
        "INSERT INTO cloud.quota_definitions(quota_id, service_id, quota_name, global, unit)
         VALUES ($1, $2, $3, $4, 'requests')",
    )
    .bind(quota_id)
    .bind(SERVICE_ID)
    .bind(quota_name)
    .bind(global)
    .execute(pool)
    .await
    .expect("the quota definition should insert");
}

/// Assigns a quota to [`ACCOUNT_ID`], in `region_name` or globally when that is `None`. The
/// database error is handed back rather than unwrapped, since refusing the insert is what most of
/// these tests are about.
async fn assign(pool: &PgPool, quota_id: &str, region_name: Option<&str>) -> Result<(), SqlxError> {
    query(
        "INSERT INTO cloud.account_quotas(account_id, service_id, quota_id, region_name, quota_value)
         VALUES ($1, $2, $3, $4, 100)",
    )
    .bind(ACCOUNT_ID)
    .bind(SERVICE_ID)
    .bind(quota_id)
    .bind(region_name)
    .execute(pool)
    .await
    .map(|_| ())
}

/// The SQLSTATE `e` reports, for a `Result` that is expected to be a database error.
fn sqlstate(e: &SqlxError) -> String {
    e.as_database_error()
        .unwrap_or_else(|| panic!("the insert should have failed against the database, not with {e}"))
        .code()
        .expect("the database error should carry a SQLSTATE")
        .into_owned()
}

/// A global quota leaves `region_name` unset, so the column has to be nullable -- which is why the
/// table's uniqueness is a `UNIQUE` constraint and not a primary key. PostgreSQL makes every
/// primary key column `NOT NULL`, and a global quota would have had nowhere to go.
pub async fn test_global_quota_stores_a_null_region(pool: &PgPool) {
    define_quota(pool, "aq-global-1", "AccountQuotaGlobalStores", true).await;
    assign(pool, "aq-global-1", None).await.expect("a global quota should store with no region");

    let stored: Option<String> = query("SELECT region_name FROM cloud.account_quotas WHERE quota_id = $1")
        .bind("aq-global-1")
        .fetch_one(pool)
        .await
        .expect("the lookup should run")
        .get("region_name");
    assert_eq!(stored, None, "a global quota should have stored no region at all");
}

/// One global row per account and quota. `NULLS NOT DISTINCT` is what enforces this: under the
/// default `NULLS DISTINCT`, every global assignment would look unique to the database and an
/// account could collect any number of them for the same quota.
pub async fn test_global_quota_is_unique_per_account(pool: &PgPool) {
    define_quota(pool, "aq-global-2", "AccountQuotaGlobalUnique", true).await;
    assign(pool, "aq-global-2", None).await.expect("the first global quota should store");

    let e = assign(pool, "aq-global-2", None).await.expect_err("a second global quota should be refused");
    assert_eq!(sqlstate(&e), SQLSTATE_UNIQUE_VIOLATION);
}

/// The same quota in two different regions is two rows, and neither collides with the global one.
pub async fn test_regional_quotas_are_per_region(pool: &PgPool) {
    define_quota(pool, "aq-regional-1", "AccountQuotaPerRegion", false).await;
    query("INSERT INTO cloud.regions(region_name) VALUES ($1)")
        .bind(UNAVAILABLE_REGION)
        .execute(pool)
        .await
        .expect("the second region should insert");
    query("INSERT INTO cloud.service_regions(service_id, region_name) VALUES ($1, $2)")
        .bind(SERVICE_ID)
        .bind(UNAVAILABLE_REGION)
        .execute(pool)
        .await
        .expect("the service should enable in the second region");

    assign(pool, "aq-regional-1", Some(AVAILABLE_REGION)).await.expect("the first regional quota should store");
    assign(pool, "aq-regional-1", Some(UNAVAILABLE_REGION)).await.expect("the second regional quota should store");
    assign(pool, "aq-regional-1", None).await.expect("a global quota should not collide with the regional ones");

    let count: i64 = query("SELECT COUNT(*) FROM cloud.account_quotas WHERE quota_id = $1")
        .bind("aq-regional-1")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 3);

    let e = assign(pool, "aq-regional-1", Some(AVAILABLE_REGION))
        .await
        .expect_err("the same region twice should be refused");
    assert_eq!(sqlstate(&e), SQLSTATE_UNIQUE_VIOLATION);
}

/// A regional quota has to name a region its service is actually available in. The composite
/// foreign key on `(service_id, region_name)` is the only thing that checks this; referencing the
/// region on its own would let a quota be assigned in a region the service never ran in.
pub async fn test_regional_quota_requires_the_service_in_that_region(pool: &PgPool) {
    define_quota(pool, "aq-regional-2", "AccountQuotaWrongRegion", false).await;
    query("INSERT INTO cloud.regions(region_name) VALUES ('test-region-3')")
        .execute(pool)
        .await
        .expect("the third region should insert");

    let e = assign(pool, "aq-regional-2", Some("test-region-3"))
        .await
        .expect_err("a region the service is not in should be refused");
    assert_eq!(sqlstate(&e), SQLSTATE_FOREIGN_KEY_VIOLATION);

    // The same row is accepted once the service is enabled there, so it is the service/region
    // pairing being refused above and not the region itself.
    query("INSERT INTO cloud.service_regions(service_id, region_name) VALUES ($1, 'test-region-3')")
        .bind(SERVICE_ID)
        .execute(pool)
        .await
        .expect("the service should enable in the third region");
    assign(pool, "aq-regional-2", Some("test-region-3")).await.expect("the quota should store once the service is in");
}
