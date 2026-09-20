//! Service test suite.
use {
    chrono::{DateTime, Utc},
    pretty_assertions::assert_eq,
    scratchstack_central_database::RequestExecutor,
    scratchstack_core::{ProvideErrorMetadata as _, ProvideRequestId as _, RequestId},
    scratchstack_shapes_cloud::{operation::CreateServiceRequest, types::Service},
    sqlx::{PgPool, Row as _, query},
};

/// What `cloud.services` holds for one service.
#[derive(Debug, Eq, PartialEq)]
struct StoredService {
    service_dns_name: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Builds a `CreateService` request.
fn request(service_id: &str, service_dns_name: &str, description: Option<&str>) -> CreateServiceRequest {
    CreateServiceRequest::builder()
        .service_id(service_id)
        .service_dns_name(service_dns_name)
        .set_description(description.map(str::to_string))
        .build()
        .expect("the request should build")
}

/// Runs a `CreateService` request in its own transaction and returns the service it reports.
async fn create(pool: &PgPool, service_id: &str, service_dns_name: &str, description: Option<&str>) -> Service {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = request(service_id, service_dns_name, description)
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create service");
    tx.commit().await.expect("Failed to commit transaction");
    resp.service
}

/// Reads what is stored for `service_id` on a pooled connection, outside whatever transaction
/// wrote it. `None` if no such service is stored.
async fn stored(pool: &PgPool, service_id: &str) -> Option<StoredService> {
    query("SELECT service_dns_name, description, created_at, updated_at FROM cloud.services WHERE service_id = $1")
        .bind(service_id)
        .fetch_optional(pool)
        .await
        .expect("the lookup should run")
        .map(|row| StoredService {
            service_dns_name: row.get("service_dns_name"),
            description: row.get("description"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
}

/// A service that does not exist yet is inserted, with the description left null when the request
/// omits one.
///
/// The row is read back after the caller's transaction commits, for the same reason the region and
/// quota unit suites do it: the insert runs inside a savepoint, and one that is never committed is
/// rolled back on drop while the response still describes what the caller asked for.
pub async fn test_create_service(pool: &PgPool) {
    let service = create(pool, "widgets", "widgets.scratchstack.net", None).await;

    assert_eq!(service.service_id, "widgets");
    assert_eq!(service.service_dns_name, "widgets.scratchstack.net");
    assert_eq!(service.description, None);
    let created_at = service.created_at.expect("the response should carry a creation time");
    let updated_at = service.updated_at.expect("the response should carry an update time");
    assert_eq!(created_at, updated_at, "a service that was just created should not report a later update");

    let row = stored(pool, "widgets").await.expect("the service should still be in the database after the commit");
    assert_eq!(
        row,
        StoredService {
            service_dns_name: "widgets.scratchstack.net".to_string(),
            description: None,
            created_at,
            updated_at,
        }
    );
}

/// A description on the request is stored alongside the rest. The column is built into the insert
/// only when the request carries one, so this is a different statement from the one
/// [`test_create_service`] exercises rather than the same statement with one more bind.
pub async fn test_create_service_with_description(pool: &PgPool) {
    let service = create(pool, "gadgets", "gadgets.scratchstack.net", Some("The gadgets service.")).await;

    assert_eq!(service.service_id, "gadgets");
    assert_eq!(service.description.as_deref(), Some("The gadgets service."));

    let row = stored(pool, "gadgets").await.expect("the service should still be in the database after the commit");
    assert_eq!(row.service_dns_name, "gadgets.scratchstack.net");
    assert_eq!(row.description.as_deref(), Some("The gadgets service."), "the description should have been stored");
}

/// `CreateService` is `@idempotent`: repeating a request that matches what is stored reports the
/// same service and leaves the row alone, timestamps included.
pub async fn test_create_service_idempotent(pool: &PgPool) {
    let first = create(pool, "sprockets", "sprockets.scratchstack.net", Some("The sprockets service.")).await;
    let before = stored(pool, "sprockets").await.expect("the service should be in the database");

    let second = create(pool, "sprockets", "sprockets.scratchstack.net", Some("The sprockets service.")).await;

    assert_eq!(second.service_id, first.service_id);
    assert_eq!(second.service_dns_name, first.service_dns_name);
    assert_eq!(second.description, first.description);
    assert_eq!(second.created_at, first.created_at, "a repeated request should report the original creation time");
    assert_eq!(second.updated_at, first.updated_at, "a repeated request should not have touched the service");

    let after = stored(pool, "sprockets").await.expect("the service should still be in the database");
    assert_eq!(after, before, "a repeated request should have left the row exactly as it was");

    let count: i64 = query("SELECT COUNT(*) FROM cloud.services WHERE service_id = $1")
        .bind("sprockets")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 1, "a repeated request should not have inserted a second row");
}

/// Reusing a service id under a different DNS name is not a redefinition -- `CreateService` has no
/// update path -- so it is refused, and the stored service is left as it was.
pub async fn test_create_service_conflicting_dns_name(pool: &PgPool) {
    let before = stored(pool, "gadgets").await.expect("the gadgets service should exist by now");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let request_id = RequestId::new();
    let err = request("gadgets", "elsewhere.scratchstack.net", Some("The gadgets service."))
        .execute(&mut tx, request_id)
        .await
        .expect_err("reusing a service id under a different DNS name should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(err.code(), "EntityAlreadyExistsException");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    assert_eq!(
        err.message(),
        Some("A service with the same service_id but different DNS name already exists: gadgets")
    );

    let after = stored(pool, "gadgets").await.expect("the gadgets service should still exist");
    assert_eq!(after, before, "a refused create should not have changed the stored service");
}

/// The same for a request that matches on id and DNS name but carries a different description:
/// idempotency means *the same* request, and this one is not it.
pub async fn test_create_service_conflicting_description(pool: &PgPool) {
    let before = stored(pool, "gadgets").await.expect("the gadgets service should exist by now");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let request_id = RequestId::new();
    let err = request("gadgets", "gadgets.scratchstack.net", Some("Something else entirely."))
        .execute(&mut tx, request_id)
        .await
        .expect_err("redescribing an existing service should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(err.code(), "EntityAlreadyExistsException");
    assert_eq!(
        err.message(),
        Some("A service with the same service_id but different description already exists: gadgets")
    );

    let after = stored(pool, "gadgets").await.expect("the gadgets service should still exist");
    assert_eq!(after, before, "a refused create should not have changed the stored service");
}

/// A DNS name belongs to one service. Claiming one that another service already holds is refused
/// off `services_service_dns_name_key` rather than the primary key, which is a different arm of
/// the operation than either duplicate-id case.
pub async fn test_create_service_duplicate_dns_name(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let request_id = RequestId::new();
    let err = request("cogs", "gadgets.scratchstack.net", None)
        .execute(&mut tx, request_id)
        .await
        .expect_err("claiming another service's DNS name should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(err.code(), "EntityAlreadyExistsException");
    assert_eq!(
        err.message(),
        Some("A service with the same DNS name but different service_id already exists: gadgets.scratchstack.net")
    );

    assert!(stored(pool, "cogs").await.is_none(), "the refused service should not have been created");
}
