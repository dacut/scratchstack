//! Quota test suite.
use {
    bigdecimal::BigDecimal,
    pretty_assertions::assert_eq,
    scratchstack_central_database::RequestExecutor,
    scratchstack_core::{ProvideErrorMetadata as _, ProvideRequestId as _, RequestId},
    scratchstack_shapes_cloud::{operation::CreateQuotaDefinitionRequest, types::QuotaScope},
    sqlx::{PgPool, Row as _, query},
    std::str::FromStr as _,
};

/// Builds a `CreateQuotaDefinition` request for `quota_name` on the `example` service, in
/// `requests`, with whatever bounds the caller wants.
fn request(
    quota_name: &str,
    scope: QuotaScope,
    description: Option<&str>,
    default_value: Option<&str>,
    min_value: Option<&str>,
    max_value: Option<&str>,
) -> CreateQuotaDefinitionRequest {
    let decimal = |v: Option<&str>| v.map(|v| BigDecimal::from_str(v).expect("the bound should parse"));

    CreateQuotaDefinitionRequest::builder()
        .service_id("example")
        .quota_name(quota_name)
        .scope(scope)
        .unit("requests")
        .set_description(description.map(str::to_string))
        .set_default_value(decimal(default_value))
        .set_min_value(decimal(min_value))
        .set_max_value(decimal(max_value))
        .build()
        .expect("the request should build")
}

/// A definition that names a service and a unit that both exist is stored, and reported back with
/// the id the database generated for it.
pub async fn test_create_quota_definition(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = request("Widgets", QuotaScope::Regional, Some("Widgets per region."), Some("10"), Some("1"), Some("100"));
    let resp = req.execute(&mut tx, RequestId::new()).await.expect("Failed to create quota definition");
    tx.commit().await.expect("Failed to commit transaction");

    let definition = resp.quota_definition;
    assert!(definition.quota_id.starts_with("quota-"), "unexpected quota id {}", definition.quota_id);
    assert_eq!(definition.service_id, "example");
    assert_eq!(definition.quota_name, "Widgets");
    assert_eq!(definition.scope, QuotaScope::Regional);
    assert_eq!(definition.unit, "requests");
    assert_eq!(definition.description.as_deref(), Some("Widgets per region."));
    assert_eq!(definition.default_value, Some(BigDecimal::from_str("10").unwrap()));
    assert_eq!(definition.min_value, Some(BigDecimal::from_str("1").unwrap()));
    assert_eq!(definition.max_value, Some(BigDecimal::from_str("100").unwrap()));

    // The row is what the response claims it is, `global` included: the column is what tells a
    // regional quota from a global one, and nothing else in the response reports it.
    let row = query("SELECT quota_id, global, unit, description FROM cloud.quota_definitions WHERE service_id = $1 AND quota_name = $2")
        .bind("example")
        .bind("Widgets")
        .fetch_one(pool)
        .await
        .expect("the definition should be in the database");
    assert_eq!(row.get::<String, _>("quota_id"), definition.quota_id);
    assert!(!row.get::<bool, _>("global"), "a Regional definition should not be marked global");
    assert_eq!(row.get::<String, _>("unit"), "requests");
    assert_eq!(row.get::<Option<String>, _>("description").as_deref(), Some("Widgets per region."));
}

/// Creating the same (service, quota name) again updates the definition in place rather than
/// failing, and keeps the id and creation time it already had. The operation is `@idempotent`, so
/// an omitted optional clears what was stored instead of leaving it behind.
pub async fn test_create_quota_definition_redefines(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let first = request("Gadgets", QuotaScope::Regional, Some("First."), Some("5"), Some("1"), Some("10"))
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create quota definition")
        .quota_definition;
    tx.commit().await.expect("Failed to commit transaction");

    // Same service and name, different scope and bounds, and no description at all.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let second = request("Gadgets", QuotaScope::Global, None, None, Some("2"), Some("20"))
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Redefining an existing quota should update it")
        .quota_definition;
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(second.quota_id, first.quota_id, "a redefinition should keep the original id");
    assert_eq!(second.created_at, first.created_at, "a redefinition should keep the original creation time");
    assert_eq!(second.scope, QuotaScope::Global);
    assert_eq!(second.min_value, Some(BigDecimal::from_str("2").unwrap()));
    assert_eq!(second.max_value, Some(BigDecimal::from_str("20").unwrap()));
    assert_eq!(second.description, None, "an omitted description should clear the stored one");
    assert_eq!(second.default_value, None, "an omitted default should clear the stored one");

    // And there is still exactly one row for the pair, which is what uk_qd_svcid_qname is for.
    let count: i64 = query("SELECT COUNT(*) FROM cloud.quota_definitions WHERE service_id = $1 AND quota_name = $2")
        .bind("example")
        .bind("Gadgets")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 1, "redefining should not have inserted a second row");
}

/// Naming a service that does not exist is the caller's mistake, and comes back as
/// `UnknownServiceError` rather than an internal failure. This is read off the foreign key's name,
/// so it breaks if the constraint is renamed without the constant following it.
pub async fn test_create_quota_definition_unknown_service(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = CreateQuotaDefinitionRequest::builder()
        .service_id("nonexistent")
        .quota_name("Widgets")
        .scope(QuotaScope::Global)
        .unit("requests")
        .build()
        .expect("the request should build");

    let request_id = RequestId::new();
    let err = req.execute(&mut tx, request_id).await.expect_err("an unknown service should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(err.code(), "UnknownServiceError");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    assert_eq!(err.message(), Some("Unknown service: nonexistent"));
}

/// The same for a unit that does not exist, off the other foreign key.
pub async fn test_create_quota_definition_unknown_unit(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = CreateQuotaDefinitionRequest::builder()
        .service_id("example")
        .quota_name("Widgets")
        .scope(QuotaScope::Global)
        .unit("furlongs")
        .build()
        .expect("the request should build");

    let request_id = RequestId::new();
    let err = req.execute(&mut tx, request_id).await.expect_err("an unknown unit should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(err.code(), "UnknownUnitError");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    assert_eq!(err.message(), Some("Unknown quota unit: furlongs"));
}

/// A redefinition can move the quota to a unit that does not exist, which reaches the foreign key
/// on the update path rather than the insert one. That arm is reported separately in the operation
/// and is easy to get wrong, since the service key is unreachable there.
pub async fn test_redefine_quota_definition_unknown_unit(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    request("Sprockets", QuotaScope::Global, None, None, None, None)
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create quota definition");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = CreateQuotaDefinitionRequest::builder()
        .service_id("example")
        .quota_name("Sprockets")
        .scope(QuotaScope::Global)
        .unit("furlongs")
        .build()
        .expect("the request should build");

    let request_id = RequestId::new();
    let err = req.execute(&mut tx, request_id).await.expect_err("an unknown unit should fail on the update path");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(err.code(), "UnknownUnitError");
    assert_eq!(err.message(), Some("Unknown quota unit: furlongs"));
}

/// The bounds check added to `cloud.quota_definitions` rejects a definition whose minimum exceeds
/// its maximum. Nothing in the operation looks at the bounds, so the constraint is the only thing
/// standing between a caller and a quota range nothing can satisfy.
pub async fn test_create_quota_definition_contradictory_bounds(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = request("Backwards", QuotaScope::Global, None, None, Some("10"), Some("1"));

    let request_id = RequestId::new();
    let err = req.execute(&mut tx, request_id).await.expect_err("min above max should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    // Not something the caller can be told how to fix beyond "those bounds contradict", and not a
    // case the operation classifies, so it lands as an internal failure.
    assert_eq!(err.code(), "InternalFailure");
}
