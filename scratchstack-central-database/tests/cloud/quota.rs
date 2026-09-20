//! Quota test suite.
use {
    bigdecimal::BigDecimal,
    pretty_assertions::assert_eq,
    scratchstack_central_database::RequestExecutor,
    scratchstack_core::{ProvideErrorMetadata as _, ProvideRequestId as _, RequestId},
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError, operation::CreateQuotaDefinitionRequest, types::QuotaScope,
    },
    sqlx::{PgPool, Row as _, query},
    std::str::FromStr as _,
};

/// Reads every column of a stored definition, rendered as text so that one comparison covers the
/// lot regardless of each column's type. `updated_at` is included: nothing this operation does to
/// an existing definition is allowed to move it.
const STORED_DEFINITION: &str = "SELECT quota_id, service_id, quota_name, global::text, unit, description, \
     default_value::text, min_value::text, max_value::text, created_at::text, updated_at::text \
     FROM cloud.quota_definitions WHERE service_id = $1 AND quota_name = $2";

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

/// The definition the conflict tests are checked against: `Gadgets`, with a description and all
/// three bounds set, so that any one field can be varied while the rest still match.
fn gadgets() -> CreateQuotaDefinitionRequest {
    request("Gadgets", QuotaScope::Regional, Some("Gadgets per region."), Some("5"), Some("1"), Some("10"))
}

/// Stores [`gadgets`], or confirms what is already stored. The request is idempotent, so a test can
/// call this without caring whether another one got there first.
async fn store_gadgets(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    gadgets().execute(&mut tx, RequestId::new()).await.expect("Failed to store the baseline definition");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Runs [`STORED_DEFINITION`] for one of the `example` service's definitions, on a pooled
/// connection outside whatever transaction wrote it.
async fn stored(pool: &PgPool, quota_name: &str) -> Vec<Option<String>> {
    let row = query(STORED_DEFINITION)
        .bind("example")
        .bind(quota_name)
        .fetch_one(pool)
        .await
        .expect("the definition should be in the database");
    (0..row.len()).map(|i| row.get(i)).collect()
}

/// Runs a request that should be refused, rolls the transaction back as a caller would, and hands
/// back the error alongside the request id it was sent under.
async fn refused(pool: &PgPool, req: CreateQuotaDefinitionRequest) -> (CloudError, RequestId) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let request_id = RequestId::new();
    let err = req.execute(&mut tx, request_id).await.expect_err("the request should have been refused");
    tx.rollback().await.expect("Failed to rollback transaction");
    (err, request_id)
}

/// Asserts that `err` is the conflict raised for a definition that already exists under different
/// terms, naming `field` as the one that differs.
fn assert_conflict(err: &CloudError, request_id: RequestId, field: &str, quota_name: &str) {
    let expected =
        format!("A quota definition with the same name but a different {field} already exists: example/{quota_name}");
    assert_eq!(err.code(), "EntityAlreadyExistsException");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    assert_eq!(err.message(), Some(expected.as_str()));
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

/// `CreateQuotaDefinition` is `@idempotent`: sending the same request twice reports the same
/// definition both times, under the id and timestamps it was first given.
///
/// The second call finds the definition already there and hands back what is stored without
/// writing anything, so every column -- `updated_at` included -- comes out the other side
/// untouched.
pub async fn test_create_quota_definition_idempotent(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let first = request("Cogs", QuotaScope::Regional, Some("Cogs per region."), Some("10"), Some("1"), Some("100"))
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create quota definition")
        .quota_definition;
    tx.commit().await.expect("Failed to commit transaction");
    let before = stored(pool, "Cogs").await;

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let second = request("Cogs", QuotaScope::Regional, Some("Cogs per region."), Some("10"), Some("1"), Some("100"))
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Repeating a definition should succeed")
        .quota_definition;
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(second.quota_id, first.quota_id, "a repeated request should keep the original id");
    assert_eq!(second.created_at, first.created_at, "a repeated request should keep the original creation time");
    assert_eq!(second.updated_at, first.updated_at, "a repeated request should not have written anything");
    assert_eq!(second.scope, first.scope);
    assert_eq!(second.unit, first.unit);
    assert_eq!(second.description, first.description);
    assert_eq!(second.default_value, first.default_value);
    assert_eq!(second.min_value, first.min_value);
    assert_eq!(second.max_value, first.max_value);
    assert_eq!(
        stored(pool, "Cogs").await,
        before,
        "a repeated request should have left the stored definition as it was"
    );

    let count: i64 = query("SELECT COUNT(*) FROM cloud.quota_definitions WHERE service_id = $1 AND quota_name = $2")
        .bind("example")
        .bind("Cogs")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 1, "a repeated request should not have inserted a second row");
}

/// Naming a service that does not exist is the caller's mistake, and comes back as
/// `UnknownServiceError` rather than an internal failure. This is read off the foreign key's name,
/// so it breaks if the constraint is renamed without the constant following it.
pub async fn test_create_quota_definition_unknown_service(pool: &PgPool) {
    let (err, request_id) = refused(
        pool,
        CreateQuotaDefinitionRequest::builder()
            .service_id("nonexistent")
            .quota_name("Widgets")
            .scope(QuotaScope::Global)
            .unit("requests")
            .build()
            .expect("the request should build"),
    )
    .await;

    assert_eq!(err.code(), "ResourceNotFoundException");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    assert_eq!(err.message(), Some("Unknown service: nonexistent"));
}

/// The same for a unit that does not exist, off the other foreign key.
///
/// The quota name has to be one no other test has used: a name that is already defined is settled
/// against the stored definition before the insert's foreign key is ever reached, which is what
/// [`test_create_quota_definition_conflicting_unit`] covers instead.
pub async fn test_create_quota_definition_unknown_unit(pool: &PgPool) {
    let (err, request_id) = refused(
        pool,
        CreateQuotaDefinitionRequest::builder()
            .service_id("example")
            .quota_name("Flywheels")
            .scope(QuotaScope::Global)
            .unit("furlongs")
            .build()
            .expect("the request should build"),
    )
    .await;

    assert_eq!(err.code(), "ResourceNotFoundException");
    assert_eq!(err.request_id(), Some(request_id.to_string().as_str()));
    assert_eq!(err.message(), Some("Unknown quota unit: furlongs"));

    let count: i64 = query("SELECT COUNT(*) FROM cloud.quota_definitions WHERE quota_name = $1")
        .bind("Flywheels")
        .fetch_one(pool)
        .await
        .expect("the count should run")
        .get(0);
    assert_eq!(count, 0, "a refused definition should not have been stored");
}

/// The bounds check added to `cloud.quota_definitions` rejects a definition whose minimum exceeds
/// its maximum. Nothing in the operation looks at the bounds, so the constraint is the only thing
/// standing between a caller and a quota range nothing can satisfy.
pub async fn test_create_quota_definition_contradictory_bounds(pool: &PgPool) {
    let (err, _) = refused(pool, request("Backwards", QuotaScope::Global, None, None, Some("10"), Some("1"))).await;

    // Not something the caller can be told how to fix beyond "those bounds contradict", and not a
    // case the operation classifies, so it lands as an internal failure.
    assert_eq!(err.code(), "InternalFailure");
}

/// Moving a definition from one scope to the other is a change, not a repeat, so it is refused.
pub async fn test_create_quota_definition_conflicting_scope(pool: &PgPool) {
    store_gadgets(pool).await;
    let before = stored(pool, "Gadgets").await;

    let mut req = gadgets();
    req.scope = QuotaScope::Global;
    let (err, request_id) = refused(pool, req).await;

    assert_conflict(&err, request_id, "scope", "Gadgets");
    assert_eq!(stored(pool, "Gadgets").await, before, "a refused request should not have changed the definition");
}

/// The same for the unit, whether or not the unit the caller asks for exists.
///
/// A unit that does not exist is still reported as a conflict rather than as an unknown quota unit: the
/// definition is settled against what is stored before anything is written, so the foreign key is
/// never reached. Telling the caller their unit does not exist would be answering a question they
/// did not get to ask.
pub async fn test_create_quota_definition_conflicting_unit(pool: &PgPool) {
    store_gadgets(pool).await;
    let before = stored(pool, "Gadgets").await;

    for unit in ["bytes", "furlongs"] {
        let mut req = gadgets();
        req.unit = unit.to_string();
        let (err, request_id) = refused(pool, req).await;

        assert_conflict(&err, request_id, "unit", "Gadgets");
        assert_eq!(stored(pool, "Gadgets").await, before, "a refused request should not have changed the definition");
    }
}

/// The same for the description, including the case where the request simply leaves it out.
///
/// An omitted optional used to clear what was stored. It no longer does: a request that omits a
/// field the stored definition has is not the same request, and clearing it is what
/// `UpdateQuotaDefinition` is for.
pub async fn test_create_quota_definition_conflicting_description(pool: &PgPool) {
    store_gadgets(pool).await;
    let before = stored(pool, "Gadgets").await;

    for description in [Some("Something else entirely."), None] {
        let mut req = gadgets();
        req.description = description.map(str::to_string);
        let (err, request_id) = refused(pool, req).await;

        assert_conflict(&err, request_id, "description", "Gadgets");
        assert_eq!(stored(pool, "Gadgets").await, before, "a refused request should not have changed the definition");
    }
}

/// The same for each of the three bounds, which are reported separately so that the caller is told
/// which one they moved.
pub async fn test_create_quota_definition_conflicting_bounds(pool: &PgPool) {
    store_gadgets(pool).await;
    let before = stored(pool, "Gadgets").await;
    let decimal = |v: &str| Some(BigDecimal::from_str(v).expect("the bound should parse"));

    // Each bound is reported separately, so that a caller is told which one they moved.
    let mut dropped_default = gadgets();
    dropped_default.default_value = None;
    let mut moved_min = gadgets();
    moved_min.min_value = decimal("2");
    let mut moved_max = gadgets();
    moved_max.max_value = decimal("20");

    for (field, req) in [("default value", dropped_default), ("minimum value", moved_min), ("maximum value", moved_max)]
    {
        let (err, request_id) = refused(pool, req).await;

        assert_conflict(&err, request_id, field, "Gadgets");
        assert_eq!(stored(pool, "Gadgets").await, before, "a refused request should not have changed the definition");
    }

    // The bound a caller re-sends unchanged is not a difference, whatever scale they write it at:
    // `5` and `5.0` are the same number, and NUMERIC compares them as one.
    let mut req = gadgets();
    req.default_value = decimal("5.0");
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    req.execute(&mut tx, RequestId::new()).await.expect("a bound re-sent at a different scale should still match");
    tx.commit().await.expect("Failed to commit transaction");
    assert_eq!(stored(pool, "Gadgets").await, before, "an idempotent repeat should not have changed the definition");
}

/// A request that disagrees on several fields is told about all of them rather than one per round
/// trip, and they are named in the order the request declares them, not the order they were set.
pub async fn test_create_quota_definition_conflict_names_every_field(pool: &PgPool) {
    store_gadgets(pool).await;
    let before = stored(pool, "Gadgets").await;

    // Two fields read as a pair...
    let mut pair = gadgets();
    pair.scope = QuotaScope::Global;
    pair.unit = "bytes".to_string();
    let (err, request_id) = refused(pool, pair).await;
    assert_conflict(&err, request_id, "scope and unit", "Gadgets");

    // ...and more than two as a series. These are varied back to front, so the message is in the
    // request's own order only if the operation is the one imposing it.
    let mut series = gadgets();
    series.max_value = None;
    series.description = Some("Something else entirely.".to_string());
    series.scope = QuotaScope::Global;
    let (err, request_id) = refused(pool, series).await;
    assert_conflict(&err, request_id, "scope, description and maximum value", "Gadgets");

    assert_eq!(stored(pool, "Gadgets").await, before, "a refused request should not have changed the definition");
}
