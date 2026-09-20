//! CreateQuotaDefinition database operation
use {
    crate::{RequestExecutor, cloud_internal_failure, constants::*},
    chrono::{DateTime, Utc},
    indoc::indoc,
    rand::random,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{CreateQuotaDefinitionRequest, CreateQuotaDefinitionResponse},
        types::{
            QuotaDefinition, QuotaScope,
            error::{EntityAlreadyExistsException, ResourceNotFoundException},
        },
    },
    sqlx::{
        Acquire as _, Error as SqlxError, FromRow, QueryBuilder, postgres::PgTransaction, query_as, types::BigDecimal,
    },
};

/// Primary key constraint for the `cloud.quota_definitions` table.
const CONSTRAINT_QUOTA_DEFINITIONS_PKEY: &str = "quota_definitions_pkey";

/// Uniqueness constraint for the `cloud.quota_definitions` table on the combination of `service_id`
/// and `quota_name`.
const CONSTRAINT_QUOTA_DEFINITIONS_SERVICE_ID_QUOTA_NAME_KEY: &str = "quota_definitions_service_id_quota_name_key";

/// Foreign key constraint for the `cloud.quota_definitions` table on the `service_id` column.
const CONSTRAINT_QUOTA_DEFINITIONS_SERVICE_ID_FKEY: &str = "quota_definitions_service_id_fkey";

/// Foreign key constraint for the `cloud.quota_definitions` table on the `unit` column.
const CONSTRAINT_QUOTA_DEFINITIONS_UNIT_FKEY: &str = "quota_definitions_unit_fkey";

/// The columns every path through this operation reports back, whether the definition was just
/// inserted or was already there and matched.
///
/// `quota_id` is returned rather than assumed: a definition that already exists keeps the id it
/// was created with, and the one generated for the attempted insert is discarded.
#[derive(FromRow)]
struct QuotaDefinitionRow {
    quota_id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// A definition already stored under a service and quota name: everything a request can specify,
/// alongside the columns [`QuotaDefinitionRow`] carries.
///
/// This is what a repeated request is checked against. `CreateQuotaDefinition` has no update path
/// -- `UpdateQuotaDefinition` is the operation for changing a definition -- so a request that
/// disagrees with any of these columns is refused rather than applied.
#[derive(FromRow)]
struct StoredQuotaDefinition {
    quota_id: String,
    global: bool,
    unit: String,
    description: Option<String>,
    default_value: Option<BigDecimal>,
    min_value: Option<BigDecimal>,
    max_value: Option<BigDecimal>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl RequestExecutor for CreateQuotaDefinitionRequest {
    type Response = CreateQuotaDefinitionResponse;
    type Error = CloudError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        let mut savepoint = tx.begin().await.map_err(
            |e| cloud_internal_failure!(request_id; "Failed to open a savepoint for CreateQuotaDefinitionRequest: {e}"),
        )?;

        let quota_id_numeric = random::<u64>();
        let quota_id = format!("quota-0{quota_id_numeric:16x}");

        let global = self.scope == QuotaScope::Global;

        let mut sql =
            QueryBuilder::new("INSERT INTO cloud.quota_definitions(quota_id, service_id, quota_name, global, unit");
        if self.description.is_some() {
            sql.push(", description");
        }
        if self.default_value.is_some() {
            sql.push(", default_value");
        }
        if self.min_value.is_some() {
            sql.push(", min_value");
        }
        if self.max_value.is_some() {
            sql.push(", max_value");
        }
        sql.push(") VALUES (");
        sql.push_bind(&quota_id);
        sql.push(",");
        sql.push_bind(&self.service_id);
        sql.push(",");
        sql.push_bind(&self.quota_name);
        sql.push(",");
        sql.push_bind(global);
        sql.push(",");
        sql.push_bind(&self.unit);
        if let Some(description) = &self.description {
            sql.push(",");
            sql.push_bind(description);
        }
        if let Some(default_value) = &self.default_value {
            sql.push(",");
            sql.push_bind(default_value);
        }
        if let Some(min_value) = &self.min_value {
            sql.push(",");
            sql.push_bind(min_value);
        }
        if let Some(max_value) = &self.max_value {
            sql.push(",");
            sql.push_bind(max_value);
        }
        sql.push(") RETURNING quota_id, created_at, updated_at");

        let insert = sql.build_query_as::<QuotaDefinitionRow>().fetch_one(savepoint.as_mut()).await;

        let row = match insert {
            Ok(row) => {
                savepoint.commit().await.map_err(
                    |e| cloud_internal_failure!(request_id; "Failed to release the quota definition savepoint: {e}"),
                )?;
                row
            }
            Err(e) => match classify_quota_definition_insert_failure(&e) {
                // The service already has a definition under this name. CreateQuotaDefinition is
                // idempotent, so a request that asks for exactly what is already stored gets it
                // back; one that asks for anything else is refused rather than applied.
                QuotaDefinitionInsertFailure::Duplicate => {
                    savepoint.rollback().await.map_err(|e| {
                        cloud_internal_failure!(
                            request_id;
                            "Failed to roll back to the quota definition savepoint: {e}"
                        )
                    })?;
                    existing_unchanged(self, tx, request_id).await?
                }

                // The two foreign keys are the only way the caller can name something that does
                // not exist, and each one says which.
                QuotaDefinitionInsertFailure::NoSuchService => {
                    return Err(ResourceNotFoundException::builder()
                        .request_id(request_id)
                        .message(format!("Unknown service: {}", self.service_id))
                        .build()
                        .into());
                }
                QuotaDefinitionInsertFailure::NoSuchUnit => {
                    return Err(ResourceNotFoundException::builder()
                        .request_id(request_id)
                        .message(format!("Unknown quota unit: {}", self.unit))
                        .build()
                        .into());
                }

                // Nothing the caller did -- a collision on the randomly generated quota id lands
                // here too, since that is ours to get right and not theirs to work around.
                QuotaDefinitionInsertFailure::Other => {
                    return Err(cloud_internal_failure!(
                        request_id;
                        "Failed to insert quota definition {} for service {}: {}",
                        self.quota_name,
                        self.service_id,
                        e
                    )
                    .into());
                }
            },
        };

        let quota_definition = QuotaDefinition::builder()
            .quota_id(row.quota_id)
            .scope(self.scope)
            .service_id(self.service_id.clone())
            .quota_name(self.quota_name.clone())
            .set_description(self.description.clone())
            .unit(self.unit.clone())
            .set_default_value(self.default_value.clone())
            .set_min_value(self.min_value.clone())
            .set_max_value(self.max_value.clone())
            .created_at(row.created_at)
            .updated_at(row.updated_at)
            .build()
            .map_err(|e| cloud_internal_failure!(request_id; "Failed to build quota definition: {e}"))?;
        Ok(CreateQuotaDefinitionResponse::builder().quota_definition(quota_definition).build().map_err(
            |e| cloud_internal_failure!(request_id; "Failed to build create quota definition response: {e}"),
        )?)
    }
}

/// Return the definition already stored for this service and quota name, provided the request asks
/// for exactly what is stored.
///
/// `CreateQuotaDefinition` is `@idempotent`, so repeating a request has to be accepted and has to
/// leave the same row behind -- the stored `quota_id`, `created_at` and `updated_at` all come back
/// untouched, since nothing is written. It is not an update: changing a stored definition is what
/// `UpdateQuotaDefinition` is for, so a request that disagrees with any column the caller can set
/// is refused and the stored definition is left as it was.
async fn existing_unchanged(
    request: &CreateQuotaDefinitionRequest,
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
) -> Result<QuotaDefinitionRow, CloudError> {
    let stored = query_as::<_, StoredQuotaDefinition>(indoc! {"
            SELECT quota_id, global, unit, description, default_value, min_value, max_value,
                created_at, updated_at
            FROM cloud.quota_definitions
            WHERE service_id = $1 AND quota_name = $2
        "})
    .bind(&request.service_id)
    .bind(&request.quota_name)
    .fetch_one(tx.as_mut())
    .await
    // Includes `RowNotFound`: the definition that collided a moment ago is gone, which cannot
    // happen inside this transaction.
    .map_err(|e| {
        cloud_internal_failure!(
            request_id;
            "Failed to read the existing quota definition {} for service {}: {e}",
            request.quota_name,
            request.service_id
        )
    })?;

    let differing = differing_fields(request, &stored);
    if !differing.is_empty() {
        return Err(EntityAlreadyExistsException::builder()
            .request_id(request_id)
            .message(format!(
                "A quota definition with the same name but a different {} already exists: {}/{}",
                conjoin(&differing),
                request.service_id,
                request.quota_name
            ))
            .build()
            .into());
    }

    Ok(QuotaDefinitionRow {
        quota_id: stored.quota_id,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
    })
}

/// Names every column the request disagrees with, reading the request in the order its fields are
/// declared, or an empty list when the request asks for exactly what is stored.
///
/// All of them rather than just the first: a caller who got one field wrong has usually got the
/// wrong definition in hand entirely, and fixing them one round trip at a time helps nobody.
fn differing_fields(request: &CreateQuotaDefinitionRequest, stored: &StoredQuotaDefinition) -> Vec<&'static str> {
    let mut differing = Vec::new();

    if stored.global != (request.scope == QuotaScope::Global) {
        differing.push("scope");
    }
    if stored.unit != request.unit {
        differing.push("unit");
    }
    if stored.description != request.description {
        differing.push("description");
    }
    if stored.default_value != request.default_value {
        differing.push("default value");
    }
    if stored.min_value != request.min_value {
        differing.push("minimum value");
    }
    if stored.max_value != request.max_value {
        differing.push("maximum value");
    }

    differing
}

/// Renders field names as an English series: `scope`, `scope and unit`, `scope, unit and
/// description`.
fn conjoin(fields: &[&str]) -> String {
    match fields {
        [] => String::new(),
        [only] => (*only).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// What a failed insert into `cloud.quota_definitions` means for a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaDefinitionInsertFailure {
    /// The service and quota name are already defined. Whether that is an error depends on what
    /// the caller asked for: a request matching the stored definition is idempotent and succeeds,
    /// and any other request is refused. See [`existing_unchanged`].
    Duplicate,

    /// `service_id` does not name a row in `cloud.services`.
    NoSuchService,

    /// `unit` does not name a row in `cloud.quota_units`.
    NoSuchUnit,

    /// Anything else: a generated quota id that collided, a connection that dropped, a constraint
    /// added since this was written. None of these are the caller's doing, so all of them become
    /// an internal failure.
    Other,
}

/// Classify a failed insert into `cloud.quota_definitions`.
pub fn classify_quota_definition_insert_failure(e: &SqlxError) -> QuotaDefinitionInsertFailure {
    let SqlxError::Database(db_err) = e else {
        return QuotaDefinitionInsertFailure::Other;
    };

    match (db_err.code().as_deref(), db_err.constraint()) {
        (Some(SQLSTATE_UNIQUE_VIOLATION), Some(CONSTRAINT_QUOTA_DEFINITIONS_PKEY))
        | (Some(SQLSTATE_UNIQUE_VIOLATION), Some(CONSTRAINT_QUOTA_DEFINITIONS_SERVICE_ID_QUOTA_NAME_KEY)) => {
            QuotaDefinitionInsertFailure::Duplicate
        }
        (Some(SQLSTATE_FOREIGN_KEY_VIOLATION), Some(CONSTRAINT_QUOTA_DEFINITIONS_SERVICE_ID_FKEY)) => {
            QuotaDefinitionInsertFailure::NoSuchService
        }
        (Some(SQLSTATE_FOREIGN_KEY_VIOLATION), Some(CONSTRAINT_QUOTA_DEFINITIONS_UNIT_FKEY)) => {
            QuotaDefinitionInsertFailure::NoSuchUnit
        }
        _ => QuotaDefinitionInsertFailure::Other,
    }
}
