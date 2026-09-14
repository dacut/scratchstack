//! CreateQuotaDefinition database operation
use {
    crate::{
        RequestExecutor, cloud_internal_failure,
        quota::{
            QuotaDefinitionInsertFailure, classify_quota_definition_insert_failure, unknown_service_error,
            unknown_unit_error,
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    rand::random,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{CreateQuotaDefinitionRequest, CreateQuotaDefinitionResponse},
        types::{QuotaDefinition, QuotaScope},
    },
    sqlx::{Acquire as _, FromRow, QueryBuilder, postgres::PgTransaction, query_as},
};

/// The columns every path through this operation reports back, whether the definition was just
/// inserted or was already there and got updated.
///
/// `quota_id` is returned rather than assumed: on the update path the definition keeps the id it
/// was created with, and the one generated for the attempted insert is discarded.
#[derive(FromRow)]
struct QuotaDefinitionRow {
    quota_id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl RequestExecutor for CreateQuotaDefinitionRequest {
    type Response = CreateQuotaDefinitionResponse;
    type Error = CloudError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
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

        log::info!("SQL: {}", sql.sql().as_str());

        // The insert runs inside a savepoint. A failed statement aborts the whole transaction in
        // PostgreSQL -- every command after it is refused until a rollback -- so the duplicate
        // arm below could not run its UPDATE without one: the conflict it recovers from is what
        // put the transaction in that state.
        let mut savepoint = tx.begin().await.map_err(
            |e| cloud_internal_failure!(request_id; "Failed to open a savepoint for the quota definition insert: {e}"),
        )?;
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
                // idempotent, so a redefinition replaces the one already stored rather than
                // failing.
                QuotaDefinitionInsertFailure::Duplicate => {
                    savepoint.rollback().await.map_err(|e| {
                        cloud_internal_failure!(
                            request_id;
                            "Failed to roll back to the quota definition savepoint: {e}"
                        )
                    })?;
                    update_existing(self, tx, request_id).await?
                }

                // The two foreign keys are the only way the caller can name something that does
                // not exist, and each one says which.
                QuotaDefinitionInsertFailure::NoSuchService => {
                    return Err(unknown_service_error(&self.service_id, request_id));
                }
                QuotaDefinitionInsertFailure::NoSuchUnit => {
                    return Err(unknown_unit_error(&self.unit, request_id));
                }

                // Nothing the caller did -- a collision on the randomly generated quota id lands
                // here too, since that is ours to get right and not theirs to work around.
                QuotaDefinitionInsertFailure::Other => {
                    return Err(cloud_internal_failure!(
                        request_id;
                        "Failed to insert quota definition {} for service {}: {e}",
                        self.quota_name,
                        self.service_id
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

/// Replace the definition already stored for this service and quota name.
///
/// Every column the request can carry is written, so an omitted optional field clears whatever was
/// stored rather than leaving it behind: the operation is `@idempotent`, and the same request twice
/// has to leave the same row both times. The stored `quota_id` and `created_at` are what the
/// definition was created with and are left alone.
async fn update_existing(
    request: &CreateQuotaDefinitionRequest,
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
) -> Result<QuotaDefinitionRow, CloudError> {
    let global = request.scope == QuotaScope::Global;

    match query_as::<_, QuotaDefinitionRow>(indoc! {"
            UPDATE cloud.quota_definitions
            SET global = $3, unit = $4, description = $5, default_value = $6, min_value = $7,
                max_value = $8, updated_at = CURRENT_TIMESTAMP
            WHERE service_id = $1 AND quota_name = $2
            RETURNING quota_id, created_at, updated_at
        "})
    .bind(&request.service_id)
    .bind(&request.quota_name)
    .bind(global)
    .bind(&request.unit)
    .bind(&request.description)
    .bind(&request.default_value)
    .bind(&request.min_value)
    .bind(&request.max_value)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(row) => Ok(row),

        // The unit foreign key is still reachable here: the row exists, but the request may be
        // moving it to a unit that does not. The service foreign key is not -- the row being
        // updated proves that service exists, and the service is not something this statement
        // changes.
        Err(e) => match classify_quota_definition_insert_failure(&e) {
            QuotaDefinitionInsertFailure::NoSuchUnit => Err(unknown_unit_error(&request.unit, request_id)),

            // Includes `RowNotFound`: the definition that collided a moment ago is gone, which
            // cannot happen inside this transaction.
            _ => Err(cloud_internal_failure!(
                request_id;
                "Failed to update quota definition {} for service {}: {e}",
                request.quota_name,
                request.service_id
            )
            .into()),
        },
    }
}
