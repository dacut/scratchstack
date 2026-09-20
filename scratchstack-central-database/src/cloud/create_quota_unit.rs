//! CreateQuotaUnit database operation
use {
    crate::{RequestExecutor, cloud_internal_failure, constants::*},
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{CreateQuotaUnitRequest, CreateQuotaUnitResponse},
        types::QuotaUnit,
    },
    sqlx::{Acquire as _, Error as SqlxError, FromRow, postgres::PgTransaction, query_as},
};

/// Primary key constraint for the `cloud.quota_units` table.
const CONSTRAINT_QUOTA_UNITS_PKEY: &str = "quota_units_pkey";

impl RequestExecutor for CreateQuotaUnitRequest {
    type Response = CreateQuotaUnitResponse;
    type Error = CloudError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        let mut savepoint = tx.begin().await.map_err(|e| {
            cloud_internal_failure!(
                request_id;
                "Failed to open a savepoint for CreateQuotaUnitRequest: {e}"
            )
        })?;

        #[derive(FromRow)]
        struct QuotaUnitRow {
            unit: String,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        }

        let insert = query_as(indoc! {"
            INSERT INTO cloud.quota_units (unit, created_at, updated_at)
            VALUES ($1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING unit, created_at, updated_at"})
        .bind(&self.unit)
        .fetch_one(savepoint.as_mut())
        .await;
        let row: QuotaUnitRow = match insert {
            Ok(row) => {
                savepoint.commit().await.map_err(|e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to commit savepoint: {e}"
                    )
                })?;
                row
            }
            Err(SqlxError::Database(e)) if e.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION) => {
                assert_eq!(e.constraint(), Some(CONSTRAINT_QUOTA_UNITS_PKEY));

                // Rollback the savepoint and fetch the existing row.
                savepoint.rollback().await.map_err(|e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to rollback savepoint after duplicate unit error: {e}"
                    )
                })?;

                query_as(indoc! {"
                    SELECT unit, created_at, updated_at
                    FROM cloud.quota_units
                    WHERE unit = $1"
                })
                .bind(&self.unit)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to fetch existing quota unit after duplicate error: {e}"
                    )
                })?
            }
            Err(e) => {
                return Err(cloud_internal_failure!(
                    request_id;
                    "Failed to insert quota unit: {e}"
                )
                .into());
            }
        };

        let quota_unit =
            QuotaUnit::builder().unit(row.unit).created_at(row.created_at).updated_at(row.updated_at).build().map_err(
                |e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to build QuotaUnit: {e}"
                    )
                },
            )?;

        Ok(CreateQuotaUnitResponse::builder().quota_unit(quota_unit).build().map_err(|e| {
            cloud_internal_failure!(
                request_id;
                "Failed to build CreateQuotaUnitResponse: {e}"
            )
        })?)
    }
}
