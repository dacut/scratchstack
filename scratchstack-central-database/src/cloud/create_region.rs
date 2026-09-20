//! CreateRegion database operation
use {
    crate::{RequestExecutor, cloud_internal_failure, constants::*},
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{CreateRegionRequest, CreateRegionResponse},
        types::Region,
    },
    sqlx::{Acquire as _, Error as SqlxError, FromRow, postgres::PgTransaction, query_as},
};

/// Primary key constraint for the `cloud.regions` table.
const CONSTRAINT_REGIONS_PKEY: &str = "regions_pkey";

impl RequestExecutor for CreateRegionRequest {
    type Response = CreateRegionResponse;
    type Error = CloudError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        let mut savepoint = tx.begin().await.map_err(|e| {
            cloud_internal_failure!(
                request_id;
                "Failed to create savepoint: {e}"
            )
        })?;

        #[derive(FromRow)]
        struct RegionRow {
            region_name: String,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        }

        let insert = query_as(indoc! {"
            INSERT INTO cloud.regions (region_name, created_at, updated_at)
            VALUES ($1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING region_name, created_at, updated_at
        "})
        .bind(&self.region_name)
        .fetch_one(savepoint.as_mut())
        .await;
        let row: RegionRow = match insert {
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
                // We already have a region with this name; return the original definition.
                assert_eq!(e.constraint(), Some(CONSTRAINT_REGIONS_PKEY));
                savepoint.rollback().await.map_err(|e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to rollback savepoint after duplicate region error: {e}"
                    )
                })?;

                query_as(indoc! {"
                    SELECT region_name, created_at, updated_at
                    FROM cloud.regions
                    WHERE region_name = $1
                "})
                .bind(&self.region_name)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to fetch existing region after duplicate error: {e}"
                    )
                })?
            }
            Err(e) => {
                return Err(cloud_internal_failure!(
                    request_id;
                    "Failed to insert region: {e}"
                )
                .into());
            }
        };

        let region = Region::builder()
            .region_name(row.region_name)
            .created_at(row.created_at)
            .updated_at(row.updated_at)
            .build()
            .map_err(|e| {
                cloud_internal_failure!(
                    request_id;
                    "Failed to build Region: {e}"
                )
            })?;

        Ok(CreateRegionResponse::builder().region(region).build().map_err(|e| {
            cloud_internal_failure!(
                request_id;
                "Failed to build CreateRegionResponse: {e}"
            )
        })?)
    }
}
