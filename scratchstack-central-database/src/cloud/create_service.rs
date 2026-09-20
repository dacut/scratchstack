//! CreateRegion database operation
use {
    crate::{RequestExecutor, cloud_internal_failure, constants::*},
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{CreateServiceRequest, CreateServiceResponse},
        types::{Service, error::EntityAlreadyExistsException},
    },
    sqlx::{Acquire as _, Error as SqlxError, FromRow, QueryBuilder, postgres::PgTransaction, query_as},
};

/// Primary key constraint for the `cloud.services` table.
const CONSTRAINT_SERVICES_PKEY: &str = "services_pkey";

/// Uniqueness constraint for the `cloud.services` table on the `service_dns_name` column.
const CONSTRAINT_SERVICES_SERVICE_DNS_NAME_KEY: &str = "services_service_dns_name_key";

impl RequestExecutor for CreateServiceRequest {
    type Response = CreateServiceResponse;
    type Error = CloudError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        let mut savepoint = tx.begin().await.map_err(|e| {
            cloud_internal_failure!(
                request_id;
                "Failed to open a savepoint for CreateServiceRequest: {e}"
            )
        })?;

        #[derive(FromRow)]
        struct ServiceRow {
            service_id: String,
            service_dns_name: String,
            description: Option<String>,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        }

        let mut sql =
            QueryBuilder::new("INSERT INTO cloud.services(service_id, service_dns_name, created_at, updated_at");
        if self.description.is_some() {
            sql.push(", description");
        }
        sql.push(") VALUES (");
        sql.push_bind(&self.service_id);
        sql.push(", ");
        sql.push_bind(&self.service_dns_name);
        sql.push(", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP");
        if let Some(description) = &self.description {
            sql.push(", ");
            sql.push_bind(description);
        }
        sql.push(") RETURNING service_id, service_dns_name, description, created_at, updated_at");

        let insert = sql.build_query_as::<ServiceRow>().fetch_one(savepoint.as_mut()).await;

        let row = match insert {
            Ok(row) => {
                savepoint.commit().await.map_err(|e| {
                    cloud_internal_failure!(
                        request_id;
                        "Failed to commit savepoint after successful insert: {e}"
                    )
                })?;
                assert_eq!(row.service_id, self.service_id);
                row
            }
            Err(e) => match classify_service_insert_failure(&e) {
                ServiceInsertFailure::DuplicateServiceId => {
                    savepoint.rollback().await.map_err(|e| {
                        cloud_internal_failure!(
                            request_id;
                            "Failed to rollback savepoint after duplicate insert failure: {e}"
                        )
                    })?;

                    // Do we have a service with the exact same values?
                    let row = query_as::<_, ServiceRow>(indoc! {"
                        SELECT service_id, service_dns_name, description, created_at, updated_at
                        FROM cloud.services
                        WHERE service_id = $1
                    "})
                    .bind(&self.service_id)
                    .fetch_one(tx.as_mut())
                    .await
                    .map_err(|e| {
                        cloud_internal_failure!(
                            request_id;
                            "Failed to query service after duplicate insert failure: {e}"
                        )
                    })?;

                    assert_eq!(row.service_id, self.service_id);

                    if row.service_dns_name != self.service_dns_name {
                        return Err(EntityAlreadyExistsException::builder()
                            .request_id(request_id)
                            .message(format!(
                                "A service with the same service_id but different DNS name already exists: {}",
                                self.service_id
                            ))
                            .build()
                            .into());
                    }

                    if row.description != self.description {
                        return Err(EntityAlreadyExistsException::builder()
                            .request_id(request_id)
                            .message(format!(
                                "A service with the same service_id but different description already exists: {}",
                                self.service_id
                            ))
                            .build()
                            .into());
                    }

                    row
                }
                ServiceInsertFailure::DuplicateServiceDnsName => {
                    savepoint.rollback().await.map_err(|e| {
                        cloud_internal_failure!(
                            request_id;
                            "Failed to rollback savepoint after duplicate DNS name insert failure: {e}"
                        )
                    })?;

                    return Err(EntityAlreadyExistsException::builder()
                        .request_id(request_id)
                        .message(format!(
                            "A service with the same DNS name but different service_id already exists: {}",
                            self.service_dns_name
                        ))
                        .build()
                        .into());
                }
                ServiceInsertFailure::Other => {
                    return Err(cloud_internal_failure!(
                        request_id;
                        "Failed to insert service due to an unexpected error: {e}"
                    )
                    .into());
                }
            },
        };

        let service = Service::builder()
            .service_id(self.service_id.clone())
            .service_dns_name(self.service_dns_name.clone())
            .set_description(self.description.clone())
            .created_at(row.created_at)
            .updated_at(row.updated_at)
            .build()
            .map_err(|e| {
                cloud_internal_failure!(
                    request_id;
                    "Failed to build Service: {e}"
                )
            })?;

        Ok(CreateServiceResponse::builder().service(service).build().map_err(|e| {
            cloud_internal_failure!(
                request_id;
                "Failed to build CreateServiceResponse: {e}"
            )
        })?)
    }
}

/// What a failed insert into `cloud.services` means for a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceInsertFailure {
    /// The service id already exists.
    DuplicateServiceId,

    /// The service DNS name already exists.
    DuplicateServiceDnsName,

    /// Anything else
    Other,
}

fn classify_service_insert_failure(e: &SqlxError) -> ServiceInsertFailure {
    let SqlxError::Database(db_err) = e else {
        return ServiceInsertFailure::Other;
    };

    if db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION) {
        match db_err.constraint() {
            Some(CONSTRAINT_SERVICES_PKEY) => ServiceInsertFailure::DuplicateServiceId,
            Some(CONSTRAINT_SERVICES_SERVICE_DNS_NAME_KEY) => ServiceInsertFailure::DuplicateServiceDnsName,
            _ => ServiceInsertFailure::Other,
        }
    } else {
        ServiceInsertFailure::Other
    }
}
