//! Quota-related database operations.
mod create_quota_definition;
// mod create_quota_unit;
// mod create_region;
// mod create_service;
// mod delete_quota;
// mod delete_quota_definition;
// mod delete_quota_unit;
// mod delete_region;
// mod delete_service;
// mod get_quota;
// mod get_quota_definition;
// mod list_quota_definitions;
// mod list_quota_units;
// mod list_quotas;
// mod list_regions;
// mod list_services;
// mod set_quota;
// mod update_quota_definition;

use {
    crate::constants::{SQLSTATE_FOREIGN_KEY_VIOLATION, SQLSTATE_UNIQUE_VIOLATION},
    scratchstack_core::RequestId,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        types::error::{UnknownServiceError, UnknownUnitError},
    },
};

/// Name of the foreign key on `cloud.quota_definitions` that requires `service_id` to name a row
/// in `cloud.services`.
pub(crate) const QUOTA_DEFINITION_SERVICE_FK_CONSTRAINT: &str = "fk_service";

/// Name of the foreign key on `cloud.quota_definitions` that requires `unit` to name a row in
/// `cloud.quota_units`.
pub(crate) const QUOTA_DEFINITION_UNITS_FK_CONSTRAINT: &str = "fk_unit";

/// Name of the unique constraint that enforces one definition per service and quota name on
/// `cloud.quota_definitions`. Used to distinguish a redefinition -- which the caller is allowed to
/// do, and which turns into an update -- from a primary-key collision on the generated quota id,
/// which is not something the caller did.
pub(crate) const QUOTA_DEFINITION_UNIQUE_CONSTRAINT: &str = "uk_qd_svcid_qname";

/// What a failed insert into `cloud.quota_definitions` means, as far as the caller is concerned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuotaDefinitionInsertFailure {
    /// The service and quota name are already defined. The caller is redefining an existing quota,
    /// which [`CreateQuotaDefinition`] treats as an update rather than an error.
    ///
    /// [`CreateQuotaDefinition`]: crate::quota::create_quota_definition
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

/// Classify a failed insert or update against `cloud.quota_definitions`.
///
/// Postgres constraint names are scoped to their table, and `fk_service` in particular names a
/// constraint on several tables in the `cloud` schema. The names only identify a constraint
/// unambiguously alongside the statement that raised them, so pass errors here only from
/// statements against `cloud.quota_definitions`.
pub(crate) fn classify_quota_definition_insert_failure(e: &sqlx::Error) -> QuotaDefinitionInsertFailure {
    let sqlx::Error::Database(db_err) = e else {
        return QuotaDefinitionInsertFailure::Other;
    };

    match (db_err.code().as_deref(), db_err.constraint()) {
        (Some(SQLSTATE_UNIQUE_VIOLATION), Some(QUOTA_DEFINITION_UNIQUE_CONSTRAINT)) => {
            QuotaDefinitionInsertFailure::Duplicate
        }
        (Some(SQLSTATE_FOREIGN_KEY_VIOLATION), Some(QUOTA_DEFINITION_SERVICE_FK_CONSTRAINT)) => {
            QuotaDefinitionInsertFailure::NoSuchService
        }
        (Some(SQLSTATE_FOREIGN_KEY_VIOLATION), Some(QUOTA_DEFINITION_UNITS_FK_CONSTRAINT)) => {
            QuotaDefinitionInsertFailure::NoSuchUnit
        }
        _ => QuotaDefinitionInsertFailure::Other,
    }
}

/// The error returned when a request names a service that does not exist.
pub(crate) fn unknown_service_error(service_id: &str, request_id: RequestId) -> CloudError {
    UnknownServiceError::builder()
        .request_id(request_id)
        .message(format!("Unknown service: {service_id}"))
        .build()
        .into()
}

/// The error returned when a request names a quota unit that does not exist.
pub(crate) fn unknown_unit_error(unit: &str, request_id: RequestId) -> CloudError {
    UnknownUnitError::builder().request_id(request_id).message(format!("Unknown quota unit: {unit}")).build().into()
}
