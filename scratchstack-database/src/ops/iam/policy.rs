//! Policy-level database operations.
use {
    crate::constants::iam::*,
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::error::{InternalFailure, NoSuchEntityException, ValidationError},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr as _,
};

/// Returns the policy id for the given permissions boundary ARN and account id, if it exists and is attachable.
/// Otherwise, returns an appropriate error.
pub async fn get_permissions_boundary_id(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    permissions_boundary: &str,
) -> Result<String, IamError> {
    let permissions_boundary = match Arn::from_str(permissions_boundary) {
        Ok(arn) => arn,
        Err(e) => {
            log::info!("Failed to parse permissions boundary ARN: {e}");
            let message = "Invalid permissions boundary ARN".to_string();

            return Err(IamError::ValidationError(ValidationError::builder().message(message).build()));
        }
    };

    let resource = permissions_boundary.resource();
    if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
        let message = "Permissions boundary ARN must have a resource that starts with \"policy/\"".to_string();
        return Err(ValidationError::builder().message(message).build().into());
    }

    let pb_account_id = permissions_boundary.account_id();
    let pb_account_id = if pb_account_id == AWS_ACCOUNT_ID {
        AWS_ACCOUNT_ID_NUMERIC
    } else if pb_account_id == account_id {
        account_id
    } else {
        let message = "Permissions boundary ARN must have an account ID that matches the request's account ID or 'aws'"
            .to_string();
        return Err(ValidationError::builder().message(message).build().into());
    };

    let policy_path_and_name = &resource[6..];
    let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let policy_path = &policy_path_and_name[..name_start];
    let policy_name = policy_path_and_name[name_start..].to_ascii_lowercase();
    let results = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(pb_account_id)
    .bind(policy_path)
    .bind(policy_name)
    .fetch_all(tx.as_mut())
    .await
    {
        Ok(results) => results,
        Err(e) => {
            log::error!("Failed to query permissions boundary from database: {e}");
            let message = "Internal failure".to_string();
            return Err(ValidationError::builder().message(message).build().into());
        }
    };

    if results.is_empty() {
        let message = format!("Scope ARN: {permissions_boundary} does not exist or is not attachable");
        let err = NoSuchEntityException::builder().message(message).build();
        return Err(err.into());
    }

    if results.len() > 1 {
        let message = "Multiple permissions boundary policies found with the same name and path; this is a database integrity error".to_string(
        );
        return Err(InternalFailure::builder().message(message).build().into());
    }

    let mp_id: &str = match results[0].try_get(0) {
        Ok(mp_id) => mp_id,
        Err(e) => {
            log::error!("Failed to get permissions boundary ID from database row: {e}");
            let message = "Internal failure".to_string();
            return Err(InternalFailure::builder().message(message).build().into());
        }
    };
    Ok(mp_id.to_string())
}
