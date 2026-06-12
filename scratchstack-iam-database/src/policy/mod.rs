//! Policy-level database operations.
mod create_policy;
mod create_policy_version;
mod delete_policy;
mod delete_policy_version;
mod get_policy;
mod get_policy_version;
mod list_entities_for_policy;
mod list_policies;
mod list_policy_tags;
mod list_policy_versions;
mod set_default_policy_version;
mod tag_policy;
mod untag_policy;
pub use {
    create_policy::*, create_policy_version::*, delete_policy::*, delete_policy_version::*, get_policy::*,
    get_policy_version::*, list_entities_for_policy::*, list_policies::*, list_policy_tags::*, list_policy_versions::*,
    set_default_policy_version::*, tag_policy::*, untag_policy::*,
};

use {
    crate::{constants::*, internal_failure},
    indoc::indoc,
    scratchstack_arn::{Arn, IamResourceArn, validate_iam_resource_name},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::{
            Tag,
            error::{InternalFailure, NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{FromRow, Row as _, postgres::PgTransaction, query, query_as},
    std::str::FromStr as _,
};

/// Construct a policy ARN from its components.
pub(crate) fn build_policy_arn(
    partition: &str,
    account_id: &str,
    path: &str,
    policy_name: &str,
) -> Result<Arn, IamError> {
    Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(policy_arn_resource(path, policy_name))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct ARN for managed policy: {e}");
            internal_failure().into()
        })
}

/// Fetch the tags attached to a managed policy.
pub(crate) async fn fetch_policy_tags(
    tx: &mut PgTransaction<'_>,
    managed_policy_id: &str,
) -> Result<Vec<Tag>, IamError> {
    /// The rows returned by the query to fetch managed policy tags.
    #[derive(FromRow)]
    struct PolicyTagRow {
        key_cased: String,
        value: String,
    }

    let rows: Vec<PolicyTagRow> = query_as(indoc! {"
            SELECT key_cased, value
            FROM iam.managed_policy_tags
            WHERE managed_policy_id = $1
            ORDER BY key_lower ASC
        "})
    .bind(managed_policy_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch managed policy tags: {e}");
        internal_failure()
    })?;

    let mut tags = Vec::with_capacity(rows.len());
    for row in rows.into_iter() {
        tags.push(Tag {
            key: row.key_cased,
            value: row.value,
        });
    }
    Ok(tags)
}

/// Calculate the number of attachments for a policy by its managed_policy_id. This is the sum of
/// the number of user, group, and role attachments.
pub(crate) async fn get_policy_attachment_count(
    tx: &mut PgTransaction<'_>,
    managed_policy_id: &str,
) -> Result<i32, IamError> {
    let row = query(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.user_attached_policies WHERE managed_policy_id = $1) +
                (SELECT COUNT(*) FROM iam.group_attached_policies WHERE managed_policy_id = $1) +
                (SELECT COUNT(*) FROM iam.role_attached_policies WHERE managed_policy_id = $1)
                AS attachment_count
        "})
    .bind(managed_policy_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query attachment count for managed policy: {e}");
        internal_failure()
    })?;

    row.try_get::<i64, _>(0)
        .map(|count| {
            if count > i32::MAX as i64 {
                i32::MAX
            } else {
                count as i32
            }
        })
        .map_err(|e| {
            log::error!("Failed to get attachment_count from database row: {e}");
            internal_failure().into()
        })
}

/// Calculate the number of permissions boundary attachments for a policy by its managed_policy_id.
/// This is the sum of the number of user and role permissions boundary attachments.
async fn get_policy_permissions_boundary_usage_count(
    tx: &mut PgTransaction<'_>,
    managed_policy_id: &str,
) -> Result<i32, IamError> {
    let row = query(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.users WHERE permissions_boundary_managed_policy_id = $1) +
                (SELECT COUNT(*) FROM iam.roles WHERE permissions_boundary_managed_policy_id = $1)
                AS usage_count
        "})
    .bind(managed_policy_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query permissions boundary usage count for managed policy: {e}");
        internal_failure()
    })?;

    row.try_get::<i64, _>("usage_count")
        .map(|count| {
            if count > i32::MAX as i64 {
                i32::MAX
            } else {
                count as i32
            }
        })
        .map_err(|e| {
            log::error!("Failed to get usage_count from database row: {e}");
            internal_failure().into()
        })
}

/// Look up the `managed_policy_id` for a policy named by ARN; returns NoSuchEntity if not found.
async fn lookup_managed_policy_id(tx: &mut PgTransaction<'_>, policy_arn: &IamResourceArn) -> Result<String, IamError> {
    let policy_account_id = match policy_arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(policy_account_id)
    .bind(policy_arn.resource_path())
    .bind(policy_arn.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        internal_failure()
    })?
    .ok_or_else(|| NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())?
    .try_get(0)
    .map_err(|e| {
        log::error!("Failed to get managed_policy_id from database row: {e}");
        internal_failure().into()
    })
}

/// Parse a policy ARN and extract the account id, path, and lowercase policy name. Returns a
/// `ValidationError` if the ARN is unparseable or does not point at a policy resource.
pub(crate) fn parse_policy_arn(policy_arn: &str) -> Result<IamResourceArn, IamError> {
    let arn = IamResourceArn::from_str(policy_arn).map_err(|e| {
        log::info!("Failed to parse policy ARN: {e}");
        ValidationError::builder().message("Invalid policy ARN".to_string()).build()
    })?;

    if !arn.region().is_empty() {
        return Err(ValidationError::builder().message("Policy ARN must not have a region".to_string()).build().into());
    }

    if arn.resource_type() != "policy" {
        return Err(ValidationError::builder()
            .message("Policy ARN must have a resource that starts with \"policy/\"".to_string())
            .build()
            .into());
    }

    validate_policy_name(arn.resource_name())?;

    Ok(arn)
}

/// Parse a policy version id of the form `v<N>` or `v<N>.<suffix>` into its numeric portion.
/// Returns `None` if the input does not start with `v` followed by digits.
pub(crate) fn parse_policy_version_id(version_id: &str) -> Option<i64> {
    let digits = version_id.strip_prefix('v')?;
    let digits = digits.split('.').next().unwrap_or(digits);
    digits.parse::<i64>().ok().filter(|n| *n > 0)
}

/// Return an ARN resource string for a policy with the given path and name.
///
/// The path is expected to start and end with a slash, but this function will trim extra slashes
/// if needed.
pub(crate) fn policy_arn_resource(path: &str, policy_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_POLICY}/{policy_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_POLICY}/{resource_path}/{policy_name}")
    }
}

/// Returns the policy id for the given permissions boundary ARN and account id, if it exists and is attachable.
/// Otherwise, returns an appropriate error.
pub(crate) async fn get_permissions_boundary_id(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    permissions_boundary: &str,
) -> Result<String, IamError> {
    let permissions_boundary = match IamResourceArn::from_str(permissions_boundary) {
        Ok(arn) => arn,
        Err(e) => {
            log::info!("Failed to parse permissions boundary ARN: {e}");
            let message = "Invalid permissions boundary ARN".to_string();

            return Err(ValidationError::builder().message(message).build().into());
        }
    };

    if permissions_boundary.resource_type() != ARN_RESOURCE_TYPE_POLICY {
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

    let results = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(pb_account_id)
    .bind(permissions_boundary.resource_path())
    .bind(permissions_boundary.resource_name_lower())
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

/// Validate that the policy name is valid according to AWS IAM rules.
pub fn validate_policy_name(policy_name: impl AsRef<str>) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Policy name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 128 characters long.";

    let policy_name = policy_name.as_ref();
    if policy_name.len() > 128 || validate_iam_resource_name(policy_name).is_err() {
        Err(ValidationError::builder().message(MESSAGE).build())
    } else {
        Ok(())
    }
}
