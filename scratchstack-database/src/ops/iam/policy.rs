//! Policy-level database operations.
use {
    crate::constants::iam::*,
    indoc::indoc,
    scratchstack_arn::Arn,
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

mod create_policy;
mod create_policy_version;
mod delete_policy;
mod delete_policy_version;
mod get_policy;
mod get_policy_version;
mod list_entities_for_policy;
mod list_policies;
mod list_policy_versions;
mod set_default_policy_version;
mod tag_policy;
mod untag_policy;
pub use {
    create_policy::*, create_policy_version::*, delete_policy::*, delete_policy_version::*, get_policy::*,
    get_policy_version::*, list_entities_for_policy::*, list_policies::*, list_policy_versions::*,
    set_default_policy_version::*, tag_policy::*, untag_policy::*,
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
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}

/// Look up the `managed_policy_id` for a policy named by ARN; returns NoSuchEntity if not found.
async fn lookup_managed_policy_id(
    tx: &mut PgTransaction<'_>,
    parts: &PolicyArnParts,
    policy_arn: &str,
) -> Result<String, IamError> {
    query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?
    .ok_or_else(|| {
        IamError::from(NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())
    })?
    .try_get(0)
    .map_err(|e| {
        log::error!("Failed to get managed_policy_id from database row: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}

/// Parts extracted from a policy ARN.
pub(crate) struct PolicyArnParts {
    /// Owning account id for the policy. The literal `aws` alias is normalized to
    /// `000000000000`.
    pub(crate) account_id: String,
    /// Canonical policy path, including a leading slash.
    pub(crate) policy_path: String,
    /// Lowercase policy name for case-insensitive lookup.
    pub(crate) policy_name_lower: String,
}

/// Parse a policy ARN and extract the account id, path, and lowercase policy name. Returns a
/// `ValidationError` if the ARN is unparseable or does not point at a `policy/` resource.
pub(crate) fn parse_policy_arn(policy_arn: &str) -> Result<PolicyArnParts, IamError> {
    let arn = Arn::from_str(policy_arn).map_err(|e| {
        log::info!("Failed to parse policy ARN: {e}");
        IamError::from(ValidationError::builder().message("Invalid policy ARN".to_string()).build())
    })?;

    let service = arn.service();
    if service != ARN_SERVICE_IAM {
        return Err(ValidationError::builder()
            .message("Policy ARN must have service \"iam\"".to_string())
            .build()
            .into());
    }

    if !arn.region().is_empty() {
        return Err(ValidationError::builder().message("Policy ARN must not have a region".to_string()).build().into());
    }

    let resource = arn.resource();
    if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
        return Err(ValidationError::builder()
            .message("Policy ARN must have a resource that starts with \"policy/\"".to_string())
            .build()
            .into());
    }

    let account_id = match arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC.to_string(),
        other => other.to_string(),
    };

    let policy_path_and_name = &resource[ARN_RESOURCE_PREFIX_POLICY.len()..];
    let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let policy_name_lower = policy_path_and_name[name_start..].to_ascii_lowercase();
    let policy_path = if name_start == 0 {
        "/".to_string()
    } else {
        format!("/{}", &policy_path_and_name[..name_start])
    };

    if policy_name_lower.is_empty() {
        return Err(ValidationError::builder().message("Policy name must not be empty".to_string()).build().into());
    }

    Ok(PolicyArnParts {
        account_id,
        policy_path,
        policy_name_lower,
    })
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
        format!("{ARN_RESOURCE_PREFIX_POLICY}{policy_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_POLICY}{resource_path}/{policy_name}")
    }
}

/// Returns the policy id for the given permissions boundary ARN and account id, if it exists and is attachable.
/// Otherwise, returns an appropriate error.
pub(crate) async fn get_permissions_boundary_id(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    permissions_boundary: &str,
) -> Result<String, IamError> {
    let permissions_boundary = match Arn::from_str(permissions_boundary) {
        Ok(arn) => arn,
        Err(e) => {
            log::info!("Failed to parse permissions boundary ARN: {e}");
            let message = "Invalid permissions boundary ARN".to_string();

            return Err(ValidationError::builder().message(message).build().into());
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
