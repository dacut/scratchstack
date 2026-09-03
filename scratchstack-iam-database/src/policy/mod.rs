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
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::{
            Tag,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{FromRow, Row as _, postgres::PgTransaction, query, query_as},
    std::str::FromStr as _,
};

/// Name of the unique constraint that enforces policy-name uniqueness on
/// `iam.managed_policies(account_id, managed_policy_name_lower)`. Used to distinguish a name
/// collision from the other unique violation the table can raise -- a primary-key collision on
/// `managed_policy_id`, whose generated ids [`crate::id::IamId::new`] does not guarantee to be
/// unique.
pub(crate) const POLICY_NAME_UNIQUE_CONSTRAINT: &str = "uk_mp_acctid_polname";

/// Returns true if `e` is a Postgres unique-violation error specifically against the unique
/// constraint on `iam.managed_policies(account_id, managed_policy_name_lower)`.
///
/// A unique violation on any other constraint of the table -- notably a `managed_policy_id`
/// primary-key collision -- is not a name collision and must not be reported as one.
pub(crate) fn is_policy_name_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
            && db_err.constraint() == Some(POLICY_NAME_UNIQUE_CONSTRAINT)
    } else {
        false
    }
}

/// Construct a policy ARN from its components.
pub(crate) fn build_policy_arn(
    partition: &str,
    account_id: &str,
    path: &str,
    policy_name: &str,
    request_id: RequestId,
) -> Result<Arn, IamError> {
    Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(policy_arn_resource(path, policy_name))
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to construct ARN for managed policy: {e}").into())
}

/// Fetch the tags attached to a managed policy.
pub(crate) async fn fetch_policy_tags(
    tx: &mut PgTransaction<'_>,
    managed_policy_id: &str,
    request_id: RequestId,
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
    .map_err(|e| internal_failure!(request_id; "Failed to fetch managed policy tags: {e}"))?;

    let mut tags = Vec::with_capacity(rows.len());
    for row in rows.into_iter() {
        tags.push(Tag {
            key: row.key_cased,
            value: row.value,
        });
    }
    Ok(tags)
}

/// Calculate the number of entities in `account_id` that carry the policy `managed_policy_id`.
/// This is the sum of the number of user, group, and role attachments.
///
/// The count is confined to one account because that is the count IAM reports: an AWS-managed
/// policy is attachable in every account, and what an account is told is how many of *its own*
/// entities carry the policy, not how many carry it everywhere. A customer-managed policy can
/// only be attached within the account that owns it, so for one the confinement changes nothing.
pub(crate) async fn get_policy_attachment_count(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    managed_policy_id: &str,
    request_id: RequestId,
) -> Result<i32, IamError> {
    let row = query(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.user_attached_policies uap
                    JOIN iam.users u ON u.user_id = uap.user_id
                    WHERE uap.managed_policy_id = $1 AND u.account_id = $2) +
                (SELECT COUNT(*) FROM iam.group_attached_policies gap
                    JOIN iam.groups g ON g.group_id = gap.group_id
                    WHERE gap.managed_policy_id = $1 AND g.account_id = $2) +
                (SELECT COUNT(*) FROM iam.role_attached_policies rap
                    JOIN iam.roles r ON r.role_id = rap.role_id
                    WHERE rap.managed_policy_id = $1 AND r.account_id = $2)
                AS attachment_count
        "})
    .bind(managed_policy_id)
    .bind(account_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to query attachment count for managed policy: {e}"))?;

    row.try_get::<i64, _>(0)
        .map(|count| {
            if count > i32::MAX as i64 {
                i32::MAX
            } else {
                count as i32
            }
        })
        .map_err(|e| internal_failure!(request_id; "Failed to get attachment_count from database row: {e}").into())
}

/// Calculate the number of entities in `account_id` that the policy `managed_policy_id` bounds.
/// This is the sum of the number of user and role permissions boundary attachments.
///
/// The count is confined to one account for the same reason
/// [`get_policy_attachment_count`] is.
async fn get_policy_permissions_boundary_usage_count(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    managed_policy_id: &str,
    request_id: RequestId,
) -> Result<i32, IamError> {
    let row = query(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.users
                    WHERE permissions_boundary_managed_policy_id = $1 AND account_id = $2) +
                (SELECT COUNT(*) FROM iam.roles
                    WHERE permissions_boundary_managed_policy_id = $1 AND account_id = $2)
                AS usage_count
        "})
    .bind(managed_policy_id)
    .bind(account_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(
        |e| internal_failure!(request_id; "Failed to query permissions boundary usage count for managed policy: {e}"),
    )?;

    row.try_get::<i64, _>("usage_count")
        .map(|count| {
            if count > i32::MAX as i64 {
                i32::MAX
            } else {
                count as i32
            }
        })
        .map_err(|e| internal_failure!(request_id; "Failed to get usage_count from database row: {e}").into())
}

/// Look up the `managed_policy_id` for a policy named by ARN; returns NoSuchEntity if not found.
async fn lookup_managed_policy_id(
    tx: &mut PgTransaction<'_>,
    policy_arn: &IamResourceArn,
    request_id: RequestId,
) -> Result<String, IamError> {
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
    .map_err(|e| internal_failure!(request_id; "Failed to query managed policy from database: {e}"))?
    .ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .request_id(request_id)
            .build()
    })?
    .try_get(0)
    .map_err(|e| internal_failure!(request_id; "Failed to get managed_policy_id from database row: {e}").into())
}

/// Resolve the account the managed policy `policy_arn` names is stored under, confined to the
/// policies a caller in `account_id` may reach.
///
/// IAM does not share managed policies across accounts. A caller reaches the policies of its own
/// account and the AWS-managed policies, which every account may attach and none owns; an ARN
/// naming any other account names nothing the caller can see. That is reported as a policy that
/// does not exist rather than as a refusal, so a caller learns nothing about whether another
/// account has a policy by that name.
///
/// An AWS-managed policy can be named either through the `aws` account alias, as IAM spells it,
/// or through the numeric account the tables store it under, and both name the same policy. The
/// account returned is the numeric one, ready to be matched against `iam.managed_policies`.
pub(crate) fn resolve_policy_account_id<'arn>(
    account_id: &str,
    policy_arn: &'arn IamResourceArn,
    request_id: RequestId,
) -> Result<&'arn str, IamError> {
    let caller_account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let policy_account_id = match policy_arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    if policy_account_id == caller_account_id || policy_account_id == AWS_ACCOUNT_ID_NUMERIC {
        return Ok(policy_account_id);
    }

    log::info!("{request_id}: Policy {policy_arn} is not reachable from account {caller_account_id}");
    Err(NoSuchEntityException::builder()
        .message(format!("Policy {policy_arn} was not found."))
        .request_id(request_id)
        .build()
        .into())
}

/// Parse a policy ARN into the [`IamResourceArn`] its account id, path and name can be read from.
///
/// # Errors
///
/// A [`ValidationError`] if the ARN does not parse; if it carries a region, since IAM is global
/// and a policy ARN has none; if it names a resource type other than `policy`; or if the resource
/// name is not one [`validate_policy_name`] accepts.
pub(crate) fn parse_policy_arn(policy_arn: &str, request_id: RequestId) -> Result<IamResourceArn, IamError> {
    let arn = IamResourceArn::from_str(policy_arn).map_err(|e| {
        log::info!("{request_id}: Failed to parse policy ARN: {e}");
        ValidationError::builder().message("Invalid policy ARN").request_id(request_id).build()
    })?;

    if !arn.region().is_empty() {
        return Err(ValidationError::builder()
            .message("Policy ARN must not have a region")
            .request_id(request_id)
            .build()
            .into());
    }

    if arn.resource_type() != "policy" {
        return Err(ValidationError::builder()
            .message("Policy ARN must have a resource that starts with \"policy/\"")
            .request_id(request_id)
            .build()
            .into());
    }

    validate_policy_name(arn.resource_name(), request_id)?;

    Ok(arn)
}

/// Parse a policy version id of the form `v<N>` or `v<N>.<suffix>` into `N`.
///
/// Returns `None` unless the input is `v` followed by a positive integer. Positive is part of the
/// rule rather than an accident of parsing: versions are numbered from 1 -- `create_policy` gives
/// a new policy `v1` -- and `iam.managed_policy_versions` carries a
/// `CHECK (managed_policy_version > 0)`, so `v0` names a version no policy can have. It is
/// refused here rather than turned into a query that is guaranteed to match nothing.
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

/// Returns the `managed_policy_id` of the managed policy that `permissions_boundary` names.
///
/// # Errors
///
/// A [`ValidationError`] if the ARN does not parse, names a resource type other than `policy`, or
/// names an account that is neither `account_id` nor `aws`. IAM does not share managed policies
/// across accounts; only the AWS-managed ones are reachable from every account.
///
/// A [`NoSuchEntityException`] if no policy matches, carrying IAM's wording for it: "Scope ARN:
/// ... does not exist or is not attachable".
///
/// # Attachability is not checked
///
/// Only existence is. The message above is quoted from IAM, and its second clause describes a
/// condition this function does not test, even though the crate models it: a managed policy is
/// attachable when it is not `deprecated`, which is what [`get_policy`](fn@get_policy) and
/// [`list_policies`](fn@list_policies) report as `is_attachable`. A deprecated policy will
/// therefore be accepted here as a
/// permissions boundary.
pub(crate) async fn get_permissions_boundary_id(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    permissions_boundary: &str,
    request_id: RequestId,
) -> Result<String, IamError> {
    let permissions_boundary = match IamResourceArn::from_str(permissions_boundary) {
        Ok(arn) => arn,
        Err(e) => {
            log::info!("{request_id}: Failed to parse permissions boundary ARN: {e}");
            let message = "Invalid permissions boundary ARN".to_string();

            return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
        }
    };

    if permissions_boundary.resource_type() != ARN_RESOURCE_TYPE_POLICY {
        let message = "Permissions boundary ARN must have a resource that starts with \"policy/\"".to_string();
        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
    }

    let pb_account_id = permissions_boundary.account_id();
    let pb_account_id = if pb_account_id == AWS_ACCOUNT_ID {
        AWS_ACCOUNT_ID_NUMERIC
    } else if pb_account_id == account_id {
        account_id
    } else {
        let message = "Permissions boundary ARN must have an account ID that matches the request's account ID or 'aws'"
            .to_string();
        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
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
            return Err(internal_failure!(request_id; "Failed to query permissions boundary from database: {e}").into());
        }
    };

    if results.is_empty() {
        let message = format!("Scope ARN: {permissions_boundary} does not exist or is not attachable");
        let err = NoSuchEntityException::builder().message(message).request_id(request_id).build();
        return Err(err.into());
    }

    if results.len() > 1 {
        return Err(internal_failure!(request_id;
            "Multiple permissions boundary policies found for {permissions_boundary}; this is a database integrity error")
        .into());
    }

    let mp_id: &str = match results[0].try_get(0) {
        Ok(mp_id) => mp_id,
        Err(e) => {
            return Err(
                internal_failure!(request_id; "Failed to get permissions boundary ID from database row: {e}").into()
            );
        }
    };
    Ok(mp_id.to_string())
}

/// Validate that the policy name is valid according to AWS IAM rules.
pub fn validate_policy_name(policy_name: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Policy name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 128 characters long.";

    let policy_name = policy_name.as_ref();
    if policy_name.len() > 128 || validate_iam_resource_name(policy_name).is_err() {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}
