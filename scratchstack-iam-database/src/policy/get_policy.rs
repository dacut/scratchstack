//! GetPolicy database operation
use {
    crate::{
        RequestExecutor,
        constants::*,
        internal_failure,
        partition::get_current_partition_or_fail,
        policy::{
            build_policy_arn, fetch_policy_tags, get_policy_attachment_count,
            get_policy_permissions_boundary_usage_count, parse_policy_arn,
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetPolicyRequest, GetPolicyResponse},
        types::{Policy, error::NoSuchEntityException},
    },
    sqlx::{FromRow, postgres::PgTransaction, query_as},
};

impl RequestExecutor for GetPolicyRequest {
    type Response = GetPolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        // The request names the policy and nothing else, so there is no caller account to count
        // attachments in; the policy's own account is the one this form can answer for. A caller
        // that knows who is asking -- the IAM service, which reads it from the session -- calls
        // [`get_policy`] with that account instead.
        let parts = parse_policy_arn(&self.policy_arn, request_id)?;
        get_policy(tx, parts.account_id(), &self.policy_arn, request_id).await
    }
}

/// Get details for a single managed policy by ARN.
///
/// `account_id` names the account asking, which is the account the reported `AttachmentCount` and
/// `PermissionsBoundaryUsageCount` are counted within: an AWS-managed policy is attachable in
/// every account, and IAM reports how many of the asking account's own entities carry it rather
/// than how many carry it everywhere.
pub async fn get_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    policy_arn: &str,
    request_id: RequestId,
) -> Result<GetPolicyResponse, IamError> {
    /// The row returned by the query to the iam.policies table to get details for the requested
    /// policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        managed_policy_name_cased: String,
        path: String,
        default_version: i64,
        deprecated: bool,
        description: Option<String>,
        created_at: DateTime<Utc>,
        update_date: DateTime<Utc>,
    }

    let parts = parse_policy_arn(policy_arn, request_id)?;
    let policy_account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let partition = get_current_partition_or_fail(tx, request_id).await?;

    let policy_row: PolicyRow = query_as(indoc! {"
            SELECT managed_policy_id, managed_policy_name_cased, path, default_version, deprecated,
                description, created_at, update_date
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(policy_account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        internal_failure(request_id)
    })?
    .ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .request_id(request_id)
            .build()
    })?;

    let arn = build_policy_arn(
        &partition,
        parts.account_id(),
        &policy_row.path,
        &policy_row.managed_policy_name_cased,
        request_id,
    )?;
    let tags = fetch_policy_tags(tx, &policy_row.managed_policy_id, request_id).await?;

    // Both counts are answered for the account asking, whoever owns the policy, so an AWS-managed
    // policy reports what the asking account has done with it rather than nothing at all.
    let counting_account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let attachment_count =
        get_policy_attachment_count(tx, counting_account_id, &policy_row.managed_policy_id, request_id).await?;
    let permissions_boundary_usage_count =
        get_policy_permissions_boundary_usage_count(tx, counting_account_id, &policy_row.managed_policy_id, request_id)
            .await?;

    let policy = Policy::builder()
        .arn(arn.to_string())
        .attachment_count(attachment_count)
        .create_date(policy_row.created_at)
        .default_version_id(format!("v{}", policy_row.default_version))
        .set_description(policy_row.description)
        .is_attachable(!policy_row.deprecated)
        .path(policy_row.path)
        .permissions_boundary_usage_count(permissions_boundary_usage_count)
        .policy_id(format!("{}{}", IamResourceType::ManagedPolicy.as_str(), policy_row.managed_policy_id))
        .policy_name(policy_row.managed_policy_name_cased)
        .update_date(policy_row.update_date)
        .set_tags(tags)
        .build()
        .map_err(|e| {
            log::error!("Failed to construct policy object: {e}");
            internal_failure(request_id)
        })?;
    Ok(GetPolicyResponse {
        policy: Some(policy),
    })
}
