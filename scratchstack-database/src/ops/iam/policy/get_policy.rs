//! GetPolicy database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{
                get_current_partition_or_fail, parse_policy_arn,
                policy::{
                    build_policy_arn, fetch_policy_tags, get_policy_attachment_count,
                    get_policy_permissions_boundary_usage_count,
                },
            },
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetPolicyRequest, GetPolicyResponse},
        types::{
            Policy,
            error::{InternalFailure, NoSuchEntityException},
        },
    },
    sqlx::{FromRow, postgres::PgTransaction, query_as},
};

impl RequestExecutor for GetPolicyRequest {
    type Response = GetPolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_policy(tx, &self.policy_arn).await
    }
}

/// Get details for a single managed policy by ARN.
pub async fn get_policy(tx: &mut PgTransaction<'_>, policy_arn: &str) -> Result<GetPolicyResponse, IamError> {
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

    let parts = parse_policy_arn(policy_arn)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let policy_row: PolicyRow = query_as(indoc! {"
            SELECT managed_policy_id, managed_policy_name_cased, path, default_version, deprecated,
                description, created_at, update_date
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
    })?;

    let arn = build_policy_arn(&partition, &parts.account_id, &policy_row.path, &policy_row.managed_policy_name_cased)?;
    let tags = fetch_policy_tags(tx, &policy_row.managed_policy_id).await?;
    let attachment_count = if parts.account_id == AWS_ACCOUNT_ID_NUMERIC {
        None
    } else {
        Some(get_policy_attachment_count(tx, &policy_row.managed_policy_id).await?)
    };
    let permissions_boundary_usage_count = if parts.account_id == AWS_ACCOUNT_ID_NUMERIC {
        None
    } else {
        Some(get_policy_permissions_boundary_usage_count(tx, &policy_row.managed_policy_id).await?)
    };

    let policy = Policy::builder()
        .arn(Some(arn.to_string()))
        .attachment_count(attachment_count)
        .create_date(Some(policy_row.created_at))
        .default_version_id(Some(format!("v{}", policy_row.default_version)))
        .description(policy_row.description)
        .is_attachable(Some(!policy_row.deprecated))
        .path(Some(policy_row.path))
        .permissions_boundary_usage_count(permissions_boundary_usage_count)
        .policy_id(Some(format!("{}{}", IamResourceType::ManagedPolicy.as_str(), policy_row.managed_policy_id)))
        .policy_name(Some(policy_row.managed_policy_name_cased))
        .update_date(Some(policy_row.update_date))
        .tags(tags)
        .build()?;
    Ok(GetPolicyResponse {
        policy: Some(policy),
    })
}
