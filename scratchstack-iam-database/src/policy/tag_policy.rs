//! TagPolicy database operation
use {
    crate::{
        RequestExecutor, internal_failure,
        policy::{lookup_managed_policy_id, parse_policy_arn},
        tag::{validate_tag_key, validate_tag_value},
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::TagPolicyRequest,
        types::{Tag, error::ValidationError},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for TagPolicyRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        tag_policy(tx, &self.policy_arn, &self.tags, request_id).await
    }
}

/// Add or update tags on a managed policy by ARN.
pub async fn tag_policy(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    tags: &[Tag],
    request_id: RequestId,
) -> Result<(), IamError> {
    if tags.is_empty() {
        return Err(ValidationError::builder()
            .message("At least one tag must be provided.")
            .request_id(request_id)
            .build()
            .into());
    }

    // TODO: make sure we don't exceed the maximum number of tags per policy.
    // Default limit is 50 but may vary by account.
    for tag in tags {
        validate_tag_key(&tag.key, request_id)?;
        validate_tag_value(&tag.value, request_id)?;
    }

    let parts = parse_policy_arn(policy_arn, request_id)?;
    let managed_policy_id = lookup_managed_policy_id(tx, &parts, request_id).await?;

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
                ON CONFLICT (managed_policy_id, key_lower)
                DO UPDATE SET key_cased = EXCLUDED.key_cased, value = EXCLUDED.value,
                              updated_at = CURRENT_TIMESTAMP
            "})
        .bind(&managed_policy_id)
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert/update managed policy tag: {e}");
            return Err(internal_failure(request_id).into());
        }
    }

    Ok(())
}
