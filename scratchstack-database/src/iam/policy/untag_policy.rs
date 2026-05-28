//! UntagPolicy database operation
use {
    crate::{
        RequestExecutor,
        iam::{internal_failure, parse_policy_arn, policy::lookup_managed_policy_id, validate_tag_key},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::UntagPolicyRequest, types::error::ValidationError,
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for UntagPolicyRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        untag_policy(tx, &self.policy_arn, &self.tag_keys).await
    }
}

/// Remove tags from a managed policy by ARN.
pub async fn untag_policy(tx: &mut PgTransaction<'_>, policy_arn: &str, tag_keys: &[String]) -> Result<(), IamError> {
    if tag_keys.is_empty() {
        return Err(ValidationError::builder().message("At least one tag key must be provided.").build().into());
    }
    for key in tag_keys {
        validate_tag_key(key)?;
    }

    let parts = parse_policy_arn(policy_arn)?;
    let managed_policy_id = lookup_managed_policy_id(tx, &parts, policy_arn).await?;

    for key in tag_keys {
        if let Err(e) = query(indoc! {"
                DELETE FROM iam.managed_policy_tags
                WHERE managed_policy_id = $1 AND key_lower = $2
            "})
        .bind(&managed_policy_id)
        .bind(key.to_ascii_lowercase())
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to delete managed policy tag: {e}");
            return Err(internal_failure().into());
        }
    }

    Ok(())
}
