//! TagPolicy database operation
use {
    crate::{
        RequestExecutor, internal_failure,
        policy::{lookup_managed_policy_id, parse_policy_arn},
        tag::{validate_tag_key, validate_tag_keys_unique, validate_tag_value},
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
///
/// # Tag key case sensitivity
///
/// This deliberately departs from IAM. AWS folds tag keys to lower case on users and roles only,
/// and treats them as case sensitive everywhere else, customer managed policies included:
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html#case-sensitivity>
///
/// Here they are folded on policies too, so `Dept` and `dept` are one tag.
///
/// The reason is that AWS's own combination is a trap. Condition key names *are* case insensitive
/// -- `aws:ResourceTag/Dept` and `aws:ResourceTag/dept` are the same key -- so a policy carrying
/// two spellings can be reached by a condition naming either, matching a value its author did not
/// intend. AWS documents this outcome as "unexpected condition failures" and offers only a naming
/// convention as the remedy. Folding the key removes the trap instead of documenting it: the two
/// spellings cannot both exist, so no condition can be surprised by which one it found.
///
/// The cost is that a policy tagged `Dept` here cannot also be tagged `dept`, and a request
/// asking for the second overwrites the first. That is a narrower behaviour than IAM's, not a
/// wider one, so a caller written against IAM cannot do anything here that IAM would refuse.
///
/// Change this only with the condition-key half in view: making keys case sensitive without also
/// making `aws:ResourceTag/${TagKey}` lookups case sensitive reintroduces exactly the ambiguity
/// above, and the lookup is case insensitive by AWS's own rule.
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

    // Two tags with the same key ask for two values for one tag. The upsert below would take the
    // last one and report success, which is not what the caller asked for, so the request is
    // rejected as tag_user and tag_role reject it. Keys are compared case-insensitively, which is
    // how this implementation stores them; see the note on tag key case sensitivity above.
    validate_tag_keys_unique(tags.iter().map(|tag| tag.key.as_str()), request_id)?;

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
