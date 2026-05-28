//! CreatePolicy database operation
use {
    crate::{
        IamId, RequestExecutor,
        constants::iam::*,
        iam::{
            get_current_partition_or_fail, internal_failure, policy_arn_resource, validate_account_id, validate_path,
            validate_policy_name, validate_tag_key, validate_tag_value,
        },
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreatePolicyInternalRequest, CreatePolicyResponse},
        types::{Policy, Tag, error::MalformedPolicyDocumentException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr as _,
};

impl RequestExecutor for CreatePolicyInternalRequest {
    type Response = CreatePolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_policy(
            tx,
            &self.account_id,
            &self.policy_name,
            &self.policy_document,
            self.description.as_deref(),
            self.path.as_deref(),
            &self.tags,
        )
        .await
    }
}

/// Create a new managed policy on the database.
pub async fn create_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    policy_name: &str,
    policy_document: &str,
    description: Option<&str>,
    path: Option<&str>,
    tags: &[Tag],
) -> Result<CreatePolicyResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path)?;
    validate_policy_name(policy_name)?;

    // Validate the policy document is valid Aspen JSON.
    if let Err(e) = AspenPolicy::from_str(policy_document) {
        let message = format!("Invalid policy document: {e}");
        return Err(MalformedPolicyDocumentException::builder().message(message).build().into());
    }

    // TODO: make sure we don't exceed the maximum number of tags per policy.
    // Default limit is 50 but may vary by account.
    for tag in tags {
        validate_tag_key(&tag.key)?;
        validate_tag_value(&tag.value)?;
    }

    // Generate a new managed policy id.
    let policy_id = IamId::new(IamResourceType::ManagedPolicy, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx).await?;

    let result = match query(indoc! {"
            INSERT INTO iam.managed_policies(
                managed_policy_id, account_id, managed_policy_name_lower, managed_policy_name_cased,
                path, default_version, deprecated, latest_version, description)
            VALUES($1, $2, $3, $4, $5, 1, false, 1, $6)
            RETURNING created_at
        "})
    .bind(&policy_id[4..])
    .bind(account_id)
    .bind(policy_name.to_ascii_lowercase())
    .bind(policy_name)
    .bind(path)
    .bind(description)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to insert managed policy into database: {e}");
            return Err(internal_failure().into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            log::error!("Failed to get created_at from database row: {e}");
            return Err(internal_failure().into());
        }
    };

    // Insert the initial policy version.
    if let Err(e) = query(indoc! {"
            INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document)
            VALUES($1, 1, $2)
        "})
    .bind(&policy_id[4..])
    .bind(policy_document)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to insert managed policy version into database: {e}");
        return Err(internal_failure().into());
    }

    // Insert tags.
    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
            "})
        .bind(&policy_id[4..])
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert managed policy tag into database: {e}");
            return Err(internal_failure().into());
        }
    }

    let arn = match Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(policy_arn_resource(path, policy_name))
        .build()
    {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("Failed to construct ARN for new managed policy: {e}");
            return Err(internal_failure().into());
        }
    };

    let policy = Policy::builder()
        .arn(Some(arn.to_string()))
        .attachment_count(Some(0))
        .create_date(Some(created_at))
        .default_version_id(Some("v1".to_string()))
        .description(description.map(|d| d.to_string()))
        .is_attachable(Some(true))
        .path(Some(path.to_string()))
        .permissions_boundary_usage_count(Some(0))
        .policy_id(Some(policy_id))
        .policy_name(Some(policy_name.to_string()))
        .tags(tags.to_vec())
        .build()
        .map_err(|e| {
            log::error!("Failed to construct policy object for new managed policy: {e}");
            internal_failure()
        })?;

    Ok(CreatePolicyResponse {
        policy: Some(policy),
    })
}
