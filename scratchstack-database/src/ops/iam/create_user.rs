//! CreateUser database level operation.

use {
    crate::{
        model::iam::{ACCOUNT_ID_REGEX, IamId, IamResourceType, PATH_REGEX, USER_NAME_REGEX},
        ops::{RequestExecutor, iam::get_current_partition::get_current_partition},
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_shapes::iam::Tag,
    serde::{Deserialize, Serialize},
    sqlx::{Row as _, query},
};

/// Parameters to create a new user on the Scratchstack IAM database.
///
/// This differs from the standard `CreateUserRequest` in `scratchstack-shapes` in that it includes
/// the `account_id` field, which is required to specify which account to create the user in.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct CreateUserRequest {
    /// The account id to create the user in. The account must already exist.
    #[cfg_attr(feature = "clap", arg(long))]
    pub account_id: String,

    /// The path to create the user at. This is optional and defaults to a slash (`/`).
    ///
    /// Paths must start and end with a slash, and can contain any ASCII characters from 33 to 126.
    /// Paths must not contain consecutive slashes, and must be at most 512 characters long.
    #[cfg_attr(feature = "clap", arg(long, default_value = "/"))]
    pub path: String,

    /// The user name to create. This is required and must be unique within the account
    /// (case-insensitive).
    #[cfg_attr(feature = "clap", arg(long))]
    pub user_name: String,

    /// The permissions boundary to set for the user. This is optional and can be used to set a
    /// managed policy as the permissions boundary for the user. The permissions boundary must be a
    /// valid IAM policy ARN.
    #[cfg_attr(feature = "clap", arg(long))]
    pub permissions_boundary: Option<String>,

    /// The tags to attach to the user. This is optional and can be used to attach any number of
    /// key-value pairs as tags to the user.
    #[cfg_attr(feature = "clap", arg(long))]
    pub tags: Vec<Tag>,
}

pub type CreateUserResponse = scratchstack_shapes::iam::CreateUserResponse;
pub type User = scratchstack_shapes::iam::User;

impl RequestExecutor for CreateUserRequest {
    type Response = CreateUserResponse;

    async fn execute(&self, tx: &mut sqlx::postgres::PgTransaction<'_>) -> anyhow::Result<Self::Response> {
        let partition = get_current_partition(tx).await?;
        let Some(partition) = partition.partition_id else {
            anyhow::bail!("No partition found in database");
        };

        if !ACCOUNT_ID_REGEX.is_match(&self.account_id) {
            anyhow::bail!("Account ID must be a 12-digit number");
        }

        let permissions_boundary_id = if let Some(permissions_boundary) = &self.permissions_boundary {
            // arn:<partition>:iam::<account-id>:policy/<policy-name>
            let Ok(arn) = permissions_boundary.parse::<Arn>() else {
                anyhow::bail!("Permissions boundary must be a valid ARN");
            };

            let account_id = arn.account_id();
            let resource = arn.resource();
            if arn.service() != "iam" || !resource.starts_with("policy/") {
                anyhow::bail!(
                    "Permissions boundary must be an IAM policy ARN with the format arn:<partition>:iam::<account-id>:policy/<policy-name>"
                );
            }

            let account_id = if account_id == self.account_id {
                account_id
            } else if account_id != "aws" {
                "000000000000"
            } else {
                anyhow::bail!(
                    "Permissions boundary ARN must have the same account id as the user being created or the 'aws' account id"
                );
            };

            let policy_path_and_name = &resource[6..];
            let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
            let policy_path = &policy_path_and_name[..name_start];
            let policy_name = policy_path_and_name[name_start..].to_ascii_lowercase();

            if !PATH_REGEX.is_match(policy_path) {
                anyhow::bail!(
                    "Permissions boundary policy path must start and end with a slash and can contain any ASCII characters from 33 to 126. Paths must not contain consecutive slashes and must be at most 512 characters long."
                );
            }

            let results = query(indoc! {"
                SELECT managed_policy_id
                FROM iam.managed_policies
                WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            "})
            .bind(account_id)
            .bind(policy_path)
            .bind(policy_name)
            .fetch_all(tx.as_mut())
            .await?;
            if results.is_empty() {
                anyhow::bail!("Permissions boundary policy does not exist");
            }
            if results.len() > 1 {
                anyhow::bail!(
                    "Multiple permissions boundary policies found with the same name and path; this is a database integrity error"
                );
            }

            let mp_id: &str = results[0].try_get(1)?;
            Some(mp_id.to_string())
        } else {
            None
        };

        if !PATH_REGEX.is_match(&self.path) {
            anyhow::bail!(
                "Path must start and end with a slash and can contain any ASCII characters from 33 to 126. Paths must not contain consecutive slashes and must be at most 512 characters long."
            );
        }

        if !USER_NAME_REGEX.is_match(&self.user_name) {
            anyhow::bail!("User name contains invalid characters");
        }

        let user_id = IamId::new(IamResourceType::User, self.account_id.parse().unwrap()).to_string();

        let result = query(indoc! {"
            INSERT INTO iam.users(
                account_id, user_id, path, user_name_lower, user_name_cased,
                permissions_boundary_managed_policy_id)
            VALUES($1, $2, $3, $4, $5, $6)
            RETURNING created_at
        "})
        .bind(&self.account_id)
        .bind(user_id[4..].to_string())
        .bind(&self.path)
        .bind(self.user_name.to_ascii_lowercase())
        .bind(&self.user_name)
        .bind(permissions_boundary_id)
        .fetch_one(tx.as_mut())
        .await?;
        let created_at: chrono::DateTime<chrono::Utc> = result.try_get(0)?;

        let user = User {
            user_id,
            arn: format!("arn:{partition}:iam::{}:user{}{}", self.account_id, self.path, self.user_name),
            path: self.path.clone(),
            user_name: self.user_name.clone(),
            tags: self.tags.clone(),
            create_date: created_at.to_rfc3339(),
            permissions_boundary: None,
            password_last_used: None,
        };

        Ok(CreateUserResponse {
            user,
        })
    }
}
