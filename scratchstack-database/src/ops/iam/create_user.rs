//! CreateUser database level operation.

use {
    crate::{
        model::iam::{IamId, IamResourceType},
        ops::{RequestExecutor, iam::get_current_partition::get_current_partition},
    },
    anyhow::bail,
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_shapes::iam::{
        AttachedPermissionsBoundary, CreateUserRequestInternal, CreateUserResponseInternal, PermissionsBoundaryType,
        User,
    },
    sqlx::{Row as _, query},
};

impl RequestExecutor for CreateUserRequestInternal {
    type Response = CreateUserResponseInternal;

    async fn execute(&self, tx: &mut sqlx::postgres::PgTransaction<'_>) -> anyhow::Result<Self::Response> {
        let partition = get_current_partition(tx).await?;
        let Some(partition) = partition.partition_id() else {
            bail!("No partition found in database");
        };

        let permissions_boundary_id = if let Some(permissions_boundary) = self.permissions_boundary() {
            let resource = permissions_boundary.resource();
            let account_id = match self.account_id() {
                "aws" => "000000000000",
                account_id => account_id,
            };
            let policy_path_and_name = &resource[6..];
            let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
            let policy_path = &policy_path_and_name[..name_start];
            let policy_name = policy_path_and_name[name_start..].to_ascii_lowercase();
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
                bail!("Permissions boundary policy does not exist");
            }
            if results.len() > 1 {
                bail!(
                    "Multiple permissions boundary policies found with the same name and path; this is a database integrity error"
                );
            }

            let mp_id: &str = results[0].try_get(0)?;
            Some(mp_id.to_string())
        } else {
            None
        };

        let account_id = match self.account_id() {
            "aws" => "000000000000",
            account_id => account_id,
        };
        let user_id = IamId::new(IamResourceType::User, self.account_id().parse().unwrap()).to_string();

        let result = query(indoc! {"
            INSERT INTO iam.users(
                account_id, user_id, path, user_name_lower, user_name_cased,
                permissions_boundary_managed_policy_id)
            VALUES($1, $2, $3, $4, $5, $6)
            RETURNING created_at
        "})
        .bind(account_id)
        .bind(user_id[4..].to_string())
        .bind(self.path())
        .bind(self.user_name().to_ascii_lowercase())
        .bind(self.user_name())
        .bind(permissions_boundary_id)
        .fetch_one(tx.as_mut())
        .await?;
        let created_at: chrono::DateTime<chrono::Utc> = result.try_get(0)?;

        for tag in self.tags() {
            let key_cased = tag.key();
            let key_lower = key_cased.to_ascii_lowercase();
            let value = tag.value();

            query(indoc! {"
                INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
            "})
            .bind(user_id[4..].to_string())
            .bind(key_lower)
            .bind(key_cased)
            .bind(value)
            .execute(tx.as_mut())
            .await?;
        }

        let arn = Arn::builder()
            .partition(partition)
            .service("iam")
            .account_id(self.account_id())
            .resource(format!("user/{}", self.user_name()))
            .build()?;

        let permissions_boundary = if let Some(pb) = self.permissions_boundary() {
            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(pb.clone())
                    .permissions_boundary_type(PermissionsBoundaryType::Policy)
                    .build()?,
            )
        } else {
            None
        };

        let user = User::builder()
            .arn(arn)
            .create_date(created_at)
            .path(self.path().to_string())
            .user_id(user_id)
            .user_name(self.user_name().to_string())
            .permissions_boundary(permissions_boundary)
            .build()?;

        Ok(CreateUserResponseInternal::builder().user(user).account_id(self.account_id().to_string()).build()?)
    }
}
