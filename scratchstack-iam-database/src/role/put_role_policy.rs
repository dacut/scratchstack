//! PutRolePolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, policy::validate_policy_name,
        role::validate_role_name,
    },
    indoc::indoc,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::PutRolePolicyInternalRequest,
        types::error::{MalformedPolicyDocumentException, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr,
};

impl RequestExecutor for PutRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        put_role_policy(tx, &self.account_id, &self.role_name, &self.policy_name, &self.policy_document, request_id)
            .await
    }
}

/// Add or replace an inline policy on a role. The policy document must parse as a valid Aspen
/// policy; semantic validity of principals/resources is not enforced.
pub async fn put_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_name: &str,
    policy_document: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name, request_id)?;
    validate_policy_name(policy_name, request_id)?;

    if let Err(e) = AspenPolicy::from_str(policy_document) {
        let message = format!("Invalid policy document: {e}");
        return Err(MalformedPolicyDocumentException::builder().message(message).request_id(request_id).build().into());
    }

    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    if let Err(e) = query(indoc! {"
            INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document)
            VALUES($1, $2, $3, $4)
            ON CONFLICT (role_id, policy_name_lower)
            DO UPDATE SET policy_name_cased = EXCLUDED.policy_name_cased,
                          policy_document = EXCLUDED.policy_document
        "})
    .bind(&role_id)
    .bind(policy_name.to_ascii_lowercase())
    .bind(policy_name)
    .bind(policy_document)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to insert/update role inline policy in database: {e}");
        return Err(internal_failure(request_id).into());
    }

    Ok(())
}
