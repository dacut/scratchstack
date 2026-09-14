//! UpdateAssumeRolePolicy database operation
use {
    crate::{RequestExecutor, account::validate_account_id, constants::*, internal_failure, role::validate_role_name},
    indoc::indoc,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::UpdateAssumeRolePolicyInternalRequest,
        types::error::{MalformedPolicyDocumentException, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
    std::str::FromStr,
};

impl RequestExecutor for UpdateAssumeRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        update_assume_role_policy(tx, &self.account_id, &self.role_name, &self.policy_document, request_id).await
    }
}

/// Replace the trust policy on a role.
///
/// The document must parse as a valid Aspen policy, as an inline policy must; what it says about
/// principals and conditions is not otherwise checked. It replaces the existing trust policy
/// outright rather than merging into it, so a document omitting a principal that could previously
/// assume the role takes that access away.
pub async fn update_assume_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_document: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name, request_id)?;

    if let Err(e) = AspenPolicy::from_str(policy_document) {
        let message = format!("Invalid policy document: {e}");
        return Err(MalformedPolicyDocumentException::builder().message(message).request_id(request_id).build().into());
    }

    let result = match query(indoc! {"
            UPDATE iam.roles
            SET assume_role_policy_document = $3
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .bind(policy_document)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to update role trust policy in database: {e}").into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The role with name {role_name} cannot be found."))
            .request_id(request_id)
            .build()
            .into());
    }

    Ok(())
}
