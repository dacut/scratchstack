//! PutGroupPolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, group::validate_group_name, internal_failure,
        policy::validate_policy_name,
    },
    indoc::indoc,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::PutGroupPolicyInternalRequest,
        types::error::{MalformedPolicyDocumentException, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr,
};

impl RequestExecutor for PutGroupPolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        put_group_policy(tx, &self.account_id, &self.group_name, &self.policy_name, &self.policy_document, request_id)
            .await
    }
}

/// Add or replace an inline policy on a group. The policy document must parse as a valid Aspen
/// policy; semantic validity of principals/resources is not enforced.
pub async fn put_group_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    policy_name: &str,
    policy_document: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;
    validate_policy_name(policy_name, request_id)?;

    if let Err(e) = AspenPolicy::from_str(policy_document) {
        let message = format!("Invalid policy document: {e}");
        return Err(MalformedPolicyDocumentException::builder().message(message).request_id(request_id).build().into());
    }

    let group_id: String = match query(indoc! {"
            SELECT group_id
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The group with name {group_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to look up group in database: {e}").into());
        }
    };

    if let Err(e) = query(indoc! {"
            INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document)
            VALUES($1, $2, $3, $4)
            ON CONFLICT (group_id, policy_name_lower)
            DO UPDATE SET policy_name_cased = EXCLUDED.policy_name_cased,
                          policy_document = EXCLUDED.policy_document
        "})
    .bind(&group_id)
    .bind(policy_name.to_ascii_lowercase())
    .bind(policy_name)
    .bind(policy_document)
    .execute(tx.as_mut())
    .await
    {
        return Err(
            internal_failure!(request_id; "Failed to insert/update group inline policy in database: {e}").into()
        );
    }

    Ok(())
}
