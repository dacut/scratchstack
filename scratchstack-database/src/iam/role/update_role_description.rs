//! UpdateRoleDescription database operation
use {
    super::get_role,
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{validate_account_id, validate_role_name},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{UpdateRoleDescriptionInternalRequest, UpdateRoleDescriptionResponse},
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for UpdateRoleDescriptionInternalRequest {
    type Response = UpdateRoleDescriptionResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_role_description(tx, &self.account_id, &self.role_name, &self.description).await
    }
}

/// Replace the description on a role and return the updated role.
pub async fn update_role_description(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    description: &str,
) -> Result<UpdateRoleDescriptionResponse, IamError> {
    validate_account_id(account_id)?;
    let resolved_account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let result = match query(indoc! {"
            UPDATE iam.roles
            SET description = $3
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(resolved_account_id)
    .bind(role_name.to_lowercase())
    .bind(description)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to update role description in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The role with name {role_name} cannot be found."))
            .build()
            .into());
    }

    let role = get_role(tx, account_id, role_name).await?.role;

    UpdateRoleDescriptionResponse::builder().role(Some(role)).build().map_err(|e| {
        log::error!("Failed to build UpdateRoleDescriptionResponse: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into()
    })
}
