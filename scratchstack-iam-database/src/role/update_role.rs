//! UpdateRole database operation
use {
    crate::{RequestExecutor, account::validate_account_id, constants::*, internal_failure, role::validate_role_name},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{UpdateRoleInternalRequest, UpdateRoleResponse},
        types::error::{NoSuchEntityException, ValidationError},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for UpdateRoleInternalRequest {
    type Response = UpdateRoleResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        update_role(
            tx,
            &self.account_id,
            &self.role_name,
            self.description.as_deref(),
            self.max_session_duration,
            request_id,
        )
        .await
    }
}

/// Update the description and/or max session duration of a role. Either or both of the optional
/// fields may be left unset, in which case the corresponding column on the role is unchanged.
pub async fn update_role(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    description: Option<&str>,
    max_session_duration: Option<i32>,
    request_id: RequestId,
) -> Result<UpdateRoleResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name, request_id)?;

    if let Some(max_session_duration) = max_session_duration
        && (max_session_duration < 3600 || max_session_duration > 43200)
    {
        let message = "Maximum session duration must be between 3600 and 43200 seconds.".to_string();
        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
    }

    if description.is_some() || max_session_duration.is_some() {
        let result = match query(indoc! {"
                UPDATE iam.roles
                SET description = COALESCE($3, description),
                    max_session_duration = COALESCE($4, max_session_duration)
                WHERE account_id = $1 AND role_name_lower = $2
            "})
        .bind(account_id)
        .bind(role_name.to_lowercase())
        .bind(description)
        .bind(max_session_duration)
        .execute(tx.as_mut())
        .await
        {
            Ok(result) => result,
            Err(e) => {
                return Err(internal_failure!(request_id; "Failed to update role in database: {e}").into());
            }
        };

        if result.rows_affected() == 0 {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
    } else {
        let result = query(indoc! {"
                SELECT 1
                FROM iam.roles
                WHERE account_id = $1 AND role_name_lower = $2
            "})
        .bind(account_id)
        .bind(role_name.to_lowercase())
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|e| internal_failure!(request_id; "Failed to query role in database: {e}"))?;

        if result.is_none() {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
    }

    UpdateRoleResponse::builder()
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to build UpdateRoleResponse: {e}").into())
}
