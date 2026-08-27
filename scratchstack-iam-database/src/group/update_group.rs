//! UpdateGroup database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        group::{is_group_name_unique_violation, validate_group_name},
        internal_failure,
        path::validate_path,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::UpdateGroupInternalRequest,
        types::error::{EntityAlreadyExistsException, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for UpdateGroupInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        update_group(
            tx,
            &self.account_id,
            &self.group_name,
            self.new_group_name.as_deref(),
            self.new_path.as_deref(),
            request_id,
        )
        .await
    }
}

/// Update a group on the database.
pub async fn update_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    new_group_name: Option<&str>,
    new_path: Option<&str>,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;
    let group_name_lower = group_name.to_lowercase();

    let (new_group_name_cased, new_group_name_lower) = if let Some(new_group_name) = new_group_name {
        validate_group_name(new_group_name, request_id)?;
        (Some(new_group_name), Some(new_group_name.to_lowercase()))
    } else {
        (None, None)
    };

    if let Some(new_path) = new_path {
        validate_path(new_path, request_id)?;
    }

    let result = match query(indoc! {"
        UPDATE iam.groups
        SET group_name_lower = COALESCE($3, group_name_lower),
            group_name_cased = COALESCE($4, group_name_cased),
            path = COALESCE($5, path)
        WHERE account_id = $1 AND group_name_lower = $2
    "})
    .bind(account_id)
    .bind(&group_name_lower)
    .bind(new_group_name_lower)
    .bind(new_group_name_cased)
    .bind(new_path)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            if is_group_name_unique_violation(&e) {
                // The rename asked for a name another group in the account already carries. The
                // new name is what collided, so that is the name the caller is told about.
                let message = format!("Group with name {} already exists.", new_group_name.unwrap_or(group_name));
                return Err(EntityAlreadyExistsException::builder()
                    .message(message)
                    .request_id(request_id)
                    .build()
                    .into());
            }
            log::error!("Failed to update group in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .request_id(request_id)
            .build()
            .into())
    } else {
        Ok(())
    }
}
