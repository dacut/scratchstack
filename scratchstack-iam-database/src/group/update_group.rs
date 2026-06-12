//! UpdateGroup database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, group::validate_group_name, internal_failure,
        path::validate_path,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::UpdateGroupInternalRequest, types::error::NoSuchEntityException,
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for UpdateGroupInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_group(tx, &self.account_id, &self.group_name, self.new_group_name.as_deref(), self.new_path.as_deref())
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
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;
    let group_name_lower = group_name.to_lowercase();

    let (new_group_name_cased, new_group_name_lower) = if let Some(new_group_name) = new_group_name {
        validate_group_name(new_group_name)?;
        (Some(new_group_name), Some(new_group_name.to_lowercase()))
    } else {
        (None, None)
    };

    if let Some(new_path) = new_path {
        validate_path(new_path)?;
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
            log::error!("Failed to update group in database: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}
