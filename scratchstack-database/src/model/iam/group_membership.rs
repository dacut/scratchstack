//! AWS IAM group membership database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM group membership database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GroupMember {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: String,

    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// Timestamp when the user was added to the group.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for GroupMember {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let sql = indoc! {"
            INSERT INTO iam.group_members(group_id, user_id)
            VALUES($1, $2)
        "};
        let result = sqlx::query(sql)
            .bind(self.group_id.clone())
            .bind(self.user_id.clone())
            .execute(conn)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}
