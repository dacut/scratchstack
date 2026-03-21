//! AWS IAM password hash algorithm database model
use {
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgConnection, FromRow},
};

/// AWS IAM password hash algorithm database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct PasswordHashAlgorithm {
    /// Password hash algorithm identifier.
    pub password_hash_algorithm_id: String,

    /// Algorithm name.
    pub algorithm_name: String,

    /// Algorithm parameters.
    pub parameters: Option<String>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for PasswordHashAlgorithm {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT password_hash_algorithm_id, algorithm_name, parameters::text AS parameters
            FROM iam.password_hash_algorithms
            ORDER BY password_hash_algorithm_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for PasswordHashAlgorithm {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.password_hash_algorithms(password_hash_algorithm_id, algorithm_name, parameters)
            VALUES($1, $2, $3::jsonb)"})
        .bind(self.password_hash_algorithm_id.clone())
        .bind(self.algorithm_name.clone())
        .bind(self.parameters.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
