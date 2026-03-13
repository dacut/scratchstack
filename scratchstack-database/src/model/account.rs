//! AWS account database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    serde::{Deserialize, Serialize},
};

#[cfg(feature = "load")]
use {
    crate::{Context, GetQueryPlaceholder, QueryPlaceholder},
    sqlx::{Connection, Encode, Error as SqlxError, Executor, IntoArguments, Type, query},
};

/// AWS account database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Account {
    /// 12-digit AWS account id.
    pub account_id: String,

    /// Email address associated with the account.
    pub email: Option<String>,

    /// Unique alias for the account.
    pub alias: Option<String>,

    /// Timestamp when the account was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(feature = "load")]
impl<C> crate::Loadable<C> for Account
where
    C: Connection,
    for<'a> &'a mut C: Executor<'a>,
    <C as Connection>::Database: GetQueryPlaceholder,
    for<'a, 'c> String: Encode<'a, <&'c mut C as Executor<'c>>::Database>,
    for<'c> String: Type<<&'c mut C as Executor<'c>>::Database>,
    for<'a, 'c> Option<String>: Encode<'a, <&'c mut C as Executor<'c>>::Database>,
    for<'c> Option<String>: Type<<&'c mut C as Executor<'c>>::Database>,
    for<'a, 'c> DateTime<Utc>: Encode<'a, <&'c mut C as Executor<'c>>::Database>,
    for<'c> DateTime<Utc>: Type<<&'c mut C as Executor<'c>>::Database>,
    for<'a, 'c> <<&'c mut C as Executor<'c>>::Database as sqlx::Database>::Arguments<'a>:
        IntoArguments<'a, <&'c mut C as Executor<'c>>::Database>,
{
    async fn load_into<'c>(
        &self,
        conn: &'c mut C,
        context: Context,
    ) -> Result<<<&'c mut C as Executor<'c>>::Database as sqlx::Database>::QueryResult, SqlxError> {
        let table_name = context.table_name("account");
        let mut qp = <<<C as Connection>::Database as GetQueryPlaceholder>::QueryPlaceholder as Default>::default();
        let ph1 = qp.next();
        let ph2 = qp.next();
        let ph3 = qp.next();
        let ph4 = qp.next();
        let sql =
            format!("INSERT INTO {table_name}(account_id,email,alias,created_at) VALUES({ph1},{ph2},{ph3},{ph4})");
        let q = query(&sql)
            .bind(self.account_id.clone())
            .bind(self.email.clone())
            .bind(self.alias.clone())
            .bind(self.created_at.clone());
        let result = q.bind(self.created_at.clone()).execute(conn).await?;
        Ok(result)
    }
}

#[cfg(feature = "schema")]
impl<C> crate::CreateSchema<C> for Account
where
    C: Connection,
    for<'c> &'c mut C: Executor<'c>,
    for<'a, 'c> <<&'c mut C as Executor<'c>>::Database as sqlx::Database>::Arguments<'a>:
        IntoArguments<'a, <&'c mut C as Executor<'c>>::Database>,
{
    /// Create the database schema for the model object.
    async fn create_schema<'c>(
        conn: &'c mut C,
        context: Context,
    ) -> Result<<<&'c mut C as Executor<'c>>::Database as sqlx::Database>::QueryResult, SqlxError> {
        let table_name = context.table_name("account");
        let sql = format!(
            r#"
            CREATE TABLE {table_name}(
                account_id CHAR(12) PRIMARY KEY,
                email VARCHAR(256),
                alias VARCHAR(63),
                created_at TEXT NOT NULL,
                CONSTRAINT uk_account_alias UNIQUE (alias)
            )
        "#
        );
        let result = query(&sql).execute(conn).await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    #[test_log::test(tokio::test)]
    #[cfg(all(feature = "schema", feature = "sqlite"))]
    async fn test_load_account() {
        use {
            crate::{Context, CreateSchema, Loadable, model::Account},
            serde_json::json,
            sqlx::{pool::Pool, sqlite::Sqlite},
        };

        let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        Account::create_schema(&mut *conn, Context::default()).await.unwrap();
        let accounts = json!([
            {
                "account_id": "123456789012",
                "email": "hello@example.com",
                "alias": "example1",
                "created_at": "2024-01-01T00:00:00Z"
            },
            {
                "account_id": "001122334455",
                "email": null,
                "alias": null,
                "created_at": "2024-02-01T00:00:00Z"
            }
        ]);
        for account in accounts.as_array().unwrap() {
            let account: Account = serde_json::from_value(account.clone()).unwrap();
            account.load_into(&mut *conn, Context::default()).await.unwrap();
        }
    }
}
