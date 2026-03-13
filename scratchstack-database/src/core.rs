//! Database loading and dumping utilities.
use {
    sqlx::{Connection, Error as SqlxError, Executor},
    std::future::Future,
};

/// The load or dump context, which allows for the table name to be prefixed or suffixed.
#[cfg(any(feature = "dump", feature = "load"))]
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// Prefix for table names; if no prefix is desired, this should be an empty string.
    pub prefix: String,

    /// Optional suffix for table names; if no suffix is desired, this be an empty string.
    pub suffix: String,
}

impl Context {
    pub(crate) fn table_name(&self, base_name: impl AsRef<str>) -> String {
        format!("{}{}{}", self.prefix, base_name.as_ref(), self.suffix)
    }
}

/// Trait that allows a model object to be dumped from a database.
#[cfg(feature = "load")]
pub trait Dumpable<D>: Sized {
    /// Dump a table containing the specified objects from the database.
    fn dump_from(database: &mut D, context: Context) -> impl Future<Output = Result<Vec<Self>, SqlxError>>;
}

/// Trait that allows a model object to be loaded into a database.
#[cfg(feature = "load")]
pub trait Loadable<C>
where
    C: Connection,
    for<'c> &'c mut C: Executor<'c>,
{
    /// Load the model object into the database.
    ///
    /// On success, returns the number of records inserted into the database.
    fn load_into<'c>(
        &self,
        conn: &'c mut C,
        context: Context,
    ) -> impl Future<Output = Result<<<&'c mut C as Executor<'c>>::Database as sqlx::Database>::QueryResult, SqlxError>>;
}

/// Trait that allows a model object type to create its corresponding database schema.
#[cfg(feature = "schema")]
pub trait CreateSchema<C>
where
    C: Connection,
    for<'c> &'c mut C: Executor<'c>,
{
    /// Create the database schema for the model object.
    fn create_schema<'c>(
        conn: &'c mut C,
        context: Context,
    ) -> impl Future<Output = Result<<<&'c mut C as Executor<'c>>::Database as sqlx::Database>::QueryResult, SqlxError>>;
}

/// A trait for types that can produce SQL query placeholder.
pub(crate) trait QueryPlaceholder: Default {
    /// Return the next placeholder.
    fn next(&mut self) -> String;
}

/// A trait for sqlx databases that defines the query placeholder type.
pub(crate) trait GetQueryPlaceholder {
    type QueryPlaceholder: QueryPlaceholder;
}

/// A Postgres-style query placeholder that produces placeholders in the form `${1}`, `${2}`, etc.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DollarParamPlaceholder {
    prev_index: usize,
}

impl QueryPlaceholder for DollarParamPlaceholder {
    fn next(&mut self) -> String {
        self.prev_index += 1;
        format!("${{{}}}", self.prev_index)
    }
}

/// A MySQL and SQLite-style query placeholder that produces `?` placeholders.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct QmPlaceholder;

impl QueryPlaceholder for QmPlaceholder {
    fn next(&mut self) -> String {
        "?".to_string()
    }
}

#[cfg(feature = "mysql")]
impl GetQueryPlaceholder for sqlx::mysql::MySql {
    type QueryPlaceholder = QmPlaceholder;
}

#[cfg(feature = "postgres")]
impl GetQueryPlaceholder for sqlx::postgres::Postgres {
    type QueryPlaceholder = DollarParamPlaceholder;
}

#[cfg(feature = "sqlite")]
impl GetQueryPlaceholder for sqlx::sqlite::Sqlite {
    type QueryPlaceholder = QmPlaceholder;
}
