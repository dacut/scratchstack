//! Tests for the IAM database model and related functionality.
#![cfg(feature = "iam")]

mod util;

use {
    postgresql_commands::Settings as _,
    pretty_assertions::{assert_eq, assert_ne},
    scratchstack_database::{Loadable, connection_url, model::iam},
    sqlx::{
        ConnectOptions,
        postgres::{PgConnectOptions, PgPoolOptions},
        query,
    },
    std::time::Duration,
    util::{BOOTSTRAP_USER, TempDatabase, generate_password},
};

/// Test all of the features of the database.
///
/// We do this instead of more granular testing because the database we're running against is typically stateful.
#[test_log::test(tokio::test)]
async fn test_database() {
    let iam_data: iam::Database =
        serde_json::from_str(TEST_DATA).expect("Failed to deserialize test data into IAM database model");

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    assert_ne!(database.settings().get_port(), 0, "Database port should be non-zero");
    database.setup().await.expect("Failed to set up PostgreSQL database");
    database.start().await.expect("Failed to start PostgreSQL database");
    let settings = database.settings();

    let mut bootstrap = PgConnectOptions::new()
        .host(&settings.host)
        .host("127.0.0.1")
        .port(settings.port)
        .username(BOOTSTRAP_USER)
        .password(&database.bootstrap_password)
        .connect()
        .await
        .expect("Failed to connect to PostgreSQL database with ConnectOptions");
    let password = generate_password(32);

    query(&format!("CREATE ROLE scratchstack NOSUPERUSER CREATEDB NOCREATEROLE LOGIN PASSWORD '{password}'"))
        .execute(&mut bootstrap)
        .await
        .expect("Failed to create role in PostgreSQL database");
    query("CREATE DATABASE iam OWNER scratchstack")
        .execute(&mut bootstrap)
        .await
        .expect("Failed to create database in PostgreSQL database");
    drop(bootstrap);

    let url =
        connection_url(Some("scratchstack"), Some(&password), Some("127.0.0.1"), Some(settings.port), Some("iam"));

    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("Failed to connect to PostgreSQL database");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    iam::MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    let rows_affected = iam_data.load_into(&mut *c).await.expect("Failed to load IAM data into database");
    eprintln!("Loaded {rows_affected} rows of IAM data into database");

    let iam_dump = iam::Database::dump_from(&mut *c).await.expect("Failed to dump IAM data from database");
    assert_ne!(iam_data, iam_dump, "Dumped IAM data should not be equal to original IAM data due to created_at fields");
    let iam_dump2 =
        iam::Database::dump_from(&mut *c).await.expect("Failed to dump IAM data from database a second time");
    assert_eq!(iam_dump, iam_dump2, "Dumped IAM data should be equal across multiple dumps");

    iam::MIGRATOR.undo(&mut *c, 0).await.expect("Failed to undo database migrations");
}

const TEST_DATA: &str = include_str!("iam_database.json");
