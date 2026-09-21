//! Tests for the Cloud database model and related functionality.
//!
//! The body of each test lives in a submodule under [tests/cloud/](cloud/); this file orchestrates
//! a single end-to-end run because the test database is stateful between calls, in the same way
//! [tests/iam.rs](iam.rs) does for the IAM model.
#![cfg(feature = "utils")]
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

use {
    scratchstack_central_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::{PgPool, raw_sql},
};

#[path = "cloud/account_quota.rs"]
mod account_quota;

#[path = "cloud/quota.rs"]
mod quota;

#[path = "cloud/quota_unit.rs"]
mod quota_unit;

#[path = "cloud/region.rs"]
mod region;

#[path = "cloud/service.rs"]
mod service;

const CLOUD_DATA: &str = include_str!("cloud.sql");

/// Test the features of the cloud database model.
///
/// As with the IAM suite, this is one test rather than many: the database is stateful between
/// calls, and each subtest is an async function awaited in order so that no single poll frame has
/// to hold every sqlx future at once.
#[test_log::test(tokio::test)]
async fn test_cloud_database() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(CLOUD_DATA).execute(&mut *c).await.expect("Failed to load cloud data into database");
    drop(c);

    subtest_account_quota_constraints(&pool).await;
    subtest_create_quota_definition(&pool).await;
    subtest_create_quota_unit(&pool).await;
    subtest_create_region(&pool).await;
    subtest_create_service(&pool).await;
    subtest_quota_definition_failures(&pool).await;
    subtest_service_failures(&pool).await;
}

async fn subtest_account_quota_constraints(pool: &PgPool) {
    account_quota::test_global_quota_stores_a_null_region(pool).await;
    account_quota::test_global_quota_is_unique_per_account(pool).await;
    account_quota::test_regional_quotas_are_per_region(pool).await;
    account_quota::test_regional_quota_requires_the_service_in_that_region(pool).await;
}

async fn subtest_create_quota_definition(pool: &PgPool) {
    quota::test_create_quota_definition(pool).await;
    quota::test_create_quota_definition_idempotent(pool).await;
}

async fn subtest_create_quota_unit(pool: &PgPool) {
    quota_unit::test_create_quota_unit(pool).await;
    quota_unit::test_create_quota_unit_idempotent(pool).await;
    quota_unit::test_create_quota_unit_already_seeded(pool).await;
}

async fn subtest_create_region(pool: &PgPool) {
    region::test_create_region(pool).await;
    region::test_create_region_duplicate(pool).await;
}

async fn subtest_create_service(pool: &PgPool) {
    service::test_create_service(pool).await;
    service::test_create_service_with_description(pool).await;
    service::test_create_service_idempotent(pool).await;
}

async fn subtest_quota_definition_failures(pool: &PgPool) {
    quota::test_create_quota_definition_unknown_service(pool).await;
    quota::test_create_quota_definition_unknown_unit(pool).await;
    quota::test_create_quota_definition_contradictory_bounds(pool).await;
    quota::test_create_quota_definition_conflicting_scope(pool).await;
    quota::test_create_quota_definition_conflicting_unit(pool).await;
    quota::test_create_quota_definition_conflicting_description(pool).await;
    quota::test_create_quota_definition_conflicting_bounds(pool).await;
    quota::test_create_quota_definition_conflict_names_every_field(pool).await;
}

async fn subtest_service_failures(pool: &PgPool) {
    service::test_create_service_conflicting_dns_name(pool).await;
    service::test_create_service_conflicting_description(pool).await;
    service::test_create_service_duplicate_dns_name(pool).await;
}
