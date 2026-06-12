//! Account test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateAccountAliasInternalRequest, CreateAccountRequest, ListAccountAliasesInternalRequest,
            ListAccountsRequest,
        },
        types::{ListAccountsFilter, ListAccountsFilterName},
    },
};

pub async fn test_create_account_specific_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000001".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with specific ID");
    tx.commit().await.expect("Failed to commit transaction");

    let account = resp.account;
    assert_eq!(account.account_id, "100000000001");
    assert_eq!(account.organization_id, None);
    assert_eq!(account.email, None);
    assert_eq!(account.account_alias, None);
}

pub async fn test_create_account_with_email_and_alias(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000002".to_string()),
        email: Some("admin@example.com".to_string()),
        account_alias: Some("example-corp".to_string()),
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with email and alias");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.account.account_id, "100000000002");
    assert_eq!(resp.account.email.as_deref(), Some("admin@example.com"));
    assert_eq!(resp.account.account_alias.as_deref(), Some("example-corp"));
}

pub async fn test_create_account_random_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: None,
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with random ID");
    tx.commit().await.expect("Failed to commit transaction");

    // The returned account ID must be a 12-digit string.
    assert_eq!(resp.account.account_id.len(), 12, "Random account ID must be 12 digits");
    assert!(resp.account.account_id.chars().all(|c| c.is_ascii_digit()), "Random account ID must be all digits");

    // Verify the account appears in ListAccounts.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec![resp.account.account_id.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(list_resp.accounts.len(), 1);
    assert_eq!(list_resp.accounts[0].account_id, resp.account.account_id);
}

pub async fn test_create_account_duplicate_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000001".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate account ID must fail");
}

pub async fn test_create_account_invalid_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("12345".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with an invalid ID must fail");
}

pub async fn test_create_account_invalid_alias_leading_dash(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000003".to_string()),
        email: None,
        account_alias: Some("-bad-alias".to_string()),
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with an invalid alias must fail");
}

pub async fn test_create_account_alias_too_short(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000003".to_string()),
        email: None,
        account_alias: Some("ab".to_string()),
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with a too-short alias must fail");
}

pub async fn test_create_account_organization_id_unsupported(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: Some("o-12345".to_string()),
        account_id: Some("100000000003".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account in an organization must fail (unsupported)");
}

pub async fn test_list_accounts_explicit(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec!["100000000001".to_string(), "100000000002".to_string()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(list_resp.accounts.len(), 2);
    assert_eq!(list_resp.accounts[0].account_id, "100000000001");
    assert_eq!(list_resp.accounts[1].account_id, "100000000002");
    assert_eq!(list_resp.accounts[1].email.as_deref(), Some("admin@example.com"));
    assert_eq!(list_resp.accounts[1].account_alias.as_deref(), Some("example-corp"));
    assert_eq!(list_resp.marker, None);
}

const BASE_ACCOUNT_ID: u64 = 876_543_210_000;
const N_BULK_ACCOUNTS: u64 = 350;

pub async fn test_create_350_accounts(pool: &sqlx::PgPool) {
    // Create 350 accounts with sequential IDs, emails, and aliases.
    for i in 0..N_BULK_ACCOUNTS {
        let account_id = format!("{:012}", BASE_ACCOUNT_ID + i);
        let email = format!("{account_id}@example.com");
        let alias = format!("account-{account_id}");

        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = CreateAccountRequest {
            organization_id: None,
            account_id: Some(account_id.clone()),
            email: Some(email.clone()),
            account_alias: Some(alias.clone()),
        }
        .execute(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("Failed to create account {account_id}: {e}"));
        tx.commit().await.expect("Failed to commit transaction");

        assert_eq!(resp.account.account_id, account_id);
        assert_eq!(resp.account.email.as_deref(), Some(email.as_str()));
        assert_eq!(resp.account.account_alias.as_deref(), Some(alias.as_str()));
    }
}

pub async fn test_list_350_accounts(pool: &sqlx::PgPool) {
    // Paginate through all accounts, collecting every account in the bulk range.
    let mut all_bulk_accounts = Vec::new();
    let mut marker: Option<String> = None;
    let mut page_count = 0u32;

    loop {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = ListAccountsRequest {
            filters: vec![],
            max_items: Some(100),
            marker: marker.clone(),
        }
        .execute(&mut tx)
        .await
        .expect("Failed to list accounts");
        tx.rollback().await.expect("Failed to rollback transaction");

        page_count += 1;
        for account in resp.accounts {
            let id: u64 = account.account_id.parse().unwrap_or(0);
            if id >= BASE_ACCOUNT_ID && id < BASE_ACCOUNT_ID + N_BULK_ACCOUNTS {
                all_bulk_accounts.push(account);
            }
        }

        marker = resp.marker;
        if marker.is_none() {
            break;
        }
    }

    assert!(page_count > 1, "Expected multiple pages, got {page_count}");
    assert_eq!(
        all_bulk_accounts.len(),
        N_BULK_ACCOUNTS as usize,
        "Expected {N_BULK_ACCOUNTS} bulk accounts across all pages, found {}",
        all_bulk_accounts.len(),
    );

    // Spot-check first, middle, and last accounts.
    for offset in [0, N_BULK_ACCOUNTS / 2, N_BULK_ACCOUNTS - 1] {
        let expected_id = format!("{:012}", BASE_ACCOUNT_ID + offset);
        let expected_email = format!("{expected_id}@example.com");
        let expected_alias = format!("account-{expected_id}");

        let account = all_bulk_accounts
            .iter()
            .find(|a| a.account_id == expected_id)
            .unwrap_or_else(|| panic!("Account {expected_id} not found in paginated results"));

        assert_eq!(account.email.as_deref(), Some(expected_email.as_str()), "Email mismatch for {expected_id}");
        assert_eq!(account.account_alias.as_deref(), Some(expected_alias.as_str()), "Alias mismatch for {expected_id}");
    }
}

/// Return the account ID, email, and alias strings for a bulk account at the given offset.
fn bulk_account(offset: u64) -> (String, String, String) {
    let id = format!("{:012}", BASE_ACCOUNT_ID + offset);
    let email = format!("{id}@example.com");
    let alias = format!("account-{id}");
    (id, email, alias)
}

pub async fn test_list_accounts_filter_single_account_id(pool: &sqlx::PgPool) {
    let (id, expected_email, expected_alias) = bulk_account(42);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec![id.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by single account ID");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for id {id}");
    assert_eq!(resp.accounts[0].account_id, id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(expected_email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.marker, None);
}

pub async fn test_list_accounts_filter_multiple_account_ids(pool: &sqlx::PgPool) {
    let offsets = [10u64, 100, 200, 300];
    let ids: Vec<String> = offsets.iter().map(|&o| bulk_account(o).0).collect();

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: ids.clone(),
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by multiple account IDs");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), offsets.len(), "Expected {} accounts", offsets.len());
    // Results are ordered by account_id; our offsets are already ascending.
    for (account, &offset) in resp.accounts.iter().zip(offsets.iter()) {
        let (expected_id, expected_email, expected_alias) = bulk_account(offset);
        assert_eq!(account.account_id, expected_id);
        assert_eq!(account.email.as_deref(), Some(expected_email.as_str()));
        assert_eq!(account.account_alias.as_deref(), Some(expected_alias.as_str()));
    }
    assert_eq!(resp.marker, None);
}

pub async fn test_list_accounts_filter_by_email(pool: &sqlx::PgPool) {
    let (expected_id, email, expected_alias) = bulk_account(77);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::Email,
            values: vec![email.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by email");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for email {email}");
    assert_eq!(resp.accounts[0].account_id, expected_id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.marker, None);
}

pub async fn test_list_accounts_filter_by_alias(pool: &sqlx::PgPool) {
    let (expected_id, expected_email, alias) = bulk_account(155);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountAlias,
            values: vec![alias.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by alias");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for alias {alias}");
    assert_eq!(resp.accounts[0].account_id, expected_id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(expected_email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(alias.as_str()));
    assert_eq!(resp.marker, None);
}

pub async fn test_list_accounts_filter_combined_match(pool: &sqlx::PgPool) {
    // AccountId AND Email filters both match the same account — should return it.
    let (id, email, expected_alias) = bulk_account(250);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![
            ListAccountsFilter {
                name: ListAccountsFilterName::AccountId,
                values: vec![id.clone()],
            },
            ListAccountsFilter {
                name: ListAccountsFilterName::Email,
                values: vec![email.clone()],
            },
        ],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with combined matching filters");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account when AccountId and Email both match");
    assert_eq!(resp.accounts[0].account_id, id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.marker, None);
}

pub async fn test_list_accounts_filter_combined_no_match(pool: &sqlx::PgPool) {
    // AccountId and Email filters refer to *different* accounts — the AND should return nothing.
    let (id_a, _, _) = bulk_account(10);
    let (_, email_b, _) = bulk_account(20);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![
            ListAccountsFilter {
                name: ListAccountsFilterName::AccountId,
                values: vec![id_a.clone()],
            },
            ListAccountsFilter {
                name: ListAccountsFilterName::Email,
                values: vec![email_b.clone()],
            },
        ],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with combined non-matching filters");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(
        resp.accounts.len(),
        0,
        "Expected no accounts when AccountId ({id_a}) and Email ({email_b}) refer to different accounts",
    );
    assert_eq!(resp.marker, None);
}

pub async fn test_list_accounts_filter_nonexistent(pool: &sqlx::PgPool) {
    // 999999999999 is never created by any test, so this must return no results.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec!["999999999999".to_string()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with nonexistent account ID filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 0, "Expected no accounts for a nonexistent account ID");
    assert_eq!(resp.marker, None);
}

// -- ListAccountAliases / CreateAccountAlias tests ---------------------------

/// ListAccountAliases on an account that has an alias returns the single alias.
pub async fn test_list_account_aliases_with_alias(pool: &sqlx::PgPool) {
    // 100000000002 was created with alias "example-corp" in test_create_account_with_email_and_alias.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountAliasesInternalRequest::builder()
        .account_id("100000000002".to_string())
        .build()
        .expect("Failed to build ListAccountAliasesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list account aliases");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.account_aliases, vec!["example-corp".to_string()]);
    assert_eq!(resp.is_truncated, Some(false));
    assert_eq!(resp.marker, None);
}

/// ListAccountAliases on an account without an alias returns an empty list.
pub async fn test_list_account_aliases_without_alias(pool: &sqlx::PgPool) {
    // 100000000001 was created without an alias in test_create_account_specific_id.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountAliasesInternalRequest::builder()
        .account_id("100000000001".to_string())
        .build()
        .expect("Failed to build ListAccountAliasesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list account aliases for un-aliased account");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.account_aliases.is_empty(), "Expected no aliases, got {:?}", resp.account_aliases);
    assert_eq!(resp.is_truncated, Some(false));
    assert_eq!(resp.marker, None);
}

/// ListAccountAliases on a nonexistent account must fail with NoSuchEntity.
pub async fn test_list_account_aliases_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListAccountAliasesInternalRequest::builder()
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build ListAccountAliasesInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("ListAccountAliases on a nonexistent account must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a ListAccountAliases request with an invalid account id must fail before touching
/// the database. The Smithy builder rejects anything that isn't 12 digits.
pub fn test_list_account_aliases_invalid_account_id() {
    let result = ListAccountAliasesInternalRequest::builder().account_id("not-a-number".to_string()).build();
    assert!(result.is_err(), "Building a request with an invalid account id must fail");
}

/// CreateAccountAlias on an account that has no alias sets it; ListAccountAliases reflects the
/// new alias.
pub async fn test_create_account_alias_simple(pool: &sqlx::PgPool) {
    // 100000000001 currently has no alias.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateAccountAliasInternalRequest::builder()
        .account_id("100000000001".to_string())
        .account_alias("my-new-alias".to_string())
        .build()
        .expect("Failed to build CreateAccountAliasInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create account alias");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountAliasesInternalRequest::builder()
        .account_id("100000000001".to_string())
        .build()
        .expect("Failed to build ListAccountAliasesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list account aliases after create");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.account_aliases, vec!["my-new-alias".to_string()]);
}

/// CreateAccountAlias on an account that already has an alias replaces it; AWS accounts only
/// support a single alias.
pub async fn test_create_account_alias_replaces(pool: &sqlx::PgPool) {
    // 100000000002 currently has alias "example-corp".
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateAccountAliasInternalRequest::builder()
        .account_id("100000000002".to_string())
        .account_alias("replacement-alias".to_string())
        .build()
        .expect("Failed to build CreateAccountAliasInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to replace account alias");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountAliasesInternalRequest::builder()
        .account_id("100000000002".to_string())
        .build()
        .expect("Failed to build ListAccountAliasesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list account aliases after replace");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.account_aliases, vec!["replacement-alias".to_string()]);
}

/// CreateAccountAlias on a nonexistent account must fail with NoSuchEntity.
pub async fn test_create_account_alias_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = CreateAccountAliasInternalRequest::builder()
        .account_id("999999999999".to_string())
        .account_alias("orphan-alias".to_string())
        .build()
        .expect("Failed to build CreateAccountAliasInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("CreateAccountAlias on a nonexistent account must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// CreateAccountAlias with an alias that violates the format rules must fail with
/// ValidationError. The Smithy regex rejects uppercase, so this is caught by the builder.
pub fn test_create_account_alias_invalid_alias() {
    let result = CreateAccountAliasInternalRequest::builder()
        .account_id("100000000001".to_string())
        .account_alias("BadAlias".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid alias must fail");
}

/// Building a CreateAccountAlias request with an invalid account id must fail before touching
/// the database.
pub fn test_create_account_alias_invalid_account_id() {
    let result = CreateAccountAliasInternalRequest::builder()
        .account_id("12345".to_string())
        .account_alias("valid-alias".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid account id must fail");
}
