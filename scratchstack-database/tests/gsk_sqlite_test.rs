use sqlx::{Error as SqlxError, Pool, SqliteConnection, query, sqlite::Sqlite};

async fn create_schema(conn: &mut SqliteConnection) -> Result<(), SqlxError> {
    query(
        r#"
        CREATE TABLE account(
            account_id CHAR(12) PRIMARY KEY,
            email VARCHAR(256),
            alias VARCHAR(63),
            CONSTRAINT uk_account_alias UNIQUE (alias)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE managed_policy(
            managed_policy_id CHAR(16) PRIMARY KEY,
            account_id CHAR(12) NOT NULL,
            managed_policy_name_lower VARCHAR(128) NOT NULL,
            managed_policy_name_cased VARCHAR(128) NOT NULL,
            path VARCHAR(512) NOT NULL,
            created_at TEXT NOT NULL,
            default_version BIGINT,
            deprecated BOOLEAN NOT NULL,
            policy_type VARCHAR(32),
            CONSTRAINT fk_mp_acctid FOREIGN KEY (account_id) REFERENCES account(account_id),
            CONSTRAINT uk_mp_acctid_polname UNIQUE(account_id, managed_policy_name_lower)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE managed_policy_version(
            managed_policy_id CHAR(16) NOT NULL,
            managed_policy_version BIGINT NOT NULL,
            policy_document TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT pk_mpv PRIMARY KEY (managed_policy_id, managed_policy_version),
            CONSTRAINT fk_mpv_mp_id FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(r#"
        CREATE TABLE iam_user(
            user_id CHAR(16) PRIMARY KEY,
            account_id CHAR(12) NOT NULL,
            user_name_lower VARCHAR(64) NOT NULL,
            user_name_cased VARCHAR(64) NOT NULL,
            path VARCHAR(512) NOT NULL,
            permissons_boundary_managed_policy_id CHAR(17),
            created_at TEXT NOT NULL,
            CONSTRAINT uk_iu_acctid_uname UNIQUE(account_id, user_name_lower),
            CONSTRAINT fk_iu_acctid FOREIGN KEY (account_id) REFERENCES account(account_id),
            CONSTRAINT fk_iu_pbmp FOREIGN KEY (permissons_boundary_managed_policy_id) REFERENCES managed_policy(managed_policy_id)
        )
    "#).execute(&mut *conn).await?;

    query(
        r#"
        CREATE TABLE iam_user_attached_policy(
            user_id CHAR(16) PRIMARY KEY,
            managed_policy_id CHAR(16) NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_iuap_userid FOREIGN KEY (user_id) REFERENCES iam_user(user_id),
            CONSTRAINT fk_iuap_mp_id FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_user_inline_policy(
            user_id CHAR(16) NOT NULL,
            policy_name_lower VARCHAR(128) NOT NULL,
            policy_name_cased VARCHAR(128) NOT NULL,
            policy_document TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT pk_iuip PRIMARY KEY (user_id, policy_name_lower),
            CONSTRAINT fk_iuip_userid FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_user_login_profile(
            user_id CHAR(16) PRIMARY KEY,
            password_hash_algorithm VARCHAR(32) NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            password_reseet_required BOOLEAN NOT NULL,
            password_last_changed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_user_password_history(
            user_id CHAR(16) NOT NULL,
            password_hash_algorithm VARCHAR(32) NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_iuph_userid FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_user_credential(
            access_key_id CHAR(16) PRIMARY KEY,
            user_id CHAR(16) NOT NULL,
            secret_key VARCHAR(256) NOT NULL,
            enabled BOOLEAN NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_iuc_userid FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_group(
            group_id CHAR(16) PRIMARY KEY,
            account_id CHAR(12) NOT NULL,
            group_name_lower VARCHAR(64) NOT NULL,
            group_name_cased VARCHAR(64) NOT NULL,
            path VARCHAR(512) NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT uk_ig_acctid_gname UNIQUE(account_id, group_name_lower),
            CONSTRAINT fk_ig_acctid FOREIGN KEY (account_id) REFERENCES account(account_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_group_attached_policy(
            group_id CHAR(16),
            managed_policy_id CHAR(16) NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_igap_groupid FOREIGN KEY (group_id) REFERENCES iam_group(group_id),
            CONSTRAINT fk_igap_mp_id FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_group_inline_policy(
            group_id CHAR(16) NOT NULL,
            policy_name_lower VARCHAR(128) NOT NULL,
            policy_name_cased VARCHAR(128) NOT NULL,
            policy_document TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT pk_igip PRIMARY KEY (group_id, policy_name_lower),
            CONSTRAINT fk_igip_groupid FOREIGN KEY (group_id) REFERENCES iam_group(group_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_group_member(
            group_id CHAR(16) NOT NULL,
            user_id CHAR(16) NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT pk_igm PRIMARY KEY (group_id, user_id),
            CONSTRAINT fk_igm_groupid FOREIGN KEY (group_id) REFERENCES iam_group(group_id),
            CONSTRAINT fk_igm_userid FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(r#"
        CREATE TABLE iam_role(
            role_id CHAR(16) PRIMARY KEY,
            account_id CHAR(12) NOT NULL,
            role_name_lower VARCHAR(64) NOT NULL,
            role_name_cased VARCHAR(64) NOT NULL,
            path VARCHAR(512) NOT NULL,
            permissons_boundary_managed_policy_id CHAR(16),
            description VARCHAR(1000),
            assume_role_policy_document TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT uk_ir_acctid_rname UNIQUE(account_id, role_name_lower),
            CONSTRAINT fk_ir_acctid FOREIGN KEY (account_id) REFERENCES account(account_id),
            CONSTRAINT fk_ir_pbmp FOREIGN KEY (permissons_boundary_managed_policy_id) REFERENCES managed_policy(managed_policy_id)
        )
    "#).execute(&mut *conn).await?;

    query(
        r#"
        CREATE TABLE iam_role_attached_policy(
            role_id CHAR(16) NOT NULL,
            managed_policy_id CHAR(16) NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT pk_irap PRIMARY KEY (role_id, managed_policy_id),
            CONSTRAINT fk_irap_roleid FOREIGN KEY (role_id) REFERENCES iam_role(role_id),
            CONSTRAINT fk_irap_mp_id FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_role_inline_policy(
            role_id CHAR(16) NOT NULL,
            policy_name_lower VARCHAR(128) NOT NULL,
            policy_name_cased VARCHAR(128) NOT NULL,
            policy_document TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT pk_irip PRIMARY KEY (role_id, policy_name_lower),
            CONSTRAINT fk_irip_roleid FOREIGN KEY (role_id) REFERENCES iam_role(role_id)
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    query(
        r#"
        CREATE TABLE iam_role_token_key(
            role_token_key_id CHAR(16) PRIMARY KEY,
            encryption_algorithm VARCHAR(32) NOT NULL,
            encryption_key BLOB NOT NULL,
            valid_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

async fn create_test_data(conn: &mut SqliteConnection) -> Result<(), SqlxError> {
    todo!()
}

#[tokio::test]
async fn gsk_sqlite_test() {
    let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    create_schema(&mut *conn).await.unwrap();
}
