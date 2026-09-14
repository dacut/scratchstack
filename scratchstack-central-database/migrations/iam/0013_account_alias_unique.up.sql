-- Enforce alias uniqueness across accounts. AWS treats account aliases as globally unique;
-- attempting to set an alias that is already in use must fail with EntityAlreadyExists.
--
-- PostgreSQL treats NULLs in unique indexes as distinct by default, so accounts without an alias
-- continue to coexist freely.
CREATE UNIQUE INDEX uk_iam_accounts_alias ON iam.accounts(alias);
