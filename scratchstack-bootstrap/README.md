# scratchstack-bootstrap

The `ssbs` command — Scratchstack's database bootstrap utility.

`ssbs` talks to the Scratchstack IAM database **directly**, over PostgreSQL, rather than through
the IAM service. That is the whole point of it: a fresh database has no accounts, no users, and no
access keys, so there are no credentials to sign a request with and no way in through the API. This
tool creates the first ones.

It is also useful afterwards as an administrative back door — repairing a database whose only
administrator was deleted, rotating session-token encryption keys, or inspecting state without
standing up a service. Because it bypasses the service, it also bypasses **every authorization
check** the service would apply. Treat access to it as equivalent to full administrative access to
the database it points at.

## Bootstrapping a new database

The order matters for the first two steps: migrations create the schema, and the partition must be
set before anything else in the database will work.

```sh
# 1. Create or update the schema.
ssbs migrate

# 2. Set the partition. Required before any other feature of the database works.
ssbs set-current-partition --partition aws

# 3. Create an account. Omit --account-id to have one chosen at random.
ssbs create-account --email admin@example.com --account-alias example

# 4. Create a user in it.
ssbs create-user --account-id 123456789012 --user-name admin

# 5. Issue credentials. The secret access key is shown once and never again.
ssbs create-access-key --account-id 123456789012 --user-name admin
```

From there the user needs permissions — `ssbs create-policy` and `ssbs attach-user-policy`, or an
inline `ssbs put-user-policy` — before it can do anything through the IAM service itself.

`ssbs migrate --downgrade-to <VERSION>` reverses migrations instead of applying them.

## Connecting to the database

Connection options are global and go **before** the subcommand. They follow `psql`'s environment
variables, so an existing PostgreSQL environment mostly works unchanged:

| Option | Environment | Default | Notes |
|---|---|---|---|
| `--database` | `PGDATABASE` | `scratchstack_iam` | |
| `--host` | `PGHOST` | `/tmp` | A directory on Unix connects over a Unix socket instead of TCP |
| `--port` | `PGPORT` | `7154` | Not PostgreSQL's usual 5432 |
| `--username` | `PGUSER` | current system user | |
| `-w`, `--no-password` | | | Never prompt |
| `--force-password-prompt` | | | Always prompt; overrides `--no-password` |

By default `ssbs` behaves like `psql`: it uses `PGPASSWORD` if set, otherwise tries without a
password, and prompts only if the server issues an auth challenge it cannot answer.

```sh
ssbs --host db.example.com --port 5432 --username scratchstack list-accounts
```

## Output

Commands that return data write pretty-printed JSON to stdout; commands that only act write
nothing. Errors go to stderr in the service's error format, and the exit status is 1.

Set `RUST_LOG` for detail — internal failures log their cause rather than returning it, exactly as
they do in the service.

## Subcommands

`ssbs --help` lists all 79; `ssbs <command> --help` documents one. They mirror the IAM and STS APIs
they are named after, so an operation behaves as its AWS counterpart does unless its help says
otherwise.

### Database

| Command | Description |
|---|---|
| `migrate` | Apply migrations, or reverse them with `--downgrade-to` |
| `get-current-partition` | Show the database's partition |
| `set-current-partition` | Set it — required before anything else works |

### Accounts

| Command | Description |
|---|---|
| `create-account` | Create an account; the id is random unless `--account-id` is given |
| `create-account-alias` | Set the alias, replacing any existing one |
| `list-accounts` | List accounts |
| `list-account-aliases` | List an account's aliases (always zero or one) |

### Users, groups, and roles

| Command | Description |
|---|---|
| `create-user`, `get-user`, `update-user`, `delete-user`, `list-users` | User lifecycle |
| `create-group`, `get-group`, `update-group`, `delete-group`, `list-groups` | Group lifecycle |
| `create-role`, `get-role`, `update-role`, `delete-role`, `list-roles` | Role lifecycle |
| `update-role-description` | Replace a role's description alone |
| `add-user-to-group`, `remove-user-from-group`, `list-groups-for-user` | Group membership |
| `tag-user`, `untag-user`, `list-user-tags` | User tags |
| `tag-role`, `untag-role`, `list-role-tags` | Role tags |
| `put-user-permissions-boundary`, `delete-user-permissions-boundary` | User permissions boundary |
| `put-role-permissions-boundary`, `delete-role-permissions-boundary` | Role permissions boundary |

Deletes are refused while something still depends on the entity: a role with attached or inline
policies, for instance, has to be emptied first.

### Policies attached to entities

These follow one shape for each of `user`, `group`, and `role` — twenty-one commands in total:

| Pattern | Description |
|---|---|
| `put-<entity>-policy`, `get-<entity>-policy`, `delete-<entity>-policy`, `list-<entity>-policies` | Inline policies |
| `attach-<entity>-policy`, `detach-<entity>-policy`, `list-attached-<entity>-policies` | Managed policy attachments |

### Managed policies

| Command | Description |
|---|---|
| `create-policy`, `get-policy`, `delete-policy`, `list-policies` | Policy lifecycle; `list-policies` can include AWS-managed policies |
| `create-policy-version`, `get-policy-version`, `delete-policy-version`, `list-policy-versions` | Versions |
| `set-default-policy-version` | Choose the version in effect |
| `tag-policy`, `untag-policy`, `list-policy-tags` | Policy tags |
| `list-entities-for-policy` | Who a policy is attached to, or uses it as a permissions boundary |

`delete-policy` requires the policy to have no attachments, no permissions-boundary usages, and no
non-default versions left.

### Credentials

| Command | Description |
|---|---|
| `create-access-key` | Issue an access key; the secret is returned once and not recoverable afterwards |
| `update-access-key` | Change status between `Active` and `Inactive` |
| `delete-access-key`, `list-access-keys` | Remove or list a user's keys |
| `assume-role` | Assume a role and return temporary credentials, as STS does |

### Session token encryption keys

The keys the services use to encrypt and decrypt temporary-credential session tokens. Each has an
issue window and a longer accept window, so a key can stop being used for new tokens while still
decrypting outstanding ones.

| Command | Description |
|---|---|
| `create-session-token-encryption-key` | Create one (`AES256-GCM`), with `--issue-valid-from`, `--issue-expires-at`, `--accept-expires-at` |
| `update-session-token-encryption-key` | Adjust those windows |
| `get-session-token-encryption-key`, `list-session-token-encryption-keys` | Inspect them |

## Related

The schema, migrations, and the typed API these commands run against live in
[`scratchstack-iam-database`](../scratchstack-iam-database). The services that serve the same
operations over HTTP are [`scratchstack-service-iam`](../scratchstack-service-iam) and
[`scratchstack-service-sts`](../scratchstack-service-sts).
