# scratchstack-aws-principal

Actor principals for AWS and AWS-like services.

Principals come in two flavors, and this crate implements one of them.

* **Policy principals** appear in the `Principal` element of an IAM policy. They have a source
  (`AWS`, `Federated`, or `Service`) and a value that may contain wildcards. They live in
  [`scratchstack-aspen`](../scratchstack-aspen).
* **Actor principals** are what a service authenticates a request *as*. They are exact — no
  wildcards, ever — and they are what this crate provides.

## Usage

```rust
use scratchstack_aws_principal::{Principal, PrincipalSource, User};
use std::str::FromStr;

let user = User::from_str("arn:aws:iam::123456789012:user/Sales/Bob").unwrap();
let principal: Principal = user.into();

assert_eq!(principal.source(), PrincipalSource::Aws);
assert!(principal.has_arn());
```

Each identity type also has a builder, which validates its components:

```rust
use scratchstack_aws_principal::User;

let user = User::builder()
    .partition("aws")
    .account_id("123456789012")
    .path("/Sales/")
    .user_name("Bob")
    .build()
    .unwrap();
```

## Principal types

`Principal` is an enum over five identities:

| Variant | Source | Has an ARN |
|---|---|---|
| `AssumedRole` | `AWS` | yes |
| `RootUser` | `AWS` | yes |
| `User` | `AWS` | yes |
| `FederatedUser` | `Federated` | yes |
| `Service` | `Service` | no |

`Principal::source` reports which of the three `PrincipalSource` values an identity maps to, and
`Principal::has_arn` distinguishes service principals — which are named `ec2.amazonaws.com`, not by
ARN — from the rest.

## Session data

An identity is not the whole story. IAM
[policy variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
reference details that are *not* part of the ARN, so those are carried alongside the principal in a
`SessionData` map rather than inside it.

The motivating case is `aws:userid`. IAM users have a
[unique ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids)
separate from their ARN: delete `/Sales/Bob` and re-create it, and the two users share an ARN but
have different unique IDs. A policy written against `aws:userid` distinguishes them; one written
against the ARN cannot.

`SessionData` behaves like a string-keyed map, and `SessionValue` covers the types a condition key
can hold — strings, integers, booleans, timestamps, IP addresses, binary, null, and multivalued
keys such as `aws:TagKeys` and `aws:CalledVia` that policies match with the `ForAllValues:` and
`ForAnyValue:` set operators.

```rust
use scratchstack_aws_principal::{SessionData, SessionValue};

let mut session_data = SessionData::new();
session_data.insert("aws:userid", SessionValue::from("AIDAQXZEAEXAMPLEUSER"));
session_data.insert("aws:MultiFactorAuthPresent", SessionValue::from(true));

assert!(session_data.contains_key("aws:userid"));
```

## S3 canonical users were removed in 0.12

S3 has effectively deprecated both canonical users and ACLs in favor of ARNs and IAM policies, so
the canonical-user principal type is gone.

Supporting it forced an oddity into the API: `Principal` and `PrincipalIdentity` had to be separate
concepts, because S3 principals — and only S3 principals — could carry multiple identities. No
client ever used that, and it cost complexity in this crate and in every crate built on it. A
`Principal` is now exactly one identity.

## Features

`serde` *(off by default)* derives `Serialize` and `Deserialize` for the principal and session
types.

## Documentation

Published to [docs.rs](https://docs.rs/scratchstack-aws-principal/).
