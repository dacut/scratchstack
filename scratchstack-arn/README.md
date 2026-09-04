# scratchstack-arn

A parser and representation for Amazon Resource Names (ARNs).

An ARN uniquely identifies a resource in AWS, in the form
`arn:partition:service:region:account-id:resource`. The `Arn` type here represents a
*fully-qualified* resource: **no wildcards**. Wildcard-bearing resource *patterns* — the strings
that appear in the `Resource` element of an IAM policy — are a different thing, and belong to
[`scratchstack-aspen`](../scratchstack-aspen).

## Usage

Parse one:

```rust
use scratchstack_arn::Arn;
use std::str::FromStr;

let arn = Arn::from_str("arn:aws:iam::123456789012:role/engineering/Deployer").unwrap();
assert_eq!(arn.partition(), "aws");
assert_eq!(arn.service(), "iam");
assert_eq!(arn.region(), "");                    // IAM is global
assert_eq!(arn.account_id(), "123456789012");
assert_eq!(arn.resource(), "role/engineering/Deployer");
```

Or assemble one component by component. `partition` and `service` are required; the rest default
to the empty string:

```rust
use scratchstack_arn::Arn;

let arn = Arn::builder()
    .partition("aws")
    .service("s3")
    .resource("examplebucket/hello.txt")
    .build()
    .unwrap();
assert_eq!(arn.to_string(), "arn:aws:s3:::examplebucket/hello.txt");
```

An `Arn` is immutable and holds the formatted string in a single allocation, recording where each
component begins. The accessors return slices into it, so reading a component costs nothing and
`to_string()` never has to reassemble anything.

## Validation

`Arn::new` and `Arn::from_str` validate the partition, service, region, and account ID — the
components whose grammar AWS actually fixes. A region or account ID that is empty is accepted, as
in the IAM ARN above.

The **resource is not validated**, because its shape is service-specific: it may contain colons
(everything after the fifth colon of an ARN is resource), and it may be empty. `Arn::new_unchecked`
skips validation entirely, at the cost of producing values that may not round-trip through their own
`Display` output.

Failures are reported as `ArnError`, which is `#[non_exhaustive]`.

The per-component validators are public in the `utils` module — `validate_partition`,
`validate_service`, `validate_region`, `validate_account_id` — for callers that need to check a
component before they have a whole ARN to build.

## Features

`iam` *(enabled by default)* adds `IamResourceArn`, which splits an IAM ARN's resource into its
type, path, and name, along with the IAM name and path validators (`validate_iam_path`,
`validate_iam_path_prefix`, `validate_iam_resource_name`).

```rust
use scratchstack_arn::IamResourceArn;
use std::str::FromStr;

let role = IamResourceArn::from_str("arn:aws:iam::123456789012:role/engineering/admins/Deployer").unwrap();
assert_eq!(role.resource_type(), "role");
assert_eq!(role.resource_path(), "/engineering/admins/");
assert_eq!(role.resource_name(), "Deployer");

// A resource with no path segments has a path of "/", matching how AWS reports one.
let plain = IamResourceArn::from_str("arn:aws:iam::123456789012:role/Deployer").unwrap();
assert_eq!(plain.resource_path(), "/");
```

The path always both begins and ends with `/` and is never empty; the name is never empty either.

## Documentation

Published to [docs.rs](https://docs.rs/scratchstack-arn/).
