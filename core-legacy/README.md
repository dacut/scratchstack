# scratchstack-core
Amazon Resource Name (ARN) and Principal utilities for Scratchstack.

![GitHub Actions](https://github.com/dacut/scratchstack-core/workflows/Rust/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/dacut/scratchstack-core/badge.svg?branch=main)](https://coveralls.io/github/dacut/scratchstack-core?branch=main)

## Amazon Resource Name (ARN)

ARNs come in two "flavors":
* An actual resource, such as an EC2 instance (`arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef`).
* A policy resource statement, which in certain instances may contain wildcards (`arn:aws:ec?:us-west-*:*:instance/*`).

The `Arn` struct is used actual resources, while the `ArnPattern` struct is used to match against `Arn` structs.

## Principal

A principal is an entity performing an action. Note that not all principals have ARNs. However, all principals have a
"principal source": the domain that owns the identity of the principals.

The principals in the AWS ecosystem are:

* Assumed Role (source: `AWS`): An IAM role assumed by an actor with a session name. Has an ARN in the form
  `arn:_partition_:sts::_account-id_:assumed-role/_role-name_/_session-name_`.
* S3 Canonical User (source: `CanonicalUser`): An S3 user performing an action on an S3 object or bucket. This is a
  legacy identifier; IAM identifers are preferred now. Does not have an ARN.
* Federated User (source: `Federated`): A user identified from a federation identity source. Has an ARN in the form
  `arn:_partition_:sts::_account-id_:federated-user/_user-name_`.
* Root User (source: `AWS`): The root user for an AWS account. Does not have an ARN. Note that the ARN in the form
  `arn:_partition_:iam::_account-id_:root` is an alias for _any entity_ in the account, not the root user.
* Service (source: `Service`): An AWS(-ish) service represented as a domain name. The domain name may or may not have the region
  embedded (e.g. `codebuild.us-west-2.amazonaws.com` vs `edgelambda.amazonaws.com`). Does not have an ARN.
* IAM User (source: `AWS`): An IAM user. Has an ARN in the form `arn:_partition_:iam::_account-id_:user/\[_path_/\]_user-name_`.

Entities that exist but are not principals:
* EC2 Instance: EC2 instances perform actions based on the assumed role tied to the instance profile. The instance
  itself has an ARN in the form `arn:_partition_:ec2:_region_:_account-id_:instance/_instance-id_`.
* IAM Group: This is used to add policies common to a set of users. Users always act on their own behalf. Has an arn
  in the form `arn:_partition_:iam::_account-id_:group/\[_path_/]_group-name_`.
