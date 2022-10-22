use crate::{AspenError, Context, Decision, Policy};

/// The source of a policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PolicySource {
    /// An inline policy directly attached to an IAM entity (user, role).
    EntityInline {
        /// The ARN of the entity.
        entity_arn: String,

        /// The IAM ID of the entity.
        entity_id: String,

        /// The name of the policy.
        policy_name: String,
    },

    /// A managed policy that is attached to an IAM entity (user, role).
    EntityAttachedPolicy {
        /// The ARN of the of the policy.
        policy_arn: String,

        /// The IAM ID of the policy.
        policy_id: String,

        /// The version of the policy used.
        version: String,
    },

    /// An inline policy directly attached to an IAM group that an IAM user ia a member of.
    GroupInline {
        /// The ARN of the IAM group.
        group_arn: String,

        /// The IAM ID of the group.
        group_id: String,

        /// The name of the policy.
        policy_name: String,
    },

    /// A managed policy that is attached to an IAM group that an IAM user is a member of.
    GroupAttachedPolicy {
        /// The ARN of the of IAM group.
        group_arn: String,

        /// The IAM ID of the group.
        group_id: String,

        /// The ARN of the of the policy.
        policy_arn: String,

        /// The IAM ID of the policy.
        policy_id: String,

        /// The version of the policy used.
        version: String,
    },

    /// A policy attached to a resource being accessed.
    Resource {
        /// The ARN of the resource being accessed.
        resource_arn: String,

        /// The name of the policy, if any.
        policy_name: Option<String>,
    },

    /// A permissions boundary attached to an IAM entity (user, role).
    PermissionBoundary {
        /// The ARN of the the policy used as a permissions boundary.
        policy_arn: String,

        /// The IAM ID of the policy used as a permissions boundary.
        policy_id: String,

        /// The version of the policy used.
        version: String,
    },

    /// An service control policy attached to an account or organizational unit.
    OrgServiceControl {
        /// The ARN of the the policy used as a service control policy.
        policy_arn: String,

        /// The name of the policy used as a service control policy.
        policy_name: String,

        /// The ARN of the account or organizational unit that the policy is attached to.
        applied_arn: String,
    },

    /// A policy embedded in an assumed role session.
    Session,
}

impl PolicySource {
    /// Indicates whether the policy is being used permissions boundary.
    ///
    /// Permissions boundaries are used to limit the permissions in effect. Allow effects in a permissions boundary
    /// do not grant permissions, but must be combined with an allow effect in a non-permissions boundary policy to
    /// be effective. Absence of an allow effect in a permissions boundary is the same as a deny effect.
    #[inline]
    pub fn is_boundary(&self) -> bool {
        matches!(
            self,
            PolicySource::PermissionBoundary { .. } | PolicySource::OrgServiceControl { .. } | PolicySource::Session
        )
    }

    /// Create a new [PolicySource::EntityInline] object.
    pub fn new_entity_inline<S1, S2, S3>(entity_arn: S1, entity_id: S2, policy_name: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self::EntityInline {
            entity_arn: entity_arn.into(),
            entity_id: entity_id.into(),
            policy_name: policy_name.into(),
        }
    }

    /// Create a new [PolicySource::EntityAttachedPolicy] object.
    pub fn new_entity_attached_policy<S1, S2, S3>(policy_arn: S1, policy_id: S2, version: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self::EntityAttachedPolicy {
            policy_arn: policy_arn.into(),
            policy_id: policy_id.into(),
            version: version.into(),
        }
    }

    /// Create a new [PolicySource::GroupInline] object.
    pub fn new_group_inline<S1, S2, S3>(group_arn: S1, group_id: S2, policy_name: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self::GroupInline {
            group_arn: group_arn.into(),
            group_id: group_id.into(),
            policy_name: policy_name.into(),
        }
    }

    /// Create a new [PolicySource::GroupAttachedPolicy] object.
    pub fn new_group_attached_policy<S1, S2, S3, S4, S5>(
        group_arn: S1,
        group_id: S2,
        policy_arn: S3,
        policy_id: S4,
        version: S5,
    ) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Self::GroupAttachedPolicy {
            group_arn: group_arn.into(),
            group_id: group_id.into(),
            policy_arn: policy_arn.into(),
            policy_id: policy_id.into(),
            version: version.into(),
        }
    }

    /// Create a new [PolicySource::Resource] object.
    pub fn new_resource<S1, S2>(resource_arn: S1, policy_name: Option<S2>) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self::Resource {
            resource_arn: resource_arn.into(),
            policy_name: policy_name.map(|s| s.into()),
        }
    }

    /// Create a new [PolicySource::PermissionBoundary] object.
    pub fn new_permission_boundary<S1, S2, S3>(policy_arn: S1, policy_id: S2, version: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self::PermissionBoundary {
            policy_arn: policy_arn.into(),
            policy_id: policy_id.into(),
            version: version.into(),
        }
    }

    /// Create a new [PolicySource::OrgServiceControl] object.
    pub fn new_org_service_control<S1, S2, S3>(policy_arn: S1, policy_name: S2, applied_arn: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self::OrgServiceControl {
            policy_arn: policy_arn.into(),
            policy_name: policy_name.into(),
            applied_arn: applied_arn.into(),
        }
    }

    /// Create a new [PolicySource::Session] object.
    pub fn new_session() -> Self {
        Self::Session
    }
}

/// A set of policies being evaluated to determine the permissions in effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySet {
    policies: Vec<(PolicySource, Policy)>,
}

impl PolicySet {
    /// Create a new, empty policy set.
    pub fn new() -> Self {
        Self {
            policies: vec![],
        }
    }

    /// Add a policy to the set from the given source.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aspen::{Policy, PolicySet, PolicySource};
    /// # use std::str::FromStr;
    /// let policy = Policy::from_str(r#"{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}"#).unwrap();
    /// let source = PolicySource::new_entity_inline("arn:aws:iam::123456789012:user/username", "AIDAEXAMPLEUSERID00", "PolicyName");
    /// let mut policy_set = PolicySet::new();
    /// policy_set.add_policy(source, policy);
    ///
    /// assert_eq!(policy_set.policies().len(), 1);
    /// ```
    pub fn add_policy(&mut self, source: PolicySource, policy: Policy) {
        self.policies.push((source, policy));
    }

    /// Return the policies in the policy set.
    pub fn policies(&self) -> &Vec<(PolicySource, Policy)> {
        &self.policies
    }

    /// Evaluate the policy set. If a denial is found, return a Deny and the source immediately. Otherwise, if one or
    /// more approvals are found, return Allow and the relevant sources. Otherwise, return a DefaultDeny with no
    /// sources.
    pub fn evaluate<'a, 'b>(&'a self, context: &'b Context) -> Result<(Decision, Vec<&'a PolicySource>), AspenError> {
        self.evaluate_core(context, false)
    }

    /// Evaluate all policies in the policy set. If one or more denials are found, return a Deny and the relevant
    /// sources. Otherwise, if one or more approvals are found, return Allow and the relevant sources. Otherwise,
    /// return a DefaultDeny with no sources.
    pub fn evaluate_all<'a, 'b>(
        &'a self,
        context: &'b Context,
    ) -> Result<(Decision, Vec<&'a PolicySource>), AspenError> {
        self.evaluate_core(context, true)
    }

    fn evaluate_core<'a, 'b>(
        &'a self,
        context: &'b Context,
        eval_all: bool,
    ) -> Result<(Decision, Vec<&'a PolicySource>), AspenError> {
        let mut allowed_sources = Vec::with_capacity(self.policies.len());
        let denied_len = if eval_all {
            self.policies.len()
        } else {
            1
        };
        let mut denied_sources = Vec::with_capacity(denied_len);

        for (source, policy) in &self.policies {
            match policy.evaluate(context)? {
                Decision::Allow => {
                    if !source.is_boundary() {
                        allowed_sources.push(source)
                    }
                }
                Decision::Deny => {
                    denied_sources.push(source);
                    if !eval_all {
                        return Ok((Decision::Deny, denied_sources));
                    }
                }
                Decision::DefaultDeny => {
                    if source.is_boundary() {
                        denied_sources.push(source);
                        if !eval_all {
                            return Ok((Decision::Deny, denied_sources));
                        }
                    }
                }
            }
        }

        if !denied_sources.is_empty() {
            Ok((Decision::Deny, denied_sources))
        } else if !allowed_sources.is_empty() {
            Ok((Decision::Allow, allowed_sources))
        } else {
            Ok((Decision::DefaultDeny, allowed_sources))
        }
    }
}

impl From<Vec<(PolicySource, Policy)>> for PolicySet {
    fn from(policies: Vec<(PolicySource, Policy)>) -> Self {
        Self {
            policies,
        }
    }
}

impl Default for PolicySet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{Context, Decision, Policy, PolicySet, PolicySource},
        indoc::indoc,
        pretty_assertions::{assert_eq, assert_ne},
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{Principal, PrincipalIdentity, SessionData, SessionValue, User},
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test_log::test]
    fn test_policy_source_derived() {
        let policy_sources = vec![
            PolicySource::new_entity_inline(
                "arn:aws:iam::123456789012:user/MyUser",
                "AIDAIXEXAMPLEID000000",
                "MyPolicy",
            ),
            PolicySource::new_entity_attached_policy(
                "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                "ANPAIXEXAMPLEID000000",
                "v1",
            ),
            PolicySource::new_group_inline(
                "arn:aws:iam::123456789012:group/MyGroup",
                "AGPAIXEXAMPLEID000000",
                "MyPolicy",
            ),
            PolicySource::new_group_attached_policy(
                "arn:aws:iam::123456789012:group/MyGroup",
                "AGPAIXEXAMPLEID000000",
                "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
                "AGPAIXEXAMPLEID000000",
                "v1",
            ),
            PolicySource::new_resource("arn:aws:dynamodb:us-west-2:123456789012:table/MyTable", Some("MyTable")),
            PolicySource::new_permission_boundary(
                "arn:aws:iam::123456789012:policy/MyPermissionBoundary",
                "APBAIXEXAMPLEID000000",
                "v1",
            ),
            PolicySource::new_org_service_control(
                "arn:aws:iam::123456789012:policy/MyOrgPolicy",
                "ANPAIXEXAMPLEID000000",
                "v1",
            ),
            PolicySource::new_session(),
        ];

        for i in 0..policy_sources.len() {
            let mut h1 = DefaultHasher::new();
            policy_sources[i].hash(&mut h1);
            let h1 = h1.finish();

            for j in 0..policy_sources.len() {
                let mut h2 = DefaultHasher::new();
                policy_sources[j].hash(&mut h2);
                let h2 = h2.finish();

                if i == j {
                    assert_eq!(policy_sources[i], policy_sources[j]);
                    assert_eq!(h1, h2);
                    assert_eq!(format!("{:?}", policy_sources[i]), format!("{:?}", policy_sources[j]));
                } else {
                    assert_ne!(policy_sources[i], policy_sources[j]);
                    assert_ne!(h1, h2);
                    assert_ne!(format!("{:?}", policy_sources[i]), format!("{:?}", policy_sources[j]));
                }
            }
        }
    }

    #[test_log::test]
    #[allow(clippy::redundant_clone)]
    fn test_eval() {
        let mut ps = PolicySet::default();

        let entity_inline_policy_source = PolicySource::new_entity_inline(
            "arn:aws:iam::123456789012:user/MyUser",
            "AIDAIXEXAMPLEID000000",
            "MyPolicy",
        );
        let entity_inline_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::mybucket",
                    "Condition": {
                        "Bool": {
                            "AllowBucketAccess": ["true"]
                        }
                    }
                }
            ]
        }"#})
        .unwrap();
        ps.add_policy(entity_inline_policy_source.clone(), entity_inline_policy.clone());

        let entity_attached_policy_source = PolicySource::new_entity_attached_policy(
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "ANPAIXEXAMPLEID000000",
            "v1",
        );
        let entity_attached_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListAllMyBuckets"
                    ],
                    "Resource": "arn:aws:s3:::*"
                }
            ]
        }"#})
        .unwrap();
        ps.add_policy(entity_attached_policy_source.clone(), entity_attached_policy.clone());

        let group_inline_policy_source = PolicySource::new_group_inline(
            "arn:aws:iam::123456789012:group/MyGroup",
            "AGPAIXEXAMPLEID000000",
            "MyPolicy",
        );
        let group_inline_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "NotResource": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                    "Principal": {
                        "CanonicalUser": "9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d"
                    }
                }
            ]
        }"#})
        .unwrap();
        ps.add_policy(group_inline_policy_source.clone(), group_inline_policy.clone());

        let group_attached_policy_source = PolicySource::new_group_attached_policy(
            "arn:aws:iam::123456789012:group/MyGroup",
            "AGPAIXEXAMPLEID000000",
            "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
            "AGPAIXEXAMPLEID000000",
            "v1",
        );
        let group_attached_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Describe*"
                    ],
                    "Resource": "*",
                    "Principal": "*"
                }
            ]
        }"#})
        .unwrap();
        ps.add_policy(group_attached_policy_source.clone(), group_attached_policy.clone());

        let resource_policy_source =
            PolicySource::new_resource("arn:aws:dynamodb:us-west-2:123456789012:table/MyTable", Some("MyTable"));
        let resource_policy = Policy::from_str(indoc! {r#"
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:DescribeTable",
                            "dynamodb:ListTagsOfResource"
                        ],
                        "Resource": "arn:aws:dynamodb:us-west-2:123456789012:table/MyTable",
                        "Principal": {
                            "AWS": "arn:aws:iam::123456789012:user/MyUser"
                        }
                    }
                ]
            }
        "#})
        .unwrap();
        ps.add_policy(resource_policy_source.clone(), resource_policy.clone());

        let permission_boundary_policy_source = PolicySource::new_permission_boundary(
            "arn:aws:iam::123456789012:policy/MyPermissionBoundary",
            "APBAIXEXAMPLEID000000",
            "v1",
        );
        let permission_boundary_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "iam:Create*",
                    "Resource": "*"
                }
            ]
        }"#})
        .unwrap();
        ps.add_policy(permission_boundary_policy_source.clone(), permission_boundary_policy.clone());

        let org_service_control_policy_source = PolicySource::new_org_service_control(
            "arn:aws:iam::123456789012:policy/MyOrgPolicy",
            "ANPAIXEXAMPLEID000000",
            "v1",
        );
        let org_service_control_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "iam:Delete*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }"#})
        .unwrap();
        ps.add_policy(org_service_control_policy_source.clone(), org_service_control_policy.clone());

        let session_source = PolicySource::new_session();
        let session_policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        "#})
        .unwrap();
        ps.add_policy(session_source.clone(), session_policy.clone());

        assert_eq!(ps.policies().len(), 8);
        let actor =
            Principal::from(vec![PrincipalIdentity::from(User::new("aws", "123456789012", "/", "MyUser").unwrap())]);
        let mut sd = SessionData::new();
        sd.insert("aws:username", SessionValue::from("MyUser"));
        let mut context_builder = Context::builder();
        context_builder.api("DescribeSecurityGroups").actor(actor).session_data(sd).service("ec2");
        let context = context_builder.build().unwrap();
        let (decision, sources) = ps.evaluate_all(&context).unwrap();
        assert_eq!(decision, Decision::Allow);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0], &group_attached_policy_source);
        assert_eq!(ps.evaluate(&context).unwrap().0, Decision::Allow);

        context_builder.api("RunInstances");
        let context = context_builder.build().unwrap();
        let (decision, sources) = ps.evaluate_all(&context).unwrap();
        assert_eq!(decision, Decision::Deny);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0], &group_inline_policy_source);
        assert_eq!(ps.evaluate(&context).unwrap().0, Decision::Deny);

        context_builder
            .api("DescribeTable")
            .service("dynamodb")
            .resources(vec![Arn::from_str("arn:aws:dynamodb:us-west-2:123456789012:table/MyTable").unwrap()]);
        let context = context_builder.build().unwrap();
        let (decision, sources) = ps.evaluate_all(&context).unwrap();
        assert_eq!(decision, Decision::Allow);
        assert_eq!(sources, vec![&resource_policy_source,]);
        assert_eq!(ps.evaluate(&context).unwrap().0, Decision::Allow);

        context_builder
            .service("iam")
            .api("CreateUser")
            .resources(vec![Arn::from_str("arn:aws:iam::123456789012:user/MyUser").unwrap()]);
        let context = context_builder.build().unwrap();
        let (decision, sources) = ps.evaluate_all(&context).unwrap();
        assert_eq!(decision, Decision::Deny);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0], &permission_boundary_policy_source);
        assert_eq!(ps.evaluate(&context).unwrap().0, Decision::Deny);

        context_builder
            .service("s3")
            .api("DeleteBucket")
            .resources(vec![Arn::from_str("arn:aws:s3:::notmybucket").unwrap()]);
        let context = context_builder.build().unwrap();
        let (decision, sources) = ps.evaluate_all(&context).unwrap();
        assert_eq!(decision, Decision::DefaultDeny);
        assert!(sources.is_empty());
        assert_eq!(ps.evaluate(&context).unwrap().0, Decision::DefaultDeny);

        let ps2 = PolicySet::from(vec![
            (entity_inline_policy_source.clone(), entity_inline_policy.clone()),
            (entity_attached_policy_source.clone(), entity_attached_policy.clone()),
            (group_inline_policy_source.clone(), group_inline_policy.clone()),
            (group_attached_policy_source.clone(), group_attached_policy.clone()),
            (resource_policy_source.clone(), resource_policy.clone()),
            (permission_boundary_policy_source.clone(), permission_boundary_policy.clone()),
            (org_service_control_policy_source.clone(), org_service_control_policy.clone()),
            (session_source.clone(), session_policy.clone()),
        ]);

        assert_eq!(ps, ps2);
        assert_eq!(ps.clone(), ps);
        assert_eq!(format!("{:?}", ps), format!("{:?}", ps2));
    }
}
