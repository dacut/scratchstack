use {
    crate::{eval::regex_from_glob, AspenError, Context, PolicyVersion},
    scratchstack_arn::Arn,
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

const PARTITION_START: usize = 4;

/// An Amazon Resource Name (ARN) statement in an IAM Aspen policy.
///
/// This is used to match [scratchstack_arn::Arn] objects from a resource statement in the IAM Aspen policy language. For example,
/// an [ResourceArn] created from `arn:aws*:ec2:us-*-?:123456789012:instance/i-*` would match the following [Arn]
/// objects:
/// * `arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0`
/// * `arn:aws-us-gov:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0`
///
/// Patterns are similar to glob statements with a few differences:
/// * The `*` character matches any number of characters, including none, within a single segment of the ARN.
/// * The `?` character matches any single character within a single segment of the ARN.
///
/// [ResourceArn] objects are immutable.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ResourceArn {
    arn: String,
    service_start: usize,
    region_start: usize,
    account_id_start: usize,
    resource_start: usize,
}

impl ResourceArn {
    /// Create a new ARN pattern from the specified components.
    ///
    /// * `partition` - The partition the resource is in.
    /// * `service` - The service the resource belongs to.
    /// * `region` - The region the resource is in.
    /// * `account_id` - The account ID the resource belongs to.
    /// * `resource` - The resource name.
    pub fn new(partition: &str, service: &str, region: &str, account_id: &str, resource: &str) -> Self {
        let arn = format!("arn:{partition}:{service}:{region}:{account_id}:{resource}");
        let service_start = PARTITION_START + partition.len() + 1;
        let region_start = service_start + service.len() + 1;
        let account_id_start = region_start + region.len() + 1;
        let resource_start = account_id_start + account_id.len() + 1;

        Self {
            arn,
            service_start,
            region_start,
            account_id_start,
            resource_start,
        }
    }

    /// Retrieve the partition string pattern.
    #[inline]
    pub fn partition_pattern(&self) -> &str {
        &self.arn[PARTITION_START..self.service_start - 1]
    }

    /// Retrieve the service string pattern.
    #[inline]
    pub fn service_pattern(&self) -> &str {
        &self.arn[self.service_start..self.region_start - 1]
    }

    /// Retrieve the region string pattern.
    #[inline]
    pub fn region_pattern(&self) -> &str {
        &self.arn[self.region_start..self.account_id_start - 1]
    }

    /// Retrieve the account ID string pattern.
    #[inline]
    pub fn account_id_pattern(&self) -> &str {
        &self.arn[self.account_id_start..self.resource_start - 1]
    }

    /// Retrieve the resource name string pattern.
    #[inline]
    pub fn resource_pattern(&self) -> &str {
        &self.arn[self.resource_start..]
    }

    /// Indicates whether this [ResourceArn] matches the candidate [Arn], given the request [Context] ad using variable
    /// substitution rules according to the specified [PolicyVersion].
    ///
    /// # Example
    /// ```
    /// # use scratchstack_aspen::{Context, PolicyVersion, Resource, ResourceArn};
    /// # use scratchstack_arn::Arn;
    /// # use scratchstack_aws_principal::{Principal, User, SessionData, SessionValue};
    /// # use std::str::FromStr;
    /// let actor = Principal::from(vec![User::from_str("arn:aws:iam::123456789012:user/exampleuser").unwrap().into()]);
    /// let s3_object_arn = Arn::from_str("arn:aws:s3:::examplebucket/exampleuser/my-object").unwrap();
    /// let resources = vec![s3_object_arn.clone()];
    /// let session_data = SessionData::from([("aws:username", SessionValue::from("exampleuser"))]);
    /// let context = Context::builder()
    ///     .service("s3").api("GetObject").actor(actor).resources(resources)
    ///     .session_data(session_data).build().unwrap();
    /// let resource_arn = ResourceArn::new("aws", "s3", "", "", "examplebucket/${aws:username}/*");
    /// assert!(resource_arn.matches(&context, PolicyVersion::V2012_10_17, &s3_object_arn).unwrap());
    ///
    /// let bad_s3_object_arn = Arn::from_str("arn:aws:s3:::examplebucket/other-user/object").unwrap();
    /// assert!(!resource_arn.matches(&context, PolicyVersion::V2012_10_17, &bad_s3_object_arn).unwrap());
    /// ```
    pub fn matches(&self, context: &Context, pv: PolicyVersion, candidate: &Arn) -> Result<bool, AspenError> {
        let partition_pattern = self.partition_pattern();
        let service_pattern = self.service_pattern();
        let region_pattern = self.region_pattern();
        let account_id_pattern = self.account_id_pattern();
        let resource_pattern = self.resource_pattern();

        let partition = regex_from_glob(partition_pattern, false);
        let service = regex_from_glob(service_pattern, false);
        let region = regex_from_glob(region_pattern, false);
        let account_id = regex_from_glob(account_id_pattern, false);
        let resource = context.matcher(resource_pattern, pv, false)?;

        let partition_match = partition.is_match(candidate.partition());
        let service_match = service.is_match(candidate.service());
        let region_match = region.is_match(candidate.region());
        let account_id_match = account_id.is_match(candidate.account_id());
        let resource_match = resource.is_match(candidate.resource());
        let result = partition_match && service_match && region_match && account_id_match && resource_match;

        log::trace!("arn_pattern_matches: pattern={:?}, candidate={} -> partition={:?} ({}) service={:?} ({}) region={:?} ({}) account_id={:?} ({}) resource={:?} vs {:?} ({}) -> result={}", self, candidate, partition, partition_match, service, service_match, region, region_match, account_id, account_id_match, resource, candidate.resource(), resource_match, result);

        Ok(result)
    }
}

impl FromStr for ResourceArn {
    type Err = AspenError;

    /// Create an [ResourceArn] from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" {
            return Err(AspenError::InvalidResource(s.to_string()));
        }

        let arn = s.to_string();
        let service_start = PARTITION_START + parts[1].len() + 1;
        let region_start = service_start + parts[2].len() + 1;
        let account_id_start = region_start + parts[3].len() + 1;
        let resource_start = account_id_start + parts[4].len() + 1;

        Ok(Self {
            arn,
            service_start,
            region_start,
            account_id_start,
            resource_start,
        })
    }
}

impl Display for ResourceArn {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&self.arn)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::ResourceArn,
        crate::AspenError,
        pretty_assertions::{assert_eq, assert_ne},
        std::{collections::hash_map::DefaultHasher, hash::Hash, str::FromStr},
    };

    #[test_log::test]
    fn check_arn_pattern_derived() {
        let pat1a = ResourceArn::from_str("arn:*:ec2:us-*-1:123456789012:instance/*").unwrap();
        let pat1b = ResourceArn::new("*", "ec2", "us-*-1", "123456789012", "instance/*");
        let pat1c = pat1a.clone();
        let pat2 = ResourceArn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/*").unwrap();
        let pat3 = ResourceArn::from_str("arn:aws:ec*:us-*-1::*").unwrap();

        assert_eq!(pat1a, pat1b);
        assert_ne!(pat1a, pat2);
        assert_eq!(pat1c, pat1b);

        assert_eq!(pat1a.partition_pattern(), "*");
        assert_eq!(pat1a.service_pattern(), "ec2");
        assert_eq!(pat1a.region_pattern(), "us-*-1");
        assert_eq!(pat1a.account_id_pattern(), "123456789012");
        assert_eq!(pat1a.resource_pattern(), "instance/*");

        // Ensure we can derive a hash for the arn.
        let mut h2 = DefaultHasher::new();
        pat3.hash(&mut h2);

        // Ensure we can debug print the arn.
        _ = format!("{pat3:?}");

        // Ensure we can print the arn.
        assert_eq!(pat3.to_string(), "arn:aws:ec*:us-*-1::*".to_string());
    }

    #[test_log::test]
    fn check_arn_pattern_components() {
        let pat = ResourceArn::from_str("arn:aws:ec*:us-*-1::*").unwrap();
        assert_eq!(pat.partition_pattern(), "aws");
        assert_eq!(pat.service_pattern(), "ec*");
        assert_eq!(pat.region_pattern(), "us-*-1");
        assert_eq!(pat.account_id_pattern(), "");
        assert_eq!(pat.resource_pattern(), "*");
    }

    #[test_log::test]
    fn check_malformed_patterns() {
        let wrong_parts =
            vec!["arn", "arn:aw*", "arn:aw*:e?2", "arn:aw*:e?2:us-*-1", "arn:aw*:e?2:us-*-1:123456789012"];
        for wrong_part in wrong_parts {
            assert_eq!(
                ResourceArn::from_str(wrong_part).unwrap_err().to_string(),
                format!("Invalid resource: {wrong_part}")
            );
        }

        let err =
            ResourceArn::from_str("https:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(
            err,
            AspenError::InvalidResource(
                "https:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0".to_string()
            )
        );
    }
}
