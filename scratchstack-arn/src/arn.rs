use {
    crate::{
        utils::{validate_account_id, validate_partition, validate_region, validate_service},
        ArnError, GlobPattern,
    },
    serde::{de, Deserialize, Serialize},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        hash::Hash,
        str::FromStr,
    },
};

const PARTITION_START: usize = 4;

/// An Amazon Resource Name (ARN) representing an exact resource.
///
/// This is used to represent a known resource, such as an S3 bucket, EC2 instance, assumed role instance, etc. This is
/// _not_ used to represent resource _statements_ in the IAM Aspen policy language, which may contain wildcards. For
/// ARNs used to match resource statements, see [ArnPattern].
///
/// [Arn] objects are immutable.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Arn {
    arn: String,
    service_start: usize,
    region_start: usize,
    account_id_start: usize,
    resource_start: usize,
}

impl Arn {
    /// Create a new ARN from the specified components.
    ///
    /// * `partition` - The partition the resource is in (required). This is usually `aws`, `aws-cn`, or `aws-us-gov`
    ///     for actual AWS resources, but may be any string meeting the rules specified in [validate_partition] for
    ///     non-AWS resources.
    /// * `service` - The service the resource belongs to (required). This is a service name like `ec2` or `s3`.
    ///     Non-AWS resources must conform to the naming rules specified in [validate_service].
    /// * `region` - The region the resource is in (optional). If the resource is regional (and may other regions
    ///     may have the resources with the same name), this is the region name. If the resource is global, this is
    ///     empty.
    /// * `account_id` - The account ID the resource belongs to (optional). This is the 12-digit account ID or the
    ///     string `aws` for certain AWS-owned resources. Some resources (such as S3 buckets and objects) do not need
    ///     the account ID (the bucket name is globally unique within a partition), so this may be empty.
    /// * `resource` - The resource name (required). This is the name of the resource. The formatting is
    ///     service-specific, but must be a valid UTF-8 string.
    ///
    /// If any of the arguments are invalid, an [ArnError] is returned.
    pub fn new(
        partition: &str,
        service: &str,
        region: &str,
        account_id: &str,
        resource: &str,
    ) -> Result<Self, ArnError> {
        validate_partition(partition)?;
        validate_service(service)?;
        if !region.is_empty() {
            validate_region(region)?
        }
        if !account_id.is_empty() {
            validate_account_id(account_id)?
        }

        let arn = format!("arn:{}:{}:{}:{}:{}", partition, service, region, account_id, resource);
        let service_start = PARTITION_START + partition.len() + 1;
        let region_start = service_start + service.len() + 1;
        let account_id_start = region_start + region.len() + 1;
        let resource_start = account_id_start + account_id.len() + 1;

        Ok(Self {
            arn,
            service_start,
            region_start,
            account_id_start,
            resource_start,
        })
    }

    /// Retrieve the partition the resource is in.
    #[inline]
    pub fn partition(&self) -> &str {
        &self.arn[PARTITION_START..self.service_start - 1]
    }

    /// Retrieve the service the resource belongs to.
    #[inline]
    pub fn service(&self) -> &str {
        &self.arn[self.service_start..self.region_start - 1]
    }

    /// Retrieve the region the resource is in.
    #[inline]
    pub fn region(&self) -> &str {
        &self.arn[self.region_start..self.account_id_start - 1]
    }

    /// Retrieve the account ID the resource belongs to.
    #[inline]
    pub fn account_id(&self) -> &str {
        &self.arn[self.account_id_start..self.resource_start - 1]
    }

    /// Retrieve the resource name.
    #[inline]
    pub fn resource(&self) -> &str {
        &self.arn[self.resource_start..]
    }
}

impl Display for Arn {
    /// Return the ARN.
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.arn)
    }
}

impl FromStr for Arn {
    type Err = ArnError;

    /// Parse an ARN from a string.
    fn from_str(s: &str) -> Result<Self, ArnError> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        if parts.len() != 6 {
            return Err(ArnError::InvalidArn(s.to_string()));
        }

        if parts[0] != "arn" {
            return Err(ArnError::InvalidScheme(parts[0].to_string()));
        }

        Self::new(parts[1], parts[2], parts[3], parts[4], parts[5])
    }
}

impl<'de> Deserialize<'de> for Arn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for Arn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.arn)
    }
}

/// An Amazon Resource Name (ARN) statement in an IAM Aspen policy.
///
/// This is used to match [Arn] objects from a resource statement in the IAM Aspen policy language. For example,
/// an [ArnPattern] created from `arn:aws*:ec2:us-*-?:123456789012:instance/i-*` would match the following [Arn]
/// objects:
/// * `arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0`
/// * `arn:aws-us-gov:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0`
///
/// Patterns are similar to glob statements with a few differences:
/// * The `*` character matches any number of characters, including none, within a single segment of the ARN.
/// * The `?` character matches any single character within a single segment of the ARN.
///
/// [ArnPattern] objects are immutable.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ArnPattern {
    partition: GlobPattern,
    service: GlobPattern,
    region: GlobPattern,
    account_id: GlobPattern,
    resource: GlobPattern,
}

impl ArnPattern {
    /// Create a new ARN pattern from the specified components.
    ///
    /// * `partition` - The partition the resource is in.
    /// * `service` - The service the resource belongs to.
    /// * `region` - The region the resource is in.
    /// * `account_id` - The account ID the resource belongs to.
    /// * `resource` - The resource name.
    pub fn new(partition: &str, service: &str, region: &str, account_id: &str, resource: &str) -> Self {
        let partition = GlobPattern::new(partition);
        let service = GlobPattern::new(service);
        let region = GlobPattern::new(region);
        let account_id = GlobPattern::new(account_id);
        let resource = GlobPattern::new(resource);

        Self {
            partition,
            service,
            region,
            account_id,
            resource,
        }
    }

    /// Retreive the pattern for the partition.
    #[inline]
    pub fn partition(&self) -> &GlobPattern {
        &self.partition
    }

    /// Retrieve the pattern for the service.
    #[inline]
    pub fn service(&self) -> &GlobPattern {
        &self.service
    }

    /// Retrieve the pattern for the region.
    #[inline]
    pub fn region(&self) -> &GlobPattern {
        &self.region
    }

    /// Retrieve the pattern for the account ID.
    #[inline]
    pub fn account_id(&self) -> &GlobPattern {
        &self.account_id
    }

    /// Retrieve the pattern for the resource.
    #[inline]
    pub fn resource(&self) -> &GlobPattern {
        &self.resource
    }

    /// Indicate whether the specified [Arn] matches this pattern.
    pub fn matches(&self, arn: &Arn) -> bool {
        // This is split out here for easier debugging breakpoints.
        let partition = arn.partition();
        let service = arn.service();
        let region = arn.region();
        let account_id = arn.account_id();
        let resource = arn.resource();

        self.partition.matches(partition)
            && self.service.matches(service)
            && self.region.matches(region)
            && self.account_id.matches(account_id)
            && self.resource.matches(resource)
    }
}

impl FromStr for ArnPattern {
    type Err = ArnError;

    /// Create an [ArnPattern] from a string.
    fn from_str(s: &str) -> Result<Self, ArnError> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        if parts.len() != 6 {
            return Err(ArnError::InvalidArn(s.to_string()));
        }

        if parts[0] != "arn" {
            return Err(ArnError::InvalidScheme(parts[0].to_string()));
        }

        Ok(Self::new(parts[1], parts[2], parts[3], parts[4], parts[5]))
    }
}

impl Display for ArnPattern {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "arn:{}:{}:{}:{}:{}", self.partition, self.service, self.region, self.account_id, self.resource)
    }
}

#[cfg(test)]
mod test {
    use {
        super::{Arn, ArnPattern, GlobPattern},
        crate::{
            utils::{validate_account_id, validate_region},
            ArnError,
        },
        pretty_assertions::{assert_eq, assert_ne},
        regex::Regex,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test]
    fn check_arn_derived() {
        let arn1a = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn1b = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn2 = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef1").unwrap();
        let arn3 = Arn::from_str("arn:aws:ec2:us-east-1:123456789013:instance/i-1234567890abcdef0").unwrap();
        let arn4 = Arn::from_str("arn:aws:ec2:us-east-2:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn5 = Arn::from_str("arn:aws:ec3:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn6 = Arn::from_str("arn:awt:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();

        assert_eq!(arn1a, arn1b);
        assert!(arn1a < arn2);
        assert!(arn2 < arn3);
        assert!(arn3 < arn4);
        assert!(arn4 < arn5);
        assert!(arn5 < arn6);

        assert_eq!(arn1a, arn1a.clone());

        // Ensure ordering is logical.
        assert!(arn1a <= arn1b);
        assert!(arn1a < arn2);
        assert!(arn2 > arn1a);
        assert!(arn2 < arn3);
        assert!(arn1a < arn3);
        assert!(arn3 > arn2);
        assert!(arn3 > arn1a);
        assert!(arn3 < arn4);
        assert!(arn4 > arn3);
        assert!(arn4 < arn5);
        assert!(arn5 > arn4);
        assert!(arn5 < arn6);
        assert!(arn6 > arn5);

        assert!(arn3.clone().min(arn4.clone()) == arn3);
        assert!(arn4.clone().max(arn3) == arn4);

        // Ensure we can derive a hash for the arn.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        arn1a.hash(&mut h1a);
        arn1b.hash(&mut h1b);
        assert_eq!(h1a.finish(), h1b.finish());

        let mut h2 = DefaultHasher::new();
        arn2.hash(&mut h2);

        // Ensure we can debug print the arn.
        _ = format!("{:?}", arn1a);

        assert_eq!(arn1a.to_string(), "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0".to_string());
    }

    #[test]
    fn check_arn_components() {
        let arn = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "ec2");
        assert_eq!(arn.region(), "us-east-1");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "instance/i-1234567890abcdef0");
    }

    #[test]
    fn check_unicode() {
        let arn = Arn::from_str("arn:aws-中国:één:日本-東京-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.partition(), "aws-中国");
        assert_eq!(arn.service(), "één");
        assert_eq!(arn.region(), "日本-東京-1");

        let arn = Arn::from_str(
            "arn:việtnam:nœrøyfjorden:ap-southeast-7-hòa-hiệp-bắc-3:123456789012:instance/i-1234567890abcdef0",
        )
        .unwrap();
        assert_eq!(arn.partition(), "việtnam");
        assert_eq!(arn.service(), "nœrøyfjorden");
        assert_eq!(arn.region(), "ap-southeast-7-hòa-hiệp-bắc-3");
    }

    #[test]
    fn check_malformed_arns() {
        let wrong_parts =
            vec!["arn", "arn:aws", "arn:aws:ec2", "arn:aws:ec2:us-east-1", "arn:aws:ec2:us-east-1:123456789012"];
        for wrong_part in wrong_parts {
            assert_eq!(Arn::from_str(wrong_part).unwrap_err(), ArnError::InvalidArn(wrong_part.to_string()));
        }
    }

    #[test]
    fn check_invalid_scheme() {
        let err = Arn::from_str("http:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid scheme: "http""#.to_string());
    }

    #[test]
    fn check_invalid_partition() {
        let err = Arn::from_str("arn:Aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "Aws""#.to_string());

        let err = Arn::from_str("arn:local-:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "local-""#.to_string());

        let err = Arn::from_str("arn::ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: """#.to_string());

        let err = Arn::from_str("arn:-local:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "-local""#.to_string());

        let err = Arn::from_str("arn:aws--1:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "aws--1""#.to_string());

        let err = Arn::from_str(
            "arn:this-partition-has-too-many-chars:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        )
        .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "this-partition-has-too-many-chars""#.to_string());

        let err = Arn::from_str("arn:🦀:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "🦀""#.to_string());
    }

    #[test]
    fn check_invalid_services() {
        let err = Arn::from_str("arn:aws:ec2-:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "ec2-""#.to_string());

        let err = Arn::from_str("arn:aws:-ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "-ec2""#.to_string());

        let err = Arn::from_str("arn:aws:Ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "Ec2""#.to_string());

        let err = Arn::from_str("arn:aws:ec--2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "ec--2""#.to_string());

        let err = Arn::from_str("arn:aws:🦀:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "🦀""#.to_string());

        let err = Arn::from_str("arn:aws::us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: """#.to_string());
    }

    #[test]
    fn check_valid_regions() {
        let arn = Arn::from_str("arn:aws:ec2:local:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.region(), "local");

        let arn = Arn::from_str("arn:aws:ec2:us-east-1-bos-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.region(), "us-east-1-bos-1");
    }

    #[test]
    fn check_invalid_region() {
        let err = Arn::from_str("arn:aws:ec2:us-east-1-:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1-""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-1a:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1a""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:-us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "-us-east-1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:Us-East-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "Us-East-1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east--1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east--1""#.to_string());

        let err =
            Arn::from_str("arn:aws:ec2:us-east-1-bos-1-lax-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1-bos-1-lax-1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-🦀:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-🦀""#.to_string());

        let err = validate_region("").unwrap_err();
        assert_eq!(err, ArnError::InvalidRegion("".to_string()));
    }

    #[test]
    fn check_valid_account_ids() {
        let arn = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.account_id(), "123456789012");

        let arn = Arn::from_str("arn:aws:ec2:us-east-1:aws:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.account_id(), "aws");
    }

    #[test]
    fn check_invalid_account_ids() {
        let err = Arn::from_str("arn:aws:ec2:us-east-1:1234567890123:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "1234567890123""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-1:12345678901:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "12345678901""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-1:12345678901a:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "12345678901a""#.to_string());

        let err = validate_account_id("").unwrap_err();
        assert_eq!(err, ArnError::InvalidAccountId("".to_string()));
    }

    #[test]
    fn check_arn_pattern_matches() {
        let arn1 = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let pat1a = ArnPattern::from_str("arn:aws:ec2:*:123456789012:instance/*").unwrap();
        let pat1b = ArnPattern::from_str("arn:aws:ec2:us-*:123456789012:instance/*").unwrap();
        let pat1c = ArnPattern::from_str("arn:aws:ec2:us-*-1:123456789012:instance/*").unwrap();

        assert!(pat1a.matches(&arn1));
        assert!(pat1b.matches(&arn1));
        assert!(pat1c.matches(&arn1));

        let arn2 = Arn::from_str("arn:aws:s3:::bucket/path/to/object").unwrap();
        let pat2a = ArnPattern::from_str("arn:aws:s3:::bucket/path/to/object").unwrap();
        let pat2b = ArnPattern::from_str("arn:aws:s3:::bucket/*").unwrap();
        let pat2c = ArnPattern::from_str("arn:aws:s3:*:*:bucket/path/*").unwrap();
        let pat2d = ArnPattern::from_str("arn:aws:s?:*:*:bucket/*/to/*").unwrap();

        assert!(pat2a.matches(&arn2));
        assert!(pat2b.matches(&arn2));
        assert!(pat2c.matches(&arn2));
        assert!(pat2d.matches(&arn2));
        assert!(!pat1a.matches(&arn2));

        assert_eq!(pat2a.to_string(), "arn:aws:s3:::bucket/path/to/object");
        assert_eq!(pat2b.to_string(), "arn:aws:s3:::bucket/*");
        assert_eq!(pat2c.to_string(), "arn:aws:s3:*:*:bucket/path/*");
        assert_eq!(pat2d.to_string(), "arn:aws:s?:*:*:bucket/*/to/*");
    }

    #[test]
    fn check_arn_pattern_derived() {
        let pat1a = ArnPattern::from_str("arn:*:ec2:us-*-1:123456789012:instance/*").unwrap();
        let pat1b = ArnPattern::from_str("arn:*:ec2:us-*-1:123456789012:instance/*").unwrap();
        let pat1c = pat1a.clone();
        let pat2 = ArnPattern::from_str("arn:aws:ec2:us-east-1:123456789012:instance/*").unwrap();
        let pat3 = ArnPattern::from_str("arn:aws:ec*:us-*-1::*").unwrap();

        assert_eq!(pat1a, pat1b);
        assert_ne!(pat1a, pat2);
        assert_eq!(pat1c, pat1b);

        assert!(pat1a.service().eq(&GlobPattern::Exact("ec2".to_string())));

        // Ensure we can derive a hash for the arn.
        let mut h2 = DefaultHasher::new();
        pat3.hash(&mut h2);

        // Ensure we can debug print the arn.
        _ = format!("{:?}", pat3);

        // Ensure we can print the arn.
        assert_eq!(pat3.to_string(), "arn:aws:ec*:us-*-1::*".to_string());

        // FromStr for ArnSegmentPattern
        GlobPattern::from_str("").unwrap();
        GlobPattern::from_str("*").unwrap();
        GlobPattern::from_str("us-east-1").unwrap();
        GlobPattern::from_str("us*").unwrap();
        GlobPattern::from_str("us-*-1").unwrap();
    }

    #[test]
    fn check_arn_pattern_components() {
        let pat = ArnPattern::from_str("arn:aws:ec*:us-*-1::*").unwrap();
        assert_eq!(pat.partition(), &GlobPattern::Exact("aws".to_string()));
        assert_eq!(pat.service(), &GlobPattern::StartsWith("ec".to_string()));
        assert_eq!(pat.region(), &GlobPattern::Regex("us-*-1".to_string(), Regex::new("us-.*-1").unwrap()));
        assert_eq!(pat.account_id(), &GlobPattern::Empty);
        assert_eq!(pat.resource(), &GlobPattern::Any);
    }

    #[test]
    fn check_malformed_patterns() {
        let wrong_parts =
            vec!["arn", "arn:aw*", "arn:aw*:e?2", "arn:aw*:e?2:us-*-1", "arn:aw*:e?2:us-*-1:123456789012"];
        for wrong_part in wrong_parts {
            assert_eq!(
                ArnPattern::from_str(wrong_part).unwrap_err().to_string(),
                format!("Invalid ARN: {:#?}", wrong_part)
            );
        }

        let err =
            ArnPattern::from_str("https:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err, ArnError::InvalidScheme("https".to_string()));
    }

    #[test]
    fn check_serialization() {
        let arn: Arn =
            serde_json::from_str(r#""arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0""#).unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "ec2");
        assert_eq!(arn.region(), "us-east-1");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "instance/i-1234567890abcdef0");

        let arn_str = serde_json::to_string(&arn).unwrap();
        assert_eq!(arn_str, r#""arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0""#);

        let arn_err = serde_json::from_str::<Arn>(r#""arn:aws:ec2:us-east-1""#).unwrap_err();
        assert_eq!(arn_err.to_string(), r#"Invalid ARN: "arn:aws:ec2:us-east-1""#);

        let arn_err = serde_json::from_str::<Arn>(r#"{}"#);
        assert_eq!(arn_err.unwrap_err().to_string(), "invalid type: map, expected a string at line 1 column 0");
    }
}
// end tests -- do not delete; needed for coverage.
