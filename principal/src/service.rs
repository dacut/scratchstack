use {
    crate::{utils::validate_dns, PrincipalError},
    scratchstack_arn::utils::validate_region,
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about a service.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Service {
    /// Name of the service.
    service_name: String,

    /// The region the service is running in. If None, the service is global.
    region: Option<String>,

    /// The DNS suffix of the service. This is usually amazonaws.com.
    dns_suffix: String,
}

impl Service {
    /// Create a [Service] object representing an AWS(-ish) service.
    ///
    /// # Arguments
    ///
    /// * `service_name`: The name of the service. This must meet the following requirements or a
    ///     [PrincipalError::InvalidService] error will be returned:
    ///     *   The name must contain between 1 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `region`: The region the service is running in. If None, the service is global.
    /// * `dns_suffix`: The DNS suffix of the service. This is usually amazonaws.com.
    ///
    /// If all of the requirements are met, a [Service] object is returned.  Otherwise, a [PrincipalError] error is
    /// returned.
    pub fn new(service_name: &str, region: Option<String>, dns_suffix: &str) -> Result<Self, PrincipalError> {
        validate_dns(service_name, 32, PrincipalError::InvalidService)?;
        validate_dns(dns_suffix, 128, PrincipalError::InvalidService)?;

        let region = match region {
            None => None,
            Some(region) => {
                validate_region(region.as_str())?;
                Some(region)
            }
        };

        Ok(Self {
            service_name: service_name.into(),
            region,
            dns_suffix: dns_suffix.into(),
        })
    }

    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[inline]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    #[inline]
    pub fn dns_suffix(&self) -> &str {
        &self.dns_suffix
    }
}

impl Display for Service {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.region {
            None => write!(f, "{}.{}", self.service_name, self.dns_suffix),
            Some(region) => write!(f, "{}.{}.{}", self.service_name, region, self.dns_suffix),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::Service,
        crate::{PrincipalIdentity, PrincipalSource},
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_components() {
        let s1 = Service::new("s3", None, "amazonaws.com").unwrap();
        let s2 = Service::new("s3", Some("us-east-1".into()), "amazonaws.com").unwrap();

        assert_eq!(s1.service_name(), "s3");
        assert_eq!(s1.region(), None);
        assert_eq!(s1.dns_suffix(), "amazonaws.com");

        assert_eq!(s2.service_name(), "s3");
        assert_eq!(s2.region(), Some("us-east-1"));
        assert_eq!(s2.dns_suffix(), "amazonaws.com");

        let p = PrincipalIdentity::from(s1);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Service);
        assert_eq!(source.to_string(), "Service".to_string());
    }

    #[test]
    fn check_derived() {
        let s1a = Service::new("s3", None, "amazonaws.com").unwrap();
        let s1b = Service::new("s3", None, "amazonaws.com").unwrap();
        let s2 = Service::new("s3", None, "amazonaws.net").unwrap();
        let s3 = Service::new("s3", Some("us-east-1".into()), "amazonaws.net").unwrap();
        let s4 = Service::new("s3", Some("us-east-2".into()), "amazonaws.net").unwrap();
        let s5 = Service::new("s4", None, "amazonaws.net").unwrap();
        let s6 = Service::new("s4", Some("us-east-1".into()), "amazonaws.net").unwrap();

        assert_eq!(s1a, s1b);
        assert_ne!(s1a, s2);
        assert_eq!(s1a.clone(), s1a);
        assert_ne!(s1a, s3);
        assert_ne!(s2, s3);
        assert_ne!(s3, s4);
        assert_ne!(s4, s5);
        assert_ne!(s5, s6);

        // Ensure we can hash a service.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        s1a.hash(&mut h1a);
        s1b.hash(&mut h1b);
        s2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure ordering is logical.
        assert!(s1a <= s1b);
        assert!(s1a < s2);
        assert!(s2 > s1a);
        assert!(s1a < s3);
        assert!(s2 < s3);
        assert!(s1a < s4);
        assert!(s2 < s4);
        assert!(s3 < s4);
        assert!(s1a < s5);
        assert!(s2 < s5);
        assert!(s3 < s5);
        assert!(s4 < s5);
        assert!(s1a < s6);
        assert!(s2 < s6);
        assert!(s3 < s6);
        assert!(s4 < s6);
        assert!(s5 < s6);
        assert_eq!(s1a.clone().max(s2.clone()), s2);
        assert_eq!(s1a.clone().min(s3), s1a);

        // Ensure formatting is correct to the DNS name.
        assert_eq!(s1a.to_string(), "s3.amazonaws.com");
        assert_eq!(s6.to_string(), "s4.us-east-1.amazonaws.net");

        // Ensure we can debug print a service.
        let _ = format!("{:?}", s1a);
    }

    #[test]
    fn check_valid_services() {
        let s1a = Service::new("service-name", None, "amazonaws.com").unwrap();
        let s1b = Service::new("service-name", None, "amazonaws.com").unwrap();
        let s2 = Service::new("service-name2", None, "amazonaws.com").unwrap();
        let s3 = Service::new("service-name", Some("us-east-1".to_string()), "amazonaws.com").unwrap();
        let s4 = Service::new("aservice-name-with-32-characters", None, "amazonaws.com").unwrap();

        assert_eq!(s1a, s1b);
        assert_ne!(s1a, s2);
        assert_eq!(s1a, s1a.clone());

        assert_eq!(s1a.to_string(), "service-name.amazonaws.com");
        assert_eq!(s2.to_string(), "service-name2.amazonaws.com");
        assert_eq!(s3.to_string(), "service-name.us-east-1.amazonaws.com");
        assert_eq!(s4.to_string(), "aservice-name-with-32-characters.amazonaws.com");
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            Service::new("service name", None, "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::new("service name", Some("us-east-1".to_string()), "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::new("service!name", None, "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(
            Service::new("service!name", Some("us-east-1".to_string()), "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(Service::new("", None, "amazonaws.com",).unwrap_err().to_string(), r#"Invalid service name: """#);

        assert_eq!(
            Service::new("a-service-name-with-33-characters", None, "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "a-service-name-with-33-characters""#
        );

        assert_eq!(
            Service::new("service-name", Some("us-east-".to_string()), "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid region: "us-east-""#
        );

        assert_eq!(
            Service::new("service-name", Some("us-east-1".to_string()), "amazonaws..com",).unwrap_err().to_string(),
            r#"Invalid service name: "amazonaws..com""#
        );
    }
}
// end tests -- do not delete; needed for coverage.
