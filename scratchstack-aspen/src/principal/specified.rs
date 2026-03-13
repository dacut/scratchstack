use {
    super::AwsPrincipal,
    crate::{display_json, from_str_json, serutil::StringLikeList},
    derive_builder::Builder,
    scratchstack_aws_principal::Principal as PrincipalActor,
    serde::{Deserialize, Serialize},
};

/// A non-wildcard principal statement in an Aspen policy.
///
/// `SpecifiedPrincipal` structs are immutable. To construct this programmatically, use
/// [`SpecifiedPrincipalBuilder`].
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecifiedPrincipal {
    /// AWS principals specified in the statement.
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "AWS", skip_serializing_if = "Option::is_none")]
    aws: Option<StringLikeList<AwsPrincipal>>,

    /// Federated users specified in the statement.
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Federated", skip_serializing_if = "Option::is_none")]
    federated: Option<StringLikeList<String>>,

    /// Services specified in the statement.
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Service", skip_serializing_if = "Option::is_none")]
    service: Option<StringLikeList<String>>,
}

display_json!(SpecifiedPrincipal);
from_str_json!(SpecifiedPrincipal);

impl SpecifiedPrincipal {
    /// Create a [`SpecifiedPrincipalBuilder`] to programmatically construct a `SpecifiedPrincipal`.
    #[inline]
    pub fn builder() -> SpecifiedPrincipalBuilder {
        SpecifiedPrincipalBuilder::default()
    }

    /// Returns the AWS principals specified in the statement.
    #[inline]
    pub fn aws(&self) -> Option<&StringLikeList<AwsPrincipal>> {
        self.aws.as_ref()
    }

    /// Returns the federated users specified in the statement.
    #[inline]
    pub fn federated(&self) -> Option<&StringLikeList<String>> {
        self.federated.as_ref()
    }

    /// Returns the services specified in the statement.
    #[inline]
    pub fn service(&self) -> Option<&StringLikeList<String>> {
        self.service.as_ref()
    }

    /// Indicates whether this Aspen-specified principal matches the given actor [principal][`Principal`].
    pub fn matches(&self, actor: &PrincipalActor) -> bool {
        if let Some(aws_ids) = self.aws() {
            for aws_id in aws_ids {
                if aws_id.matches(actor) {
                    return true;
                }
            }
        }

        if let PrincipalActor::FederatedUser(actor) = actor
            && let Some(federated_ids) = self.federated()
        {
            for federated_id in federated_ids {
                if federated_id.to_lowercase() == actor.user_name().to_lowercase() {
                    return true;
                }
            }
        }

        if let PrincipalActor::Service(actor) = actor
            && let Some(service_ids) = self.service()
        {
            for service_id in service_ids {
                let service_id_lower = service_id.to_lowercase();
                if service_id_lower == actor.regional_dns_name().to_lowercase()
                    || service_id_lower == actor.global_dns_name().to_lowercase()
                {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use {
        super::SpecifiedPrincipal,
        scratchstack_aws_principal::{FederatedUser, Principal as PrincipalActor, Service, User},
        std::str::FromStr,
    };

    #[test_log::test]
    fn test_deserialize_basic1() {
        let sp = SpecifiedPrincipal::from_str(
            r#"
            {
                "AWS": ["123456789012", "arn:aws:iam::123456789012:user/dacut"],
                "CanonicalUser": ["df22d4799ef444d6434c676951d8b390145f2fc5f9107140d0e4b733ad40516d"],
                "Federated": ["dacut@kanga.org"],
                "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
            }
        "#,
        )
        .unwrap();

        assert!(sp.aws.is_some());
        assert!(sp.federated.is_some());
        assert!(sp.service.is_some());
    }

    #[test_log::test]
    fn test_matches() {
        let sp = SpecifiedPrincipal::from_str(
            r#"
            {
                "AWS": ["arn:aws:iam::123456789012:user/dacut"],
                "Federated": ["dacut@kanga.org"],
                "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
            }
        "#,
        )
        .unwrap();

        let user = User::new("aws", "123456789012", "/", "dacut").unwrap();
        let federated_user = FederatedUser::new("aws", "123456789012", "dacut@kanga.org").unwrap();
        let lambda_regional = Service::new("lambda", Some("us-east-1".to_string()), "amazonaws.com").unwrap();

        assert!(sp.matches(&PrincipalActor::from(user.clone())));
        assert!(sp.matches(&PrincipalActor::from(federated_user.clone())));
        assert!(sp.matches(&PrincipalActor::from(lambda_regional.clone())));

        let user_wrong_partition = User::new("aws-us-gov", "123456789012", "/", "dacut").unwrap();
        assert!(!sp.matches(&PrincipalActor::from(user_wrong_partition)));

        let wrong_federated_user = FederatedUser::new("aws", "123456789012", "evildoer@kanga.org").unwrap();
        assert!(!sp.matches(&PrincipalActor::from(wrong_federated_user)));

        let wrong_service = Service::new("s3", None, "amazonaws.com").unwrap();
        assert!(!sp.matches(&PrincipalActor::from(wrong_service)));

        let empty = SpecifiedPrincipal::builder().build().unwrap();
        assert!(!empty.matches(&PrincipalActor::from(user)));
        assert!(!empty.matches(&PrincipalActor::from(federated_user)));
        assert!(!empty.matches(&PrincipalActor::from(lambda_regional)));
    }
}
