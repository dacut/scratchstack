use {
    super::AwsPrincipal,
    crate::{display_json, serutil::StringLikeList},
    derive_builder::Builder,
    scratchstack_aws_principal::{Principal as PrincipalActor, PrincipalIdentity, PrincipalSource},
    serde::{Deserialize, Serialize},
};

#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecifiedPrincipal {
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "AWS", skip_serializing_if = "Option::is_none")]
    aws: Option<StringLikeList<AwsPrincipal>>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "CanonicalUser", skip_serializing_if = "Option::is_none")]
    canonical_user: Option<StringLikeList<String>>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Federated", skip_serializing_if = "Option::is_none")]
    federated: Option<StringLikeList<String>>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Service", skip_serializing_if = "Option::is_none")]
    service: Option<StringLikeList<String>>,
}

display_json!(SpecifiedPrincipal);

impl SpecifiedPrincipal {
    #[inline]
    pub fn builder() -> SpecifiedPrincipalBuilder {
        SpecifiedPrincipalBuilder::default()
    }

    #[inline]
    pub fn aws(&self) -> Option<&StringLikeList<AwsPrincipal>> {
        self.aws.as_ref()
    }

    #[inline]
    pub fn canonical_user(&self) -> Option<&StringLikeList<String>> {
        self.canonical_user.as_ref()
    }

    #[inline]
    pub fn federated(&self) -> Option<&StringLikeList<String>> {
        self.federated.as_ref()
    }

    #[inline]
    pub fn service(&self) -> Option<&StringLikeList<String>> {
        self.service.as_ref()
    }

    pub fn matches(&self, actor: &PrincipalActor) -> bool {
        for identity in actor.iter() {
            let source = identity.source();
            match source {
                PrincipalSource::Aws => {
                    if let Some(aws_ids) = self.aws() {
                        for aws_id in aws_ids.iter() {
                            if aws_id.matches(identity) {
                                return true;
                            }
                        }
                    }
                }
                PrincipalSource::CanonicalUser => {
                    if let PrincipalIdentity::CanonicalUser(identity) = identity {
                        if let Some(canonical_users) = self.canonical_user() {
                            for canonical_user in canonical_users.iter() {
                                if canonical_user == identity.canonical_user_id() {
                                    return true;
                                }
                            }
                        }
                    }
                }
                PrincipalSource::Federated => {
                    todo!("Federated principal matching not implemented");
                }
                PrincipalSource::Service => {
                    if let PrincipalIdentity::Service(identity) = identity {
                        if let Some(services) = self.service() {
                            for service in services.iter() {
                                if service == identity.global_dns_name().as_str()
                                    || service == identity.regional_dns_name().as_str()
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::SpecifiedPrincipal;

    #[test]
    fn test_deserialize_basic1() {
        let sp: SpecifiedPrincipal = serde_json::from_str(
            r#"
            {
                "AWS": ["123456789012", "arn:aws:iam::123456789012:user/*"],
                "CanonicalUser": ["df22d4799ef444d6434c676951d8b390145f2fc5f9107140d0e4b733ad40516d"],
                "Federated": ["dacut@kanga.org"],
                "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
            }
        "#,
        )
        .unwrap();

        assert!(sp.aws.is_some());
        assert!(sp.canonical_user.is_some());
        assert!(sp.federated.is_some());
        assert!(sp.service.is_some());
    }
}
