use {
    super::AwsPrincipal,
    crate::{
        display_json,
        serutil::{ElementList, StringList},
    },
    derive_builder::Builder,
    serde::{Deserialize, Serialize},
};

#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecifiedPrincipal {
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "AWS", skip_serializing_if = "Option::is_none")]
    aws: Option<ElementList<AwsPrincipal>>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "CanonicalUser", skip_serializing_if = "Option::is_none")]
    canonical_user: Option<StringList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Federated", skip_serializing_if = "Option::is_none")]
    federated: Option<StringList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Service", skip_serializing_if = "Option::is_none")]
    service: Option<StringList>,
}

display_json!(SpecifiedPrincipal);

impl SpecifiedPrincipal {
    #[inline]
    pub fn builder() -> SpecifiedPrincipalBuilder {
        SpecifiedPrincipalBuilder::default()
    }

    #[inline]
    pub fn aws(&self) -> Option<&ElementList<AwsPrincipal>> {
        self.aws.as_ref()
    }

    #[inline]
    pub fn canonical_user(&self) -> Option<&StringList> {
        self.canonical_user.as_ref()
    }

    #[inline]
    pub fn federated(&self) -> Option<&StringList> {
        self.federated.as_ref()
    }

    #[inline]
    pub fn service(&self) -> Option<&StringList> {
        self.service.as_ref()
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
