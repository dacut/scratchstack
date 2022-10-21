mod arn;

use {
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_arn::Arn,
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

pub use arn::ResourceArn;

pub type ResourceList = StringLikeList<Resource>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resource {
    Any,
    Arn(ResourceArn),
}

impl Resource {
    #[inline]
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    pub fn matches(&self, context: &Context, pv: PolicyVersion, candidate: &Arn) -> Result<bool, AspenError> {
        match self {
            Self::Any => Ok(true),
            Self::Arn(pattern) => pattern.matches(context, pv, candidate),
        }
    }
}

impl FromStr for Resource {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(Self::Any);
        }

        let pattern = ResourceArn::from_str(s)?;
        Ok(Self::Arn(pattern))
    }
}

impl Display for Resource {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Any => f.write_str("*"),
            Self::Arn(arn_pattern) => f.write_str(&arn_pattern.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{serutil::ListKind, Resource, ResourceArn, ResourceList},
        indoc::indoc,
        pretty_assertions::assert_eq,
        std::{panic::catch_unwind, str::FromStr},
    };

    #[test_log::test]
    fn deserialize_resource_list_star() {
        let resource_list: ResourceList = serde_json::from_str("\"*\"").unwrap();
        assert_eq!(resource_list.kind(), ListKind::Single);
        let v = resource_list.to_vec();
        assert_eq!(v, vec![&Resource::Any]);
        assert!(!v.is_empty());
    }

    #[test_log::test]
    fn check_from() {
        let ap = ResourceArn::from_str("arn:*:ec*:us-*-2:123?56789012:instance/*").unwrap();
        let rl1: ResourceList = Resource::Arn(ap.clone()).into();
        let rl2: ResourceList = Resource::Arn(ap.clone()).into();
        let rl3: ResourceList = vec![Resource::Arn(ap.clone())].into();
        let rl4: ResourceList = vec![Resource::Arn(ap.clone())].into();

        assert_eq!(rl1, rl2);
        assert_eq!(rl1, rl3);
        assert_eq!(rl1, rl4);
        assert_eq!(rl2, rl3);
        assert_eq!(rl2, rl4);
        assert_eq!(rl3, rl4);
        assert_eq!(rl2, rl1);
        assert_eq!(rl3, rl1);
        assert_eq!(rl4, rl1);
        assert_eq!(rl3, rl2);
        assert_eq!(rl4, rl2);
        assert_eq!(rl4, rl3);

        assert!(!rl1.is_empty());
        assert!(!rl2.is_empty());
        assert!(!rl3.is_empty());
        assert!(!rl4.is_empty());
        assert_eq!(rl1.len(), 1);
        assert_eq!(rl2.len(), 1);
        assert_eq!(rl3.len(), 1);
        assert_eq!(rl4.len(), 1);

        assert_eq!(rl1[0], Resource::Arn(ap.clone()));
        assert_eq!(rl2[0], Resource::Arn(ap));

        let e = catch_unwind(|| {
            println!("This will not print: {}", rl1[1]);
        })
        .unwrap_err();
        assert_eq!(*e.downcast::<String>().unwrap(), "index out of bounds: the len is 1 but the index is 1");

        assert_eq!(format!("{}", rl1), r#""arn:*:ec*:us-*-2:123?56789012:instance/*""#);
        assert_eq!(
            format!("{}", rl3),
            indoc! { r#"
            [
                "arn:*:ec*:us-*-2:123?56789012:instance/*"
            ]"# }
        );
    }

    #[test_log::test]
    fn check_bad() {
        let e = Resource::from_str("arn:aws").unwrap_err();
        assert_eq!(e.to_string(), "Invalid resource: arn:aws");
    }

    #[test_log::test]
    fn check_derived() {
        let r1a = Resource::from_str("arn:aws:ec2:us-east-2:123456789012:instance/*").unwrap();
        let r1b = Resource::from_str("arn:aws:ec2:us-east-2:123456789012:instance/*").unwrap();
        let r2 = Resource::Any;

        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);
        assert_eq!(r1a, r1a.clone());

        assert_eq!(r1a.to_string(), "arn:aws:ec2:us-east-2:123456789012:instance/*");
        assert_eq!(r2.to_string(), "*");
    }
}
