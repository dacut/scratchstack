use {
    crate::{display_json, AspenError},
    log::debug,
    scratchstack_arn::ArnPattern,
    serde::{
        de::{self, Deserializer, IntoDeserializer, SeqAccess, Visitor},
        ser::{SerializeSeq, Serializer},
        Deserialize, Serialize,
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        ops::Index,
        str::FromStr,
        sync::Arc,
    },
};

#[derive(Clone, Debug, Eq)]
pub enum ResourceList {
    Single(Arc<Resource>),
    List(Vec<Arc<Resource>>),
}

impl PartialEq for ResourceList {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Single(ref resource), Self::Single(ref other_resource)) => resource == other_resource,
            (Self::List(ref resource_list), Self::List(ref other_resource_list)) => {
                resource_list == other_resource_list
            }
            (Self::Single(ref resource), Self::List(ref other_resource_list)) => {
                other_resource_list.len() == 1 && resource == &other_resource_list[0]
            }
            (Self::List(ref resource_list), Self::Single(ref other_resource)) => {
                resource_list.len() == 1 && &resource_list[0] == other_resource
            }
        }
    }
}

impl ResourceList {
    pub fn to_vec(&self) -> Vec<Arc<Resource>> {
        match self {
            Self::Single(resource) => vec![resource.clone()],
            Self::List(resource_list) => {
                let mut result = Vec::with_capacity(resource_list.len());
                for resource in resource_list {
                    result.push(resource.clone());
                }
                result
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::List(resource_list) => resource_list.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::List(resource_list) => resource_list.len(),
        }
    }
}

impl From<Arc<Resource>> for ResourceList {
    fn from(resource: Arc<Resource>) -> Self {
        Self::Single(resource)
    }
}

impl From<Vec<Arc<Resource>>> for ResourceList {
    fn from(resources: Vec<Arc<Resource>>) -> Self {
        Self::List(resources)
    }
}

impl From<Resource> for ResourceList {
    fn from(resource: Resource) -> Self {
        Self::Single(Arc::new(resource))
    }
}

impl From<Vec<Resource>> for ResourceList {
    fn from(resources: Vec<Resource>) -> Self {
        let mut result = Vec::with_capacity(resources.len());
        for resource in resources {
            result.push(Arc::new(resource));
        }
        Self::List(result)
    }
}

impl Index<usize> for ResourceList {
    type Output = Arc<Resource>;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            Self::Single(resource) => {
                if index == 0 {
                    resource
                } else {
                    panic!("index out of bounds: the len is 1 but the index is {}", index);
                }
            }
            Self::List(resource_list) => &resource_list[index],
        }
    }
}

display_json!(ResourceList);

struct ResourceListVisitor {}

impl<'de> Visitor<'de> for ResourceListVisitor {
    type Value = ResourceList;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "resource or list of resources")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(ResourceList::Single(Arc::new(Resource::deserialize(v.into_deserializer())?)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut result = match access.size_hint() {
            Some(size) => Vec::with_capacity(size),
            None => Vec::new(),
        };

        while let Some(resource) = access.next_element()? {
            result.push(Arc::new(resource));
        }

        Ok(ResourceList::List(result))
    }
}

impl<'de> Deserialize<'de> for ResourceList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ResourceListVisitor {})
    }
}

impl Serialize for ResourceList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(resource) => resource.serialize(serializer),
            Self::List(resource_list) => {
                let mut seq = serializer.serialize_seq(Some(resource_list.len()))?;
                for resource in resource_list {
                    seq.serialize_element(&**resource)?;
                }
                seq.end()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resource {
    Any,
    Arn(Arc<ArnPattern>),
}

impl FromStr for Resource {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(Self::Any);
        }

        match ArnPattern::from_str(s) {
            Ok(arn_pattern) => Ok(Self::Arn(Arc::new(arn_pattern))),
            Err(e) => {
                debug!("Failed to parse resource {:#?} as ARN pattern: {}", s, e);
                Err(AspenError::InvalidResource(s.to_string()))
            }
        }
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

struct ResourceVisitor {}
impl<'de> Visitor<'de> for ResourceVisitor {
    type Value = Resource;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "resource ARN or \"*\"")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match Resource::from_str(v) {
            Ok(resource) => Ok(resource),
            Err(_) => Err(E::invalid_value(de::Unexpected::Str(v), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ResourceVisitor {})
    }
}

impl Serialize for Resource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Any => serializer.serialize_str("*"),
            Self::Arn(arn) => serializer.serialize_str(&arn.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{Resource, ResourceList},
        indoc::indoc,
        pretty_assertions::assert_eq,
        scratchstack_arn::ArnPattern,
        std::{panic::catch_unwind, str::FromStr, sync::Arc},
    };

    #[test_log::test]
    fn deserialize_resource_list_star() {
        let resource_list: ResourceList = serde_json::from_str("\"*\"").unwrap();
        assert_eq!(resource_list, ResourceList::Single(Arc::new(Resource::Any)));
        let v = resource_list.to_vec();
        assert_eq!(v, vec![Arc::new(Resource::Any)]);
        assert!(!v.is_empty());
    }

    #[test_log::test]
    fn check_from() {
        let ap = ArnPattern::from_str("arn:*:ec*:us-*-2:123?56789012:instance/*").unwrap();
        let rl1: ResourceList = Resource::Arn(Arc::new(ap.clone())).into();
        let rl2: ResourceList = Arc::new(Resource::Arn(Arc::new(ap.clone()))).into();
        let rl3: ResourceList = vec![Resource::Arn(Arc::new(ap.clone()))].into();
        let rl4: ResourceList = vec![Arc::new(Resource::Arn(Arc::new(ap.clone())))].into();

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

        assert_eq!(*rl1[0], Resource::Arn(Arc::new(ap.clone())));
        assert_eq!(*rl2[0], Resource::Arn(Arc::new(ap)));

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
