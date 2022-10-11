use {
    crate::{display_json, AspenError},
    log::debug,
    serde::{
        de::{self, Deserializer, IntoDeserializer, SeqAccess, Unexpected, Visitor},
        ser::Serializer,
        Deserialize, Serialize,
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        ops::Index,
        str::FromStr,
    },
};

#[derive(Clone, Debug, Eq, Serialize)]
#[serde(untagged)]
pub enum ActionList {
    Single(Action),
    List(Vec<Action>),
}

impl PartialEq for ActionList {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Single(ref action), Self::Single(ref other_action)) => action == other_action,
            (Self::List(ref action_list), Self::List(ref other_action_list)) => action_list == other_action_list,
            (Self::Single(ref action), Self::List(ref other_action_list)) => {
                other_action_list.len() == 1 && action == &other_action_list[0]
            }
            (Self::List(ref action_list), Self::Single(ref other_action)) => {
                action_list.len() == 1 && &action_list[0] == other_action
            }
        }
    }
}

impl ActionList {
    pub fn to_vec(&self) -> Vec<&Action> {
        match self {
            Self::Single(ref action) => vec![action],
            Self::List(ref action_list) => {
                let mut result = Vec::with_capacity(action_list.len());
                for action in action_list {
                    result.push(action);
                }
                result
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::List(ref action_list) => action_list.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::List(ref action_list) => action_list.len(),
        }
    }
}

impl From<Action> for ActionList {
    fn from(action: Action) -> Self {
        Self::Single(action)
    }
}

impl From<Vec<Action>> for ActionList {
    fn from(actions: Vec<Action>) -> Self {
        Self::List(actions)
    }
}

impl Index<usize> for ActionList {
    type Output = Action;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            Self::Single(ref action) => {
                if index == 0 {
                    action
                } else {
                    panic!("index out of bounds: the len is 1 but the index is {}", index)
                }
            }
            Self::List(ref action_list) => &action_list[index],
        }
    }
}

display_json!(ActionList);

struct ActionListVisitor;

impl<'de> Visitor<'de> for ActionListVisitor {
    type Value = ActionList;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "a string or a list of strings")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(ActionList::Single(Action::deserialize(v.into_deserializer())?))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut result = match access.size_hint() {
            Some(size) => Vec::with_capacity(size),
            None => Vec::new(),
        };

        while let Some(resource) = access.next_element()? {
            result.push(resource);
        }

        Ok(ActionList::List(result))
    }
}

impl<'de> Deserialize<'de> for ActionList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ActionListVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Any,
    Specific {
        service: String,
        action: String,
    },
}

impl Action {
    pub fn new<S: Into<String>, A: Into<String>>(service: S, action: A) -> Result<Self, AspenError> {
        let service = service.into();
        let action = action.into();

        if service.is_empty() {
            debug!("Action '{service}:{action}' has an empty service.");
            return Err(AspenError::InvalidAction(format!("{}:{}", service, action)));
        }

        if action.is_empty() {
            debug!("Action '{service}:{action}' has an empty service.");
            return Err(AspenError::InvalidAction(format!("{}:{}", service, action)));
        }

        if !service.is_ascii() || !action.is_ascii() {
            debug!("Action '{service}:{action}' is not ASCII.");
            return Err(AspenError::InvalidAction(format!("{}:{}", service, action)));
        }

        for (i, c) in service.bytes().enumerate() {
            if !c.is_ascii_alphanumeric() && !(i > 0 && i < service.len() - 1 && (c == b'-' || c == b'_')) {
                debug!("Action '{service}:{action}' has an invalid service.");
                return Err(AspenError::InvalidAction(format!("{}:{}", service, action)));
            }
        }

        for (i, c) in action.bytes().enumerate() {
            if !c.is_ascii_alphanumeric() && c != b'*' && !(i > 0 && i < action.len() - 1 && (c == b'-' || c == b'_')) {
                debug!("Action '{service}:{action}' has an invalid action.");
                return Err(AspenError::InvalidAction(format!("{}:{}", service, action)));
            }
        }

        Ok(Action::Specific {
            service,
            action,
        })
    }

    #[inline]
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    #[inline]
    pub fn is_specific(&self) -> bool {
        matches!(self, Self::Specific { .. })
    }

    #[inline]
    pub fn service(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::Specific {
                service,
                ..
            } => service,
        }
    }

    #[inline]
    pub fn action(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::Specific {
                action,
                ..
            } => action,
        }
    }
}

impl FromStr for Action {
    type Err = AspenError;
    fn from_str(v: &str) -> Result<Self, Self::Err> {
        if v == "*" {
            return Ok(Self::Any);
        }

        let parts: Vec<&str> = v.split(':').collect();
        if parts.len() != 2 {
            return Err(AspenError::InvalidAction(v.to_string()));
        }

        let service = parts[0];
        let action = parts[1];

        Action::new(service, action)
    }
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Any => f.write_str("*"),
            Self::Specific {
                service,
                action,
            } => write!(f, "{}:{}", service, action),
        }
    }
}

struct ActionVisitor {}
impl<'de> Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "service:action or \"*\"")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        match Action::from_str(v) {
            Ok(action) => Ok(action),
            Err(_) => Err(E::invalid_value(Unexpected::Str(v), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(ActionVisitor {})
    }
}

impl Serialize for Action {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Any => serializer.serialize_str("*"),
            Self::Specific {
                service,
                action,
            } => serializer.serialize_str(&format!("{}:{}", service, action)),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{Action, ActionList},
        indoc::indoc,
        pretty_assertions::{assert_eq, assert_ne},
        std::{panic::catch_unwind, str::FromStr},
    };

    #[test_log::test]
    fn test_eq() {
        let a1a = ActionList::Single(Action::new("s1", "a1").unwrap());
        let a1b = ActionList::List(vec![Action::new("s1", "a1").unwrap()]);
        let a2a = ActionList::Single(Action::new("s2", "a1").unwrap());
        let a2b = ActionList::List(vec![Action::new("s2", "a1").unwrap()]);
        let a3a = ActionList::Single(Action::new("s1", "a2").unwrap());
        let a3b = ActionList::List(vec![Action::new("s1", "a2").unwrap()]);
        let a4a = ActionList::List(vec![]);
        let a4b = ActionList::List(vec![]);

        assert_eq!(a1a, a1a.clone());
        assert_eq!(a1b, a1b.clone());
        assert_eq!(a2a, a2a.clone());
        assert_eq!(a2b, a2b.clone());
        assert_eq!(a3a, a3a.clone());
        assert_eq!(a3b, a3b.clone());
        assert_eq!(a4a, a4a.clone());
        assert_eq!(a4b, a4b.clone());

        assert_eq!(a1a.len(), 1);
        assert_eq!(a1b.len(), 1);
        assert_eq!(a2a.len(), 1);
        assert_eq!(a2b.len(), 1);
        assert_eq!(a3a.len(), 1);
        assert_eq!(a3b.len(), 1);
        assert_eq!(a4a.len(), 0);
        assert_eq!(a4b.len(), 0);

        assert!(!a1a.is_empty());
        assert!(!a1b.is_empty());
        assert!(!a2a.is_empty());
        assert!(!a2b.is_empty());
        assert!(!a3a.is_empty());
        assert!(!a3b.is_empty());
        assert!(a4a.is_empty());
        assert!(a4b.is_empty());

        assert_eq!(a1a, a1b);
        assert_eq!(a1b, a1a);
        assert_eq!(a2a, a2b);
        assert_eq!(a2b, a2a);
        assert_eq!(a3a, a3b);
        assert_eq!(a3b, a3a);
        assert_eq!(a4a, a4b);
        assert_eq!(a4b, a4a);

        assert_ne!(a1a, a2a);
        assert_ne!(a1a, a2b);
        assert_ne!(a1a, a3a);
        assert_ne!(a1a, a3b);
        assert_ne!(a1a, a4a);
        assert_ne!(a1a, a4b);
        assert_ne!(a2a, a1a);
        assert_ne!(a2b, a1a);
        assert_ne!(a3a, a1a);
        assert_ne!(a3b, a1a);
        assert_ne!(a4a, a1a);
        assert_ne!(a4b, a1a);

        assert_ne!(a1b, a2a);
        assert_ne!(a1b, a2b);
        assert_ne!(a1b, a3a);
        assert_ne!(a1b, a3b);
        assert_ne!(a1b, a4a);
        assert_ne!(a1b, a4b);
        assert_ne!(a2a, a1b);
        assert_ne!(a2b, a1b);
        assert_ne!(a3a, a1b);
        assert_ne!(a3b, a1b);
        assert_ne!(a4a, a1b);
        assert_ne!(a4b, a1b);

        assert_ne!(a2a, a3a);
        assert_ne!(a2a, a3b);
        assert_ne!(a2a, a4a);
        assert_ne!(a2a, a4b);
        assert_ne!(a3a, a2a);
        assert_ne!(a3b, a2a);
        assert_ne!(a4a, a2a);
        assert_ne!(a4b, a2a);

        assert_ne!(a2b, a3a);
        assert_ne!(a2b, a3b);
        assert_ne!(a2b, a4a);
        assert_ne!(a2b, a4b);
        assert_ne!(a3a, a2b);
        assert_ne!(a3b, a2b);
        assert_ne!(a4a, a2b);
        assert_ne!(a4b, a2b);

        assert_ne!(a3a, a4a);
        assert_ne!(a3a, a4b);
        assert_ne!(a4a, a3a);
        assert_ne!(a4b, a3a);

        assert_ne!(a3b, a4a);
        assert_ne!(a3b, a4b);
        assert_ne!(a4a, a3b);
        assert_ne!(a4b, a3b);
    }

    #[test_log::test]
    fn test_from() {
        let a1a: ActionList = vec![Action::new("s1", "a1").unwrap()].into();
        let a1b: ActionList = Action::new("s1", "a1").unwrap().into();
        let a2a: ActionList = vec![Action::Any].into();

        assert_eq!(a1a, a1b);
        assert_eq!(a1b, a1a);
        assert_ne!(a1a, a2a);

        assert_eq!(a1a[0], a1b[0]);

        assert_eq!(
            format!("{}", a1a),
            indoc! {r#"
            [
                "s1:a1"
            ]"#}
        );
        assert_eq!(format!("{}", a1b), r#""s1:a1""#);
        assert_eq!(
            format!("{}", a2a),
            indoc! {r#"
            [
                "*"
            ]"#}
        );

        assert_eq!(format!("{}", a2a[0]), "*");

        let e = catch_unwind(|| {
            println!("This will not be printed: {}", a1b[1]);
        })
        .unwrap_err();
        assert_eq!(*e.downcast::<String>().unwrap(), "index out of bounds: the len is 1 but the index is 1");
    }

    #[test_log::test]
    fn test_bad_strings() {
        assert_eq!(Action::from_str("").unwrap_err().to_string(), "Invalid action: ");
        assert_eq!(Action::from_str("ec2:").unwrap_err().to_string(), "Invalid action: ec2:");
        assert_eq!(
            Action::from_str(":DescribeInstances").unwrap_err().to_string(),
            "Invalid action: :DescribeInstances"
        );
        assert_eq!(
            Action::from_str("🦀:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: 🦀:DescribeInstances"
        );
        assert_eq!(Action::from_str("ec2:🦀").unwrap_err().to_string(), "Invalid action: ec2:🦀");
        assert_eq!(
            Action::from_str("-ec2:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: -ec2:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("_ec2:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: _ec2:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2-:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2-:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2_:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2_:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2:-DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2:-DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2:_DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2:_DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2:DescribeInstances-").unwrap_err().to_string(),
            "Invalid action: ec2:DescribeInstances-"
        );
        assert_eq!(
            Action::from_str("ec2:DescribeInstances_").unwrap_err().to_string(),
            "Invalid action: ec2:DescribeInstances_"
        );

        assert_eq!(Action::from_str("e_c-2:De-scribe_Instances").unwrap().service(), "e_c-2");
        assert_eq!(Action::from_str("e_c-2:De-scribe_Instances").unwrap().action(), "De-scribe_Instances");
        assert!(Action::from_str("e_c-2:De-scribe_Instances").unwrap().is_specific());
        assert!(!Action::from_str("e_c-2:De-scribe_Instances").unwrap().is_any());
        assert_eq!(Action::from_str("*").unwrap().service(), "*");
        assert_eq!(Action::from_str("*").unwrap().action(), "*");
        assert!(Action::from_str("*").unwrap().is_any());
        assert!(!Action::from_str("*").unwrap().is_specific());
    }
}
