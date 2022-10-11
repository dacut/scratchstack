use {
    log::debug,
    serde::{
        de::{
            self,
            value::{MapAccessDeserializer, SeqAccessDeserializer},
            Deserializer, IntoDeserializer, MapAccess, SeqAccess, Unexpected, Visitor,
        },
        ser::{SerializeSeq, Serializer},
        Deserialize, Serialize,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        marker::PhantomData,
        ops::Index,
        sync::Arc,
    },
};

/// Implement Display for a given class by formatting it as pretty-printed JSON.
#[macro_export]
macro_rules! display_json {
    ($cls:ident) => {
        impl std::fmt::Display for $cls {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                let buf = Vec::new();
                let serde_formatter = ::serde_json::ser::PrettyFormatter::with_indent(b"    ");
                let mut ser = ::serde_json::Serializer::with_formatter(buf, serde_formatter);
                match self.serialize(&mut ser) {
                    Ok(()) => (),
                    Err(e) => {
                        ::log::error!("Failed to serialize: {}", e);
                        return Err(::std::fmt::Error {});
                    }
                };
                match std::str::from_utf8(&ser.into_inner()) {
                    Ok(s) => write!(f, "{}", s),
                    Err(e) => {
                        ::log::error!("JSON serialization contained non-UTF-8 characters: {}", e);
                        Err(::std::fmt::Error {})
                    }
                }
            }
        }
    };
}

/// Implement FromStr for a given class by parsing it as JSON.
#[macro_export]
macro_rules! from_str_json {
    ($cls:ident) => {
        impl ::std::str::FromStr for $cls {
            type Err = ::serde_json::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match ::serde_json::from_str::<Self>(s) {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        ::log::debug!("Failed to parse: {}: {:?}", s, e);
                        Err(e)
                    }
                }
            }
        }
    };
}

/// ElementList allows a JSON field to an element (represented as a JSON object) or a list of elements (represented as a JSON array).
pub enum ElementList<E> {
    Single(Arc<E>),
    List(Vec<Arc<E>>),
}

impl<E> ElementList<E> {
    pub fn to_vec(&self) -> Vec<Arc<E>> {
        match self {
            Self::Single(element) => vec![element.clone()],
            Self::List(element_list) => {
                let mut result = Vec::with_capacity(element_list.len());
                for element in element_list {
                    result.push(element.clone());
                }
                result
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::List(element_list) => element_list.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::List(element_list) => element_list.len(),
        }
    }
}

impl<E: Clone> Clone for ElementList<E> {
    fn clone(&self) -> Self {
        match self {
            Self::Single(v) => Self::Single(v.clone()),
            Self::List(v) => Self::List(v.clone()),
        }
    }
}

impl<E: Debug> Debug for ElementList<E> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Single(v) => write!(f, "{:?}", v),
            Self::List(v) => write!(f, "{:?}", v),
        }
    }
}

impl<E: Display> Display for ElementList<E> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Single(v) => write!(f, "{}", v),
            Self::List(v) => {
                let mut first = true;
                f.write_str("[")?;
                for e in v {
                    if first {
                        first = false;
                    } else {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", e)?;
                }
                f.write_str("]")
            }
        }
    }
}

impl<E> PartialEq for ElementList<E>
where
    E: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Single(v1), Self::Single(v2)) => v1 == v2,
            (Self::List(v1), Self::List(v2)) => v1 == v2,
            (Self::Single(v1), Self::List(v2)) => v2.len() == 1 && v1 == &v2[0],
            (Self::List(v1), Self::Single(v2)) => v1.len() == 1 && &v1[0] == v2,
        }
    }
}

impl<E> Eq for ElementList<E> where E: Eq {}

impl<E> From<Arc<E>> for ElementList<E> {
    fn from(v: Arc<E>) -> Self {
        Self::Single(v)
    }
}

impl<E> From<E> for ElementList<E> {
    fn from(v: E) -> Self {
        Self::Single(Arc::new(v))
    }
}

impl<E> From<Vec<Arc<E>>> for ElementList<E> {
    fn from(v: Vec<Arc<E>>) -> Self {
        Self::List(v)
    }
}

impl<E> Index<usize> for ElementList<E> {
    type Output = Arc<E>;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            Self::Single(v) => {
                if index == 0 {
                    v
                } else {
                    panic!("index out of bounds: the len is 1 but the index is {}", index);
                }
            }
            Self::List(v) => &v[index],
        }
    }
}

struct ElementListVisitor<E> {
    phantom: PhantomData<E>,
}

impl<'de, E: Clone + Debug + Deserialize<'de> + Serialize> Visitor<'de> for ElementListVisitor<E> {
    type Value = ElementList<E>;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "element or list of elements")
    }

    fn visit_str<SE: de::Error>(self, str: &str) -> Result<Self::Value, SE> {
        Ok(ElementList::<E>::Single(Arc::new(E::deserialize(str.into_deserializer())?)))
    }

    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        Ok(ElementList::<E>::Single(Arc::new(E::deserialize(MapAccessDeserializer::new(access))?)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut result: Vec<Arc<E>> = match access.size_hint() {
            None => Vec::new(),
            Some(size) => Vec::with_capacity(size),
        };

        while let Some(item) = access.next_element::<E>()? {
            result.push(Arc::new(item));
        }
        Ok(ElementList::List(result))
    }
}

impl<'de, E: Clone + Debug + Deserialize<'de> + Serialize> Deserialize<'de> for ElementList<E> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ElementListVisitor {
            phantom: PhantomData,
        })
    }
}

impl<E: Clone + Debug + Serialize> Serialize for ElementList<E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Single(v) => v.serialize(serializer),
            Self::List(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for e in v {
                    seq.serialize_element(&**e)?;
                }
                seq.end()
            }
        }
    }
}

/// StringList allows a JSON field to be a string or list of strings.
#[derive(Clone, Debug)]
pub enum StringList {
    Single(String),
    List(Vec<String>),
}

impl StringList {
    pub fn to_vec(&self) -> Vec<&str> {
        match self {
            Self::Single(s) => vec![s.as_str()],
            Self::List(s_list) => {
                let mut result = Vec::with_capacity(s_list.len());
                for s in s_list {
                    result.push(s.as_str());
                }
                result
            }
        }
    }
}

impl PartialEq<StringList> for StringList {
    fn eq(&self, other: &StringList) -> bool {
        match (self, other) {
            (Self::Single(my_el), Self::Single(other_el)) => my_el == other_el,
            (Self::Single(my_el), Self::List(other_el)) => other_el.len() == 1 && my_el == &other_el[0],
            (Self::List(my_el), Self::Single(other_el)) => my_el.len() == 1 && &my_el[0] == other_el,
            (Self::List(my_el), Self::List(other_el)) => my_el == other_el,
        }
    }
}

impl Eq for StringList {}

struct StringListVisitor {}

impl<'de> Visitor<'de> for StringListVisitor {
    type Value = StringList;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "string or list of strings")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        let deserializer = SeqAccessDeserializer::new(access);
        match Vec::<String>::deserialize(deserializer) {
            Ok(l) => Ok(StringList::List(l)),
            Err(e) => {
                debug!("Failed to deserialize string list: {:?}", e);
                Err(<A::Error as de::Error>::invalid_value(Unexpected::Seq, &self))
            }
        }
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StringList::Single(v.to_string()))
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StringListVisitor {})
    }
}

impl Serialize for StringList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Single(v) => v.serialize(serializer),
            Self::List(v) => v.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::serutil::ElementList,
        serde::Serialize,
        std::{panic::catch_unwind, sync::Arc},
    };

    #[test_log::test]
    fn test_basic_ops() {
        let el1a = ElementList::<u32>::Single(Arc::new(1));
        let el1b = ElementList::<u32>::List(vec![Arc::new(1)]);
        let el2a = ElementList::<u32>::List(vec![Arc::new(1), Arc::new(2)]);
        let el2b = ElementList::<u32>::List(vec![Arc::new(1), Arc::new(2)]);
        let el3 = ElementList::<u32>::List(vec![]);
        assert_eq!(el1a, el1b);
        assert_eq!(el1b, el1a);
        assert_ne!(el1a, el2a);
        assert_ne!(el2b, el1a);
        assert_eq!(el2a, el2b);

        assert!(!el1a.is_empty());
        assert!(!el1b.is_empty());
        assert!(!el2a.is_empty());
        assert!(el3.is_empty());

        assert_eq!(el1a.len(), 1);
        assert_eq!(el1b.len(), 1);
        assert_eq!(el2a.len(), 2);
        assert_eq!(el3.len(), 0);

        assert_eq!(el1a.clone(), el1a);

        assert_eq!(format!("{:?}", el1a), "1");
        assert_eq!(format!("{:?}", el1b), "[1]");
        assert_eq!(format!("{}", el2a), "[1, 2]");

        assert_eq!(*el1a[0], 1);
        assert_eq!(*el1b[0], 1);
        let e = catch_unwind(|| {
            let new_el = ElementList::<u32>::Single(Arc::new(1));
            println!("This won't print: {}", &new_el[1]);
        })
        .unwrap_err();
        assert_eq!(*e.downcast::<String>().unwrap(), "index out of bounds: the len is 1 but the index is 1");
    }

    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct SerFail {}
    display_json!(SerFail);

    impl Serialize for SerFail {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("Serialization failed"))
        }
    }

    #[derive(Clone, Debug)]
    struct SerBadUtf8 {}
    display_json!(SerBadUtf8);

    impl Serialize for SerBadUtf8 {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let bad = unsafe { String::from_utf8_unchecked(vec![0xc0]) };
            serializer.serialize_str(&bad)
        }
    }

    #[test_log::test]
    fn test_ser_fail() {
        let el = ElementList::Single(Arc::new(SerFail {}));
        let result = serde_json::to_string(&el);
        assert!(result.is_err());

        let e = catch_unwind(|| el.to_string()).unwrap_err();
        let e2 = e.downcast::<String>().unwrap();
        assert!((*e2).contains("a Display implementation returned an error"));

        let el = ElementList::List(vec![Arc::new(SerBadUtf8 {})]);
        let e = catch_unwind(|| el.to_string()).unwrap_err();
        let e2 = e.downcast::<String>().unwrap();
        assert!((*e2).contains("a Display implementation returned an error"));
    }
}
