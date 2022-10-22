use {
    log::{debug, error},
    serde::{
        de::{
            self,
            value::{MapAccessDeserializer, SeqAccessDeserializer},
            Deserializer, MapAccess, SeqAccess, Unexpected, Visitor,
        },
        ser::{SerializeSeq, Serializer},
        Deserialize, Serialize,
    },
    std::{
        any::type_name,
        fmt::{Debug, Display, Error as FmtError, Formatter, Result as FmtResult},
        marker::PhantomData,
        str::{from_utf8, FromStr},
    },
};

/// Return the simplified type name of a type.
fn simple_type_name<E>() -> &'static str {
    // Get the type name of the element we're serializing.
    let tn = type_name::<E>();

    // If it's wrapped in an Option or the like, unwrap it.
    let tn = match tn.rfind('<') {
        None => tn,
        Some(i) => {
            let sub = &tn[i + 1..tn.len()];
            match sub.find('>') {
                None => sub,
                Some(j) => &sub[..j],
            }
        }
    };

    // If it's a reference, unwrap it.
    let tn = tn.trim_start_matches('&');

    // If it's a path, use just the last component.
    match tn.rfind("::") {
        None => tn,
        Some(i) => &tn[i + 2..],
    }
}

/// Implement Display for a given class by formatting it as pretty-printed JSON.
#[macro_export]
macro_rules! display_json {
    ($cls:ty) => {
        impl ::std::fmt::Display for $cls {
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

/// The JSON representation of a list-like type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonRep {
    Single,
    List,
}

macro_rules! define_list_like_type {
    ($list_like_type:ident) => {
        /// $llt allows a JSON field to be represented as the element itself (equivalent to a list of 1 item) or as s
        /// list of elements.

        pub struct $list_like_type<E> {
            elements: ::std::vec::Vec<E>,
            kind: $crate::serutil::JsonRep,
        }

        impl<E> $list_like_type<E> {
            /// Returns the JSON representation of the list.
            #[inline]
            pub fn kind(&self) -> $crate::serutil::JsonRep {
                self.kind
            }

            /// Returns the elements of the list as a slice.
            #[inline]
            pub fn as_slice(&self) -> &[E] {
                self.elements.as_slice()
            }

            /// Returns the elements of the list as a vector of references.
            pub fn to_vec(&self) -> Vec<&E> {
                let mut result = ::std::vec::Vec::with_capacity(self.elements.len());
                for element in self.elements.iter() {
                    result.push(element);
                }
                result
            }

            /// Returns `true` if the list is empty.
            #[inline]
            pub fn is_empty(&self) -> bool {
                self.elements.is_empty()
            }

            /// Returns the number of elements in the list.
            #[inline]
            pub fn len(&self) -> usize {
                self.elements.len()
            }
        }

        impl<E> ::std::clone::Clone for $list_like_type<E>
        where
            E: ::std::clone::Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    elements: self.elements.clone(),
                    kind: self.kind,
                }
            }
        }

        impl<E> ::std::fmt::Debug for $list_like_type<E>
        where
            E: ::std::fmt::Debug,
        {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match self.kind {
                    $crate::serutil::JsonRep::Single => (&self.elements[0] as &dyn ::std::fmt::Debug).fmt(f),
                    $crate::serutil::JsonRep::List => (&self.elements as &dyn ::std::fmt::Debug).fmt(f),
                }
            }
        }

        impl<E> ::std::cmp::PartialEq for $list_like_type<E>
        where
            E: ::std::cmp::PartialEq,
        {
            fn eq(&self, other: &Self) -> bool {
                self.elements == other.elements
            }
        }

        impl<E> ::std::cmp::Eq for $list_like_type<E> where E: ::std::cmp::Eq {}

        impl<E> ::std::convert::From<E> for $list_like_type<E> {
            fn from(v: E) -> Self {
                Self {
                    elements: vec![v],
                    kind: $crate::serutil::JsonRep::Single,
                }
            }
        }

        impl<E> ::std::convert::From<Vec<E>> for $list_like_type<E> {
            fn from(v: ::std::vec::Vec<E>) -> Self {
                Self {
                    elements: v,
                    kind: $crate::serutil::JsonRep::List,
                }
            }
        }

        impl<E, I> ::std::ops::Index<I> for $list_like_type<E>
        where
            I: ::std::slice::SliceIndex<[E]>,
        {
            type Output = <I as ::std::slice::SliceIndex<[E]>>::Output;

            fn index(&self, index: I) -> &<::std::vec::Vec<E> as ::std::ops::Index<I>>::Output {
                self.elements.index(index)
            }
        }

        impl<E> ::std::ops::Deref for $list_like_type<E> {
            type Target = [E];

            fn deref(&self) -> &[E] {
                self.elements.deref()
            }
        }
    };
}

define_list_like_type!(MapList);

struct MapListVisitor<E> {
    phantom: PhantomData<E>,
}

impl<'de, E: Deserialize<'de>> Visitor<'de> for MapListVisitor<E> {
    type Value = MapList<E>;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        let tn = simple_type_name::<E>();
        write!(f, "{} or list of {}", tn, tn)
    }

    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        let el = E::deserialize(MapAccessDeserializer::new(access))?;
        Ok(MapList {
            elements: vec![el],
            kind: JsonRep::Single,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut result: Vec<E> = match access.size_hint() {
            None => Vec::new(),
            Some(size) => Vec::with_capacity(size),
        };

        while let Some(item) = access.next_element::<E>()? {
            result.push(item);
        }

        Ok(MapList {
            elements: result,
            kind: JsonRep::List,
        })
    }
}

impl<E: Serialize> Display for MapList<E> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let buf = Vec::new();
        let serde_formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(buf, serde_formatter);
        match self.serialize(&mut ser) {
            Ok(()) => (),
            Err(e) => {
                error!("Failed to serialize: {}", e);
                return Err(FmtError {});
            }
        };
        match from_utf8(&ser.into_inner()) {
            Ok(s) => f.write_str(s),
            Err(e) => {
                error!("JSON serialization contained non-UTF-8 characters: {}", e);
                Err(FmtError {})
            }
        }
    }
}

impl<'de, E: Deserialize<'de>> Deserialize<'de> for MapList<E> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(MapListVisitor {
            phantom: PhantomData,
        })
    }
}

impl<E: Serialize> Serialize for MapList<E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.kind {
            JsonRep::Single => self.elements[0].serialize(serializer),
            JsonRep::List => {
                let mut seq = serializer.serialize_seq(Some(self.elements.len()))?;
                for e in &self.elements {
                    seq.serialize_element(e)?;
                }
                seq.end()
            }
        }
    }
}

define_list_like_type!(StringLikeList);

struct StringListVisitor<T> {
    _phantom: PhantomData<T>,
}

impl<'de, T> Visitor<'de> for StringListVisitor<T>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    type Value = StringLikeList<T>;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        let tn = simple_type_name::<T>();
        write!(f, "{} or list of {}", tn, tn)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        let deserializer = SeqAccessDeserializer::new(access);
        match Vec::<String>::deserialize(deserializer) {
            Ok(l) => {
                let mut result = Vec::with_capacity(l.len());
                for e in &l {
                    match T::from_str(e) {
                        Ok(s) => result.push(s),
                        Err(e) => return Err(de::Error::custom(e)),
                    }
                }
                Ok(StringLikeList {
                    elements: result,
                    kind: JsonRep::List,
                })
            }
            Err(e) => {
                debug!("Failed to deserialize string list: {:?}", e);
                Err(<A::Error as de::Error>::invalid_value(Unexpected::Seq, &self))
            }
        }
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        match T::from_str(v) {
            Ok(s) => Ok(StringLikeList {
                elements: vec![s],
                kind: JsonRep::Single,
            }),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}

impl<E: ToString> Display for StringLikeList<E> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let buf = Vec::new();
        let serde_formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(buf, serde_formatter);
        match self.serialize(&mut ser) {
            Ok(()) => (),
            Err(e) => {
                error!("Failed to serialize: {}", e);
                return Err(FmtError {});
            }
        };
        match from_utf8(&ser.into_inner()) {
            Ok(s) => f.write_str(s),
            Err(e) => {
                error!("JSON serialization contained non-UTF-8 characters: {}", e);
                Err(FmtError {})
            }
        }
    }
}

impl<'de, T> Deserialize<'de> for StringLikeList<T>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StringListVisitor {
            _phantom: PhantomData,
        })
    }
}

impl<T> Serialize for StringLikeList<T>
where
    T: ToString,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.kind {
            JsonRep::Single => {
                let s = self.elements[0].to_string();
                s.serialize(serializer)
            }
            JsonRep::List => {
                let mut seq = Vec::with_capacity(self.elements.len());
                for e in &self.elements {
                    let s = e.to_string();
                    seq.push(s);
                }
                seq.serialize(serializer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{simple_type_name, JsonRep, MapList},
        crate::display_json,
        indoc::indoc,
        serde::{ser::Serializer, Deserialize, Serialize},
        std::panic::catch_unwind,
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SimpleMap {
        pub value: u32,
    }

    #[test_log::test]
    fn test_basic_ops() {
        let map1 = SimpleMap {
            value: 42,
        };

        let map2 = SimpleMap {
            value: 43,
        };

        let el1a: MapList<SimpleMap> = map1.clone().into();
        let el1b: MapList<SimpleMap> = vec![map1.clone()].into();
        let el2a: MapList<SimpleMap> = vec![map1.clone(), map2.clone()].into();
        let el2b: MapList<SimpleMap> = vec![map1.clone(), map2].into();
        let el3: MapList<SimpleMap> = vec![].into();
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

        assert_eq!(
            format!("{}", el1a),
            indoc! { r#"
            {
                "value": 42
            }"#}
        );
        assert_eq!(
            format!("{}", el1b),
            indoc! { r#"
            [
                {
                    "value": 42
                }
            ]"#}
        );
        assert_eq!(
            format!("{}", el2a),
            indoc! { r#"
            [
                {
                    "value": 42
                },
                {
                    "value": 43
                }
            ]"# }
        );

        assert_eq!(el1a[0].value, 42);
        assert_eq!(el1b[0].value, 42);
        let e = catch_unwind(|| {
            let new_el: MapList<SimpleMap> = map1.clone().into();
            println!("This won't print: {:?}", &new_el[1]);
        })
        .unwrap_err();
        assert_eq!(*e.downcast::<String>().unwrap(), "index out of bounds: the len is 1 but the index is 1");
    }

    #[derive(Clone, Debug)]
    struct SerBadUtf8 {}
    const BAD_UTF8: [u8; 3] = [0xc3, 0xc3, 0xc3];

    impl Serialize for SerBadUtf8 {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let s = unsafe { String::from_utf8_unchecked(BAD_UTF8.to_vec()) };
            serializer.serialize_str(&s)
        }
    }

    display_json!(SerBadUtf8);

    #[test_log::test]
    fn test_ser_fail() {
        let el: MapList<SerBadUtf8> = vec![SerBadUtf8 {}].into();
        let e = catch_unwind(|| format!("{}", el)).unwrap_err();
        let e2 = e.downcast::<String>().unwrap();
        assert!((*e2).contains("a formatting trait implementation returned an error"));

        let e = catch_unwind(|| format!("{}", el)).unwrap_err();
        let e2 = e.downcast::<String>().unwrap();
        assert!((*e2).contains("a formatting trait implementation returned an error"));
    }

    #[test_log::test]
    fn test_simple_type_name() {
        assert_eq!(simple_type_name::<u32>(), "u32");
        assert_eq!(simple_type_name::<Option<u32>>(), "u32");
    }

    #[test_log::test]
    fn test_list_kind() {
        assert_eq!(JsonRep::Single, JsonRep::Single.clone());
        assert_eq!(JsonRep::List, JsonRep::List.clone());
        assert_ne!(JsonRep::Single, JsonRep::List);
        assert_eq!(format!("{:?}", JsonRep::Single), "Single");
        assert_eq!(format!("{:?}", JsonRep::List), "List");
    }
}
