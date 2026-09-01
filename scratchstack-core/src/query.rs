//! Deserialization of AWS query-protocol request parameters.
//!
//! The AWS query protocol flattens structured request parameters into
//! `application/x-www-form-urlencoded` key/value pairs: nested structure members are joined with
//! `.`, and list entries are addressed through a `member` segment and a 1-based index. For
//! example, the request:
//!
//! ```text
//! RoleArn=arn:aws:iam::123456789012:role/Example&PolicyArns.member.1.arn=arn:aws:iam::123456789012:policy/P
//! ```
//!
//! carries a scalar `RoleArn` member and a `PolicyArns` list whose first element is a structure
//! with an `arn` member. `from_query_str` rebuilds the parameter tree from the flattened form
//! and drives a [`serde`] deserializer over it, so request shapes can be deserialized directly
//! from a query string or form-encoded request body.
//!
//! Absent list members deserialize as empty lists and absent optional members as `None`, matching
//! how the protocol omits empty collections entirely. When the same parameter appears more than
//! once, the last occurrence wins; this lets callers concatenate the query string and request
//! body (in that order) and obtain the AWS behavior of body parameters overriding query
//! parameters.

use {
    serde::de::{
        self, DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor, value::StrDeserializer,
    },
    std::{
        collections::{BTreeMap, btree_map::Entry},
        error::Error as StdError,
        fmt::{Display, Formatter, Result as FmtResult},
        vec::IntoIter as VecIntoIter,
    },
};

/// Prefix marking a [`QueryError`] message that already names the parameter at fault.
const PARAMETER_PREFIX: &str = "parameter ";

/// An error encountered while deserializing query-protocol parameters.
///
/// The message is intended for the caller of the API: it names the offending parameter but never echoes parameter
/// values back, so an error may be reported to the caller without leaking a credential or other sensitive input that
/// happened to be malformed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryError(String);

/// A node in the parameter tree rebuilt from the flattened query parameters.
#[derive(Debug)]
enum Node {
    /// An interior node: a structure or list addressed by further `.`-separated segments.
    Map(BTreeMap<String, Node>),

    /// A leaf node holding a (URL-decoded) parameter value.
    Value(String),
}

/// A deserializer for a struct field that has no corresponding parameter.
///
/// Lists deserialize as empty and options as `None`; anything else reports the field as missing,
/// mirroring the error `serde` itself produces for a field that is never seen.
struct AbsentFieldDeserializer(&'static str);

/// Deserializer over a [`Node`].
struct NodeDeserializer<'a>(&'a Node);

/// [`MapAccess`] implementation over a [`Node::Map`]'s entries.
///
/// When the target type's field names are known (i.e. [`Deserializer::deserialize_struct`]),
/// fields without a corresponding entry are still surfaced, backed by
/// [`AbsentFieldDeserializer`], so lists and options default correctly.
struct NodeMapAccess<'a> {
    /// Expected field names with no corresponding entry, in reverse order (popped from the back).
    absent: Vec<&'static str>,

    /// The present entries remaining to be visited.
    entries: VecIntoIter<(&'a str, &'a Node)>,

    /// The value for the most recently yielded key.
    pending: Option<PendingValue<'a>>,
}

/// [`SeqAccess`] implementation over a list's elements, ordered by index.
struct NodeSeqAccess<'a> {
    /// The elements remaining to be visited, each with the 1-based index it was addressed by.
    elements: VecIntoIter<(u32, &'a Node)>,
}

/// The value companion to the key most recently yielded by [`NodeMapAccess`].
enum PendingValue<'a> {
    /// The field had no corresponding parameter.
    Absent(&'static str),

    /// The field is present in the parameter tree, under the given key.
    Present(&'a str, &'a Node),
}

/// Deserialize a value from AWS query-protocol parameters.
///
/// `query` is the still-URL-encoded parameter string: a query string, a form-encoded request
/// body, or the two joined with `&` (with the body last, so its parameters win).
pub fn from_query_str<T: DeserializeOwned>(query: &str) -> Result<T, QueryError> {
    let mut root = BTreeMap::new();

    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        insert(&mut root, &key, value.into_owned())?;
    }

    T::deserialize(NodeDeserializer(&Node::Map(root)))
}

/// Insert a single decoded key/value pair into the parameter tree.
fn insert(root: &mut BTreeMap<String, Node>, key: &str, value: String) -> Result<(), QueryError> {
    let mut segments: Vec<&str> = key.split('.').collect();
    let last = segments.pop().expect("split always yields at least one segment");

    let mut current = root;
    for segment in segments {
        match current.entry(segment.to_string()).or_insert_with(|| Node::Map(BTreeMap::new())) {
            Node::Map(map) => current = map,
            Node::Value(_) => {
                return Err(de::Error::custom(format_args!(
                    "parameter {key} conflicts with a scalar parameter at {segment}"
                )));
            }
        }
    }

    match current.entry(last.to_string()) {
        Entry::Occupied(mut entry) => match entry.get_mut() {
            // The last occurrence of a repeated parameter wins.
            Node::Value(existing) => *existing = value,
            Node::Map(_) => {
                return Err(de::Error::custom(format_args!("parameter {key} conflicts with a structured parameter")));
            }
        },
        Entry::Vacant(entry) => {
            entry.insert(Node::Value(value));
        }
    }

    Ok(())
}

impl QueryError {
    /// Attribute this error to a parameter, or extend the name it already carries.
    ///
    /// Deserializing a structure walks its members through nested [`NodeMapAccess`] and [`NodeSeqAccess`] instances,
    /// so an inner failure passes through every enclosing member on the way out. Each prepends its own segment,
    /// rebuilding the dotted parameter name the caller actually sent.
    fn in_parameter(self, segment: &str) -> Self {
        match self.0.strip_prefix(PARAMETER_PREFIX) {
            Some(rest) => Self(format!("{PARAMETER_PREFIX}{segment}.{rest}")),
            None => Self(format!("{PARAMETER_PREFIX}{segment}: {}", self.0)),
        }
    }
}

impl Display for QueryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&self.0)
    }
}

impl StdError for QueryError {}

impl de::Error for QueryError {
    fn custom<T: Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

impl Node {
    /// Returns the scalar value of this node, or an error naming the expected type otherwise.
    fn value(&self, expected: &str) -> Result<&str, QueryError> {
        match self {
            Node::Map(_) => Err(de::Error::custom(format_args!("expected {expected}, found a structured parameter"))),
            Node::Value(value) => Ok(value),
        }
    }
}

/// Implement a `Deserializer` method for a scalar type by parsing the node's value with
/// [`FromStr`][std::str::FromStr].
macro_rules! deserialize_parsed_scalar {
    ($method:ident, $visit:ident, $type:ty, $expected:literal) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
            let value = self.0.value($expected)?;
            match value.parse::<$type>() {
                Ok(parsed) => visitor.$visit(parsed),
                Err(_) => Err(de::Error::custom(concat!("invalid value, expected ", $expected))),
            }
        }
    };
}

impl<'de> Deserializer<'de> for NodeDeserializer<'_> {
    type Error = QueryError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        match self.0 {
            Node::Map(_) => self.deserialize_map(visitor),
            Node::Value(value) => visitor.visit_str(value),
        }
    }

    deserialize_parsed_scalar!(deserialize_bool, visit_bool, bool, "a boolean");
    deserialize_parsed_scalar!(deserialize_f32, visit_f32, f32, "a number");
    deserialize_parsed_scalar!(deserialize_f64, visit_f64, f64, "a number");
    deserialize_parsed_scalar!(deserialize_i8, visit_i8, i8, "an integer");
    deserialize_parsed_scalar!(deserialize_i16, visit_i16, i16, "an integer");
    deserialize_parsed_scalar!(deserialize_i32, visit_i32, i32, "an integer");
    deserialize_parsed_scalar!(deserialize_i64, visit_i64, i64, "an integer");
    deserialize_parsed_scalar!(deserialize_u8, visit_u8, u8, "an integer");
    deserialize_parsed_scalar!(deserialize_u16, visit_u16, u16, "an integer");
    deserialize_parsed_scalar!(deserialize_u32, visit_u32, u32, "an integer");
    deserialize_parsed_scalar!(deserialize_u64, visit_u64, u64, "an integer");
    deserialize_parsed_scalar!(deserialize_char, visit_char, char, "a single character");

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_str(self.0.value("a string")?)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_bytes(self.0.value("bytes")?.as_bytes())
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, QueryError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        let Node::Map(map) = self.0 else {
            return Err(de::Error::custom("expected a list, found a scalar parameter"));
        };

        // Lists normally arrive wrapped in a `member` segment (`List.member.1`); accept the
        // unwrapped (flattened) form as well.
        let entries = match map.get("member") {
            Some(Node::Map(inner)) if map.len() == 1 => inner,
            _ => map,
        };

        let mut elements: Vec<(u32, &Node)> = Vec::with_capacity(entries.len());
        for (key, node) in entries {
            let Ok(index) = key.parse::<u32>() else {
                return Err(de::Error::custom(format_args!("invalid list index {key}")));
            };
            elements.push((index, node));
        }

        elements.sort_by_key(|(index, _)| *index);

        visitor.visit_seq(NodeSeqAccess {
            elements: elements.into_iter(),
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, QueryError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, QueryError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        let Node::Map(map) = self.0 else {
            return Err(de::Error::custom("expected a structure, found a scalar parameter"));
        };

        visitor.visit_map(NodeMapAccess {
            absent: Vec::new(),
            entries: map.iter().map(|(key, node)| (key.as_str(), node)).collect::<Vec<_>>().into_iter(),
            pending: None,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, QueryError> {
        let Node::Map(map) = self.0 else {
            return Err(de::Error::custom("expected a structure, found a scalar parameter"));
        };

        // Reversed so NodeMapAccess can pop the absent fields in declaration order.
        let absent: Vec<&'static str> =
            fields.iter().rev().filter(|field| !map.contains_key(**field)).copied().collect();

        visitor.visit_map(NodeMapAccess {
            absent,
            entries: map.iter().map(|(key, node)| (key.as_str(), node)).collect::<Vec<_>>().into_iter(),
            pending: None,
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, QueryError> {
        visitor.visit_enum(StrDeserializer::new(self.0.value("an enumerated value")?))
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_unit()
    }
}

impl<'de> MapAccess<'de> for NodeMapAccess<'_> {
    type Error = QueryError;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, QueryError> {
        if let Some((key, node)) = self.entries.next() {
            self.pending = Some(PendingValue::Present(key, node));
            return seed.deserialize(StrDeserializer::new(key)).map(Some);
        }

        if let Some(field) = self.absent.pop() {
            self.pending = Some(PendingValue::Absent(field));
            return seed.deserialize(StrDeserializer::new(field)).map(Some);
        }

        Ok(None)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, QueryError> {
        match self.pending.take().expect("next_value_seed called before next_key_seed") {
            PendingValue::Absent(field) => seed.deserialize(AbsentFieldDeserializer(field)),
            // Name the parameter the failure came from. Nested failures are already named by the
            // inner map, so only add this parameter's own name when nothing has named one yet.
            PendingValue::Present(key, node) => {
                seed.deserialize(NodeDeserializer(node)).map_err(|err| err.in_parameter(key))
            }
        }
    }
}

impl<'de> SeqAccess<'de> for NodeSeqAccess<'_> {
    type Error = QueryError;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, QueryError> {
        match self.elements.next() {
            None => Ok(None),
            Some((index, node)) => seed
                .deserialize(NodeDeserializer(node))
                .map_err(|err| err.in_parameter(&format!("member.{index}")))
                .map(Some),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.elements.len())
    }
}

impl<'de> Deserializer<'de> for AbsentFieldDeserializer {
    type Error = QueryError;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, QueryError> {
        Err(de::Error::missing_field(self.0))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_none()
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_seq(NodeSeqAccess {
            elements: Vec::new().into_iter(),
        })
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, QueryError> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf unit unit_struct
        newtype_struct tuple tuple_struct map struct enum identifier
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{QueryError, from_query_str},
        pretty_assertions::assert_eq,
        serde::Deserialize,
    };

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct PolicyDescriptor {
        #[serde(rename = "arn")]
        arn: Option<String>,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Tag {
        #[serde(rename = "Key")]
        key: String,

        #[serde(rename = "Value")]
        value: String,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct AssumeRoleLikeRequest {
        #[serde(rename = "DurationSeconds")]
        duration_seconds: Option<i32>,

        #[serde(rename = "PolicyArns")]
        policy_arns: Vec<PolicyDescriptor>,

        #[serde(rename = "RoleArn")]
        role_arn: String,

        #[serde(rename = "Tags")]
        tags: Vec<Tag>,

        #[serde(rename = "TransitiveTagKeys")]
        transitive_tag_keys: Vec<String>,
    }

    #[test_log::test]
    fn test_scalars_only() {
        let request: AssumeRoleLikeRequest = from_query_str(
            "Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FExample",
        )
        .expect("deserialization failed");

        assert_eq!(request.role_arn, "arn:aws:iam::123456789012:role/Example");
        assert_eq!(request.duration_seconds, None);
        assert!(request.policy_arns.is_empty());
        assert!(request.tags.is_empty());
        assert!(request.transitive_tag_keys.is_empty());
    }

    #[test_log::test]
    fn test_nested_lists() {
        let request: AssumeRoleLikeRequest = from_query_str(
            "RoleArn=arn:aws:iam::123456789012:role/Example&DurationSeconds=900\
             &PolicyArns.member.1.arn=arn:aws:iam::123456789012:policy/P1\
             &PolicyArns.member.2.arn=arn:aws:iam::123456789012:policy/P2\
             &Tags.member.1.Key=Project&Tags.member.1.Value=scratchstack\
             &TransitiveTagKeys.member.1=Project",
        )
        .expect("deserialization failed");

        assert_eq!(request.duration_seconds, Some(900));
        assert_eq!(
            request.policy_arns,
            vec![
                PolicyDescriptor {
                    arn: Some("arn:aws:iam::123456789012:policy/P1".to_string())
                },
                PolicyDescriptor {
                    arn: Some("arn:aws:iam::123456789012:policy/P2".to_string())
                },
            ]
        );
        assert_eq!(
            request.tags,
            vec![Tag {
                key: "Project".to_string(),
                value: "scratchstack".to_string(),
            }]
        );
        assert_eq!(request.transitive_tag_keys, vec!["Project".to_string()]);
    }

    /// List indices define ordering (not their lexical order in the parameter string) and need
    /// not be contiguous.
    #[test_log::test]
    fn test_list_index_ordering() {
        let request: AssumeRoleLikeRequest = from_query_str(
            "RoleArn=x&TransitiveTagKeys.member.10=third&TransitiveTagKeys.member.2=second\
             &TransitiveTagKeys.member.1=first",
        )
        .expect("deserialization failed");

        assert_eq!(request.transitive_tag_keys, vec!["first".to_string(), "second".to_string(), "third".to_string()]);
    }

    /// The last occurrence of a repeated parameter wins, matching the query-string-then-body
    /// parameter joining performed by the services.
    #[test_log::test]
    fn test_last_duplicate_wins() {
        let request: AssumeRoleLikeRequest =
            from_query_str("RoleArn=first&RoleArn=second").expect("deserialization failed");
        assert_eq!(request.role_arn, "second");
    }

    #[test_log::test]
    fn test_missing_required_field() {
        let err = from_query_str::<AssumeRoleLikeRequest>("DurationSeconds=900").expect_err("expected an error");
        assert!(err.to_string().contains("RoleArn"), "unexpected error: {err}");
    }

    #[test_log::test]
    fn test_invalid_integer() {
        let err =
            from_query_str::<AssumeRoleLikeRequest>("RoleArn=x&DurationSeconds=abc").expect_err("expected an error");
        assert_eq!(err.to_string(), "parameter DurationSeconds: invalid value, expected an integer");
    }

    #[test_log::test]
    fn test_errors_name_the_parameter_path() {
        // The name in the message is the dotted name the caller sent, rebuilt as the error passes
        // back out through each enclosing structure and list.
        let err = from_query_str::<AssumeRoleLikeRequest>(
            "RoleArn=x&Tags.member.2.Key=K&Tags.member.2.Value=V&Tags.member.1=oops",
        )
        .expect_err("expected an error");
        assert_eq!(err.to_string(), "parameter Tags.member.1: expected a structure, found a scalar parameter");

        let err = from_query_str::<AssumeRoleLikeRequest>("RoleArn=x&PolicyArns.member.1.arn.nested=oops")
            .expect_err("expected an error");
        assert_eq!(
            err.to_string(),
            "parameter PolicyArns.member.1.arn: expected a string, found a structured parameter"
        );
    }

    #[test_log::test]
    fn test_errors_never_echo_values() {
        // Error text reaches the API caller, so a malformed credential must not come back in it.
        for query in [
            "RoleArn=x&DurationSeconds=SUPERSECRET",
            "RoleArn=x&Tags.member.1=SUPERSECRET",
            "RoleArn=x&Tags=SUPERSECRET",
        ] {
            let err = from_query_str::<AssumeRoleLikeRequest>(query).expect_err("expected an error");
            assert!(!err.to_string().contains("SUPERSECRET"), "leaked a value: {err}");
        }
    }

    #[test_log::test]
    fn test_scalar_structure_conflicts() {
        let err = from_query_str::<AssumeRoleLikeRequest>("Tags=oops&Tags.member.1.Key=Project&RoleArn=x")
            .expect_err("expected an error");
        assert!(err.to_string().contains("conflicts"), "unexpected error: {err}");

        let err = from_query_str::<AssumeRoleLikeRequest>("Tags.member.1.Key=Project&Tags=oops&RoleArn=x")
            .expect_err("expected an error");
        assert!(err.to_string().contains("conflicts"), "unexpected error: {err}");

        let err: QueryError =
            from_query_str::<AssumeRoleLikeRequest>("RoleArn=x&Tags=oops").expect_err("expected an error");
        assert!(err.to_string().contains("expected a list"), "unexpected error: {err}");
    }
}
