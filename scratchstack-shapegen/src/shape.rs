use {
    super::{Enum, IntEnum, List, Map, Member, Operation, Resource, Service, Structure, Typed, Union, primitive},
    serde::{Deserialize, Serialize},
    serde_json::Value as JsonValue,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// Smithy shape definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Shape {
    /// The `unit` type in Smithy is similar to `Void` and `None` in other languages. It is used
    /// when the input or output of an operation has no meaningful value or if a union member has no
    /// meaningful value.
    #[serde(rename = "unit")]
    Unit(primitive::Unit),

    /// A `blob` is uninterpreted binary data.
    #[serde(rename = "blob")]
    Blob(primitive::Blob),

    /// A `boolean` is a Boolean value type.
    #[serde(rename = "boolean")]
    Boolean(primitive::Boolean),

    /// A `string` is a UTF-8 encoded string.
    #[serde(rename = "string")]
    String(primitive::String),

    /// A `byte` is an 8-bit signed integer ranging from -128 to 127 (inclusive).
    #[serde(rename = "byte")]
    Byte(primitive::Byte),

    /// A `short` is a 16-bit signed integer ranging from -32,768 to 32,767 (inclusive).
    #[serde(rename = "short")]
    Short(primitive::Short),

    /// An `integer` is a 32-bit signed integer ranging from -2^31 to (2^31)-1 (inclusive).
    #[serde(rename = "integer")]
    Integer(primitive::Integer),

    /// A `long` is a 64-bit signed integer ranging from -2^63 to (2^63)-1 (inclusive).
    #[serde(rename = "long")]
    Long(primitive::Long),

    /// A `float` is a single precision IEEE-754 floating point number.
    #[serde(rename = "float")]
    Float(primitive::Float),

    /// A `double` is a double precision IEEE-754 floating point number.
    #[serde(rename = "double")]
    Double(primitive::Double),

    /// A `bigInteger` is an arbitrarily large signed integer.
    #[serde(rename = "bigInteger")]
    BigInteger(primitive::BigInteger),

    /// A `bigDecimal` is an arbitrary precision signed decimal number.
    #[serde(rename = "bigDecimal")]
    BigDecimal(primitive::BigDecimal),

    /// A `document` represents protocol-agnostic open content that functions as a kind of "any"
    /// type. Document types are represented by a JSON-like data model and can contain UTF-8
    /// strings, arbitrary precision numbers, booleans, nulls, a list of these values, and a map of
    /// UTF-8 strings to these values. Open content is useful for modeling unstructured data that
    /// has no schema, data that can't be modeled using rigid types, or data that has a schema that
    /// evolves outside of the purview of a model. The serialization format of a document is an
    /// implementation detail of a protocol and MUST NOT have any effect on the types exposed by
    /// tooling to represent a document value.
    #[serde(rename = "document")]
    Document,

    /// A `timestamp` represents an instant in time in the proleptic Gregorian calendar, independent
    /// of local times or timezones. Timestamps support an allowable date range between midnight
    /// January 1, 0001 CE to 23:59:59.999 on December 31, 9999 CE, with a temporal resolution of
    /// 1 millisecond. This resolution and range ensures broad support across programming languages
    /// and guarantees compatibility with RFC 3339.
    #[serde(rename = "timestamp")]
    Timestamp(primitive::Timestamp),

    /// The `enum` shape is used to represent a fixed set of one or more string values. Each value
    /// listed in the enum is a member that implicitly targets the unit type.
    #[serde(rename = "enum")]
    Enum(Enum),

    /// An `intEnum` is used to represent an enumerated set of one or more integer values. The members
    /// of intEnum MUST be marked with the enumValue trait set to a unique integer value.
    #[serde(rename = "intEnum")]
    IntEnum(IntEnum),

    /// The `list` type represents an ordered homogeneous collection of values. A list shape requires
    /// a single member named member.
    #[serde(rename = "list")]
    List(List),

    /// The `map` type represents a map data structure that maps string keys to homogeneous values. A
    /// map requires a member named key that MUST target a string shape and a member named value.
    #[serde(rename = "map")]
    Map(Map),

    /// The `structure` type represents a fixed set of named, unordered, heterogeneous values. A
    /// structure shape contains a set of named members, and each member name maps to exactly one
    /// member definition.
    #[serde(rename = "structure")]
    Structure(Structure),

    /// The `union` type represents a tagged union data structure that can take on several different,
    /// but fixed, types. Unions function similarly to structures except that only one member can
    /// be used at any one time. Each member in the union is a variant of the tagged union, where
    /// member names are the tags of each variant, and the shapes targeted by members are the values
    /// of each variant.
    #[serde(rename = "union")]
    Union(Union),

    /// A `service` is the entry point of an API that aggregates resources and operations together.
    /// The resources and operations of an API are bound within the closure of a service.
    #[serde(rename = "service")]
    Service(Service),

    /// The `operation` type represents the input, output, and possible errors of an API operation.
    /// Operation shapes are bound to resource shapes and service shapes.
    #[serde(rename = "operation")]
    Operation(Operation),

    /// A `resource` is an entity with an identity that has a set of operations.
    #[serde(rename = "resource")]
    Resource(Resource),
}

impl Shape {
    /// If this shape has members, returns a mutable reference to the members map. Otherwise, returns None.
    pub fn members_mut(&mut self) -> Option<&mut HashMap<String, Member>> {
        match self {
            Self::Enum(e) => Some(&mut e.members),
            Self::IntEnum(i) => Some(&mut i.members),
            Self::Structure(s) => Some(&mut s.members),
            Self::Union(u) => Some(&mut u.members),
            _ => None,
        }
    }

    /// If this type has traits, returns a mutable reference to the traits map. Otherwise, returns None.
    pub fn traits_mut(&mut self) -> Option<&mut HashMap<String, JsonValue>> {
        match self {
            Self::Unit(u) => Some(&mut u.traits),
            Self::Blob(b) => Some(&mut b.traits),
            Self::Boolean(b) => Some(&mut b.traits),
            Self::String(s) => Some(&mut s.traits),
            Self::Byte(b) => Some(&mut b.traits),
            Self::Short(s) => Some(&mut s.traits),
            Self::Integer(i) => Some(&mut i.traits),
            Self::Long(l) => Some(&mut l.traits),
            Self::Float(f) => Some(&mut f.traits),
            Self::Double(d) => Some(&mut d.traits),
            Self::BigInteger(b) => Some(&mut b.traits),
            Self::BigDecimal(b) => Some(&mut b.traits),
            Self::Document => None,
            Self::Timestamp(t) => Some(&mut t.traits),
            Self::Enum(e) => Some(&mut e.traits),
            Self::IntEnum(i) => Some(&mut i.traits),
            Self::List(l) => Some(&mut l.traits),
            Self::Map(m) => Some(&mut m.traits),
            Self::Structure(s) => Some(&mut s.traits),
            Self::Union(u) => Some(&mut u.traits),
            _ => None,
        }
    }

    /// Returns the inner typed shape; panics if the inner type is not a [`Typed`] shape.
    pub fn inner(&self) -> Option<&dyn Typed> {
        match self {
            Self::Unit(u) => Some(u),
            Self::Blob(b) => Some(b),
            Self::Boolean(b) => Some(b),
            Self::String(s) => Some(s),
            Self::Byte(b) => Some(b),
            Self::Short(s) => Some(s),
            Self::Integer(i) => Some(i),
            Self::Long(l) => Some(l),
            Self::Float(f) => Some(f),
            Self::Double(d) => Some(d),
            Self::BigInteger(b) => Some(b),
            Self::BigDecimal(b) => Some(b),
            Self::Document => unimplemented!("Document type is not supported yet"),
            Self::Timestamp(t) => Some(t),
            Self::Enum(e) => Some(e),
            Self::IntEnum(i) => Some(i),
            Self::List(l) => Some(l),
            Self::Map(m) => Some(m),
            Self::Structure(s) => Some(s),
            Self::Union(u) => Some(u),
            _ => None,
        }
    }

    /// Returns the inner typed shape as mutable; panics if the inner type is not a [`Typed`] shape.
    pub fn inner_mut(&mut self) -> Option<&mut dyn Typed> {
        match self {
            Self::Unit(u) => Some(u),
            Self::Blob(b) => Some(b),
            Self::Boolean(b) => Some(b),
            Self::String(s) => Some(s),
            Self::Byte(b) => Some(b),
            Self::Short(s) => Some(s),
            Self::Integer(i) => Some(i),
            Self::Long(l) => Some(l),
            Self::Float(f) => Some(f),
            Self::Double(d) => Some(d),
            Self::BigInteger(b) => Some(b),
            Self::BigDecimal(b) => Some(b),
            Self::Document => unimplemented!("Document type is not supported yet"),
            Self::Timestamp(t) => Some(t),
            Self::Enum(e) => Some(e),
            Self::IntEnum(i) => Some(i),
            Self::List(l) => Some(l),
            Self::Map(m) => Some(m),
            Self::Structure(s) => Some(s),
            Self::Union(u) => Some(u),
            _ => None,
        }
    }
}

impl Typed for Shape {
    fn rust_typename(&self) -> String {
        self.inner().expect("Shape does not contain a typed inner shape").rust_typename()
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        if let Some(inner) = self.inner() {
            inner.write(output)
        } else {
            Ok(())
        }
    }

    fn has_decl(&self, model: &super::SmithyModel) -> bool {
        if let Some(inner) = self.inner() {
            inner.has_decl(model)
        } else {
            false
        }
    }

    fn is_primitive(&self) -> bool {
        self.inner().expect("Shape does not contain a typed inner shape").is_primitive()
    }

    fn get_clap_parser(&self, option: bool) -> String {
        self.inner().expect("Shape does not contain a typed inner shape").get_clap_parser(option)
    }

    fn get_derive_builder_validator(&self, var: &str) -> Option<String> {
        self.inner().expect("Shape does not contain a typed inner shape").get_derive_builder_validator(var)
    }

    fn mark_reachable_from_input(&mut self) {
        if let Some(inner) = self.inner_mut() {
            inner.mark_reachable_from_input();
        }
    }
}
