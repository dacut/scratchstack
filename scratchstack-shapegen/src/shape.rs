use {
    crate::{
        Enum, IntEnum, List, Map, Member, Operation, Resource, Service, ShapeInfo, SmithyModel, Structure, TraitMap,
        Union, primitive,
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
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
    Unit(primitive::SmithyUnit),

    /// A `blob` is uninterpreted binary data.
    #[serde(rename = "blob")]
    Blob(primitive::SmithyBlob),

    /// A `boolean` is a Boolean value type.
    #[serde(rename = "boolean")]
    Boolean(primitive::SmithyBoolean),

    /// A `bigInteger` is an arbitrarily large signed integer.
    #[serde(rename = "bigInteger")]
    BigInteger(primitive::SmithyBigInteger),

    /// A `bigDecimal` is an arbitrary precision signed decimal number.
    #[serde(rename = "bigDecimal")]
    BigDecimal(primitive::SmithyBigDecimal),

    /// A `string` is a UTF-8 encoded string.
    #[serde(rename = "string")]
    String(primitive::SmithyString),

    /// A `timestamp` represents an instant in time in the proleptic Gregorian calendar, independent
    /// of local times or timezones. Timestamps support an allowable date range between midnight
    /// January 1, 0001 CE to 23:59:59.999 on December 31, 9999 CE, with a temporal resolution of
    /// 1 millisecond. This resolution and range ensures broad support across programming languages
    /// and guarantees compatibility with RFC 3339.
    #[serde(rename = "timestamp")]
    Timestamp(primitive::SmithyTimestamp),

    /// A `byte` is an 8-bit signed integer ranging from -128 to 127 (inclusive).
    #[serde(rename = "byte")]
    Byte(primitive::SmithyByte),

    /// A `short` is a 16-bit signed integer ranging from -32,768 to 32,767 (inclusive).
    #[serde(rename = "short")]
    Short(primitive::SmithyShort),

    /// An `integer` is a 32-bit signed integer ranging from -2^31 to (2^31)-1 (inclusive).
    #[serde(rename = "integer")]
    Integer(primitive::SmithyInteger),

    /// A `long` is a 64-bit signed integer ranging from -2^63 to (2^63)-1 (inclusive).
    #[serde(rename = "long")]
    Long(primitive::SmithyLong),

    /// A `float` is a single precision IEEE-754 floating point number.
    #[serde(rename = "float")]
    Float(primitive::SmithyFloat),

    /// A `double` is a double precision IEEE-754 floating point number.
    #[serde(rename = "double")]
    Double(primitive::SmithyDouble),

    /// A `document` represents protocol-agnostic open content that functions as a kind of "any"
    /// type. Document types are represented by a JSON-like data model and can contain UTF-8
    /// strings, arbitrary precision numbers, booleans, nulls, a list of these values, and a map of
    /// UTF-8 strings to these values. Open content is useful for modeling unstructured data that
    /// has no schema, data that can't be modeled using rigid types, or data that has a schema that
    /// evolves outside of the purview of a model. The serialization format of a document is an
    /// implementation detail of a protocol and MUST NOT have any effect on the types exposed by
    /// tooling to represent a document value.
    #[serde(rename = "document")]
    Document(primitive::SmithyDocument),

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

macro_rules! unwrap_inner {
    ($self:ident) => {
        match $self {
            Self::Unit(u) => u,
            Self::Blob(b) => b,
            Self::Boolean(b) => b,
            Self::String(s) => s,
            Self::Byte(b) => b,
            Self::Short(s) => s,
            Self::Integer(i) => i,
            Self::Long(l) => l,
            Self::Float(f) => f,
            Self::Double(d) => d,
            Self::BigInteger(b) => b,
            Self::BigDecimal(b) => b,
            Self::Document(d) => d,
            Self::Timestamp(t) => t,
            Self::Enum(e) => e,
            Self::IntEnum(i) => i,
            Self::List(l) => l,
            Self::Map(m) => m,
            Self::Structure(s) => s,
            Self::Union(u) => u,
            Self::Service(s) => s,
            Self::Operation(o) => o,
            Self::Resource(r) => r,
        }
    };

    ($self:ident => &mut $($suffix:tt)+) => {
        match $self {
            Self::Unit(u) => &mut u.$($suffix)+,
            Self::Blob(b) => &mut b.$($suffix)+,
            Self::Boolean(b) => &mut b.$($suffix)+,
            Self::String(s) => &mut s.$($suffix)+,
            Self::Byte(b) => &mut b.$($suffix)+,
            Self::Short(s) => &mut s.$($suffix)+,
            Self::Integer(i) => &mut i.$($suffix)+,
            Self::Long(l) => &mut l.$($suffix)+,
            Self::Float(f) => &mut f.$($suffix)+,
            Self::Double(d) => &mut d.$($suffix)+,
            Self::BigInteger(b) => &mut b.$($suffix)+,
            Self::BigDecimal(b) => &mut b.$($suffix)+,
            Self::Document(d) => &mut d.$($suffix)+,
            Self::Timestamp(t) => &mut t.$($suffix)+,
            Self::Enum(e) => &mut e.$($suffix)+,
            Self::IntEnum(i) => &mut i.$($suffix)+,
            Self::List(l) => &mut l.$($suffix)+,
            Self::Map(m) => &mut m.$($suffix)+,
            Self::Structure(s) => &mut s.$($suffix)+,
            Self::Union(u) => &mut u.$($suffix)+,
            Self::Service(s) => &mut s.$($suffix)+,
            Self::Operation(o) => &mut o.$($suffix)+,
            Self::Resource(r) => &mut r.$($suffix)+,
        }
    };

    ($self:ident => $($suffix:tt)+) => {
        match $self {
            Self::Unit(u) => u.$($suffix)+,
            Self::Blob(b) => b.$($suffix)+,
            Self::Boolean(b) => b.$($suffix)+,
            Self::String(s) => s.$($suffix)+,
            Self::Byte(b) => b.$($suffix)+,
            Self::Short(s) => s.$($suffix)+,
            Self::Integer(i) => i.$($suffix)+,
            Self::Long(l) => l.$($suffix)+,
            Self::Float(f) => f.$($suffix)+,
            Self::Double(d) => d.$($suffix)+,
            Self::BigInteger(b) => b.$($suffix)+,
            Self::BigDecimal(b) => b.$($suffix)+,
            Self::Document(d) => d.$($suffix)+,
            Self::Timestamp(t) => t.$($suffix)+,
            Self::Enum(e) => e.$($suffix)+,
            Self::IntEnum(i) => i.$($suffix)+,
            Self::List(l) => l.$($suffix)+,
            Self::Map(m) => m.$($suffix)+,
            Self::Structure(s) => s.$($suffix)+,
            Self::Union(u) => u.$($suffix)+,
            Self::Service(s) => s.$($suffix)+,
            Self::Operation(o) => o.$($suffix)+,
            Self::Resource(r) => r.$($suffix)+,
        }
    };
}

impl Shape {
    /// Returns the inner type as a reference to a `dyn ShapeInfo`.
    pub fn as_shape_info(&self) -> &dyn ShapeInfo {
        unwrap_inner!(self)
    }

    /// Returns the inner type as a mutable reference to a `dyn ShapeInfo`.
    pub fn as_shape_info_mut(&mut self) -> &mut dyn ShapeInfo {
        unwrap_inner!(self)
    }
}

impl ShapeInfo for Shape {
    fn resolve(&mut self, smithy_name: &str, model: &SmithyModel) {
        self.as_shape_info_mut().resolve(smithy_name, model)
    }

    #[inline(always)]
    fn smithy_name(&self) -> String {
        self.as_shape_info().smithy_name()
    }

    #[inline(always)]
    fn rust_typename(&self) -> String {
        self.as_shape_info().rust_typename()
    }

    #[inline(always)]
    fn clap_parser(&self) -> Option<String> {
        self.as_shape_info().clap_parser()
    }

    #[inline(always)]
    fn mark_reachable_from_input(&mut self) {
        self.as_shape_info_mut().mark_reachable_from_input()
    }

    #[inline(always)]
    fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
        self.as_shape_info().derive_builder_validator(var, field_name)
    }

    #[inline(always)]
    fn generate(&self, w: &mut dyn Write) -> IoResult<()> {
        self.as_shape_info().generate(w)
    }
}

impl Shape {
    /// If this shape is a list, returns a reference to the underlying list.
    pub fn as_list(&self) -> Option<&List> {
        match self {
            Self::List(l) => Some(l),
            _ => None,
        }
    }

    /// If this shape has members, returns a mutable reference to the members map. Otherwise, returns None.
    pub fn members_mut(&mut self) -> Option<&mut BTreeMap<String, Member>> {
        match self {
            Self::Enum(e) => Some(&mut e.members),
            Self::IntEnum(i) => Some(&mut i.members),
            Self::Structure(s) => Some(&mut s.members),
            Self::Union(u) => Some(&mut u.members),
            _ => None,
        }
    }

    /// If this type has traits, returns a mutable reference to the traits map. Otherwise, returns None.
    pub fn traits_mut(&mut self) -> &mut TraitMap {
        unwrap_inner!(self => &mut base.traits)
    }
}
