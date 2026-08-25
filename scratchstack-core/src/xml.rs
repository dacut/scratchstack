//! Serialization of values as the AWS query protocol's XML.
//!
//! The query protocol spells collections in a way serde renders on its own for no format: a list
//! is the field's element wrapping one `<member>` element per value, and a map is the field's
//! element wrapping one `<entry>` element per pair, each holding a `<key>` and a `<value>`.
//!
//! Left alone, serde renders a sequence as the field element repeated once per value, with no
//! wrapper. Two or more values survive that by accident -- a client that iterates the children of
//! the wrapper reads the repeated sibling elements back as the same values -- but a single value
//! does not: the one element is taken for the wrapper, its text is not a child of anything, and
//! the value is dropped. An empty sequence renders as nothing at all, which reads as a missing
//! field rather than an empty one. A map fares worse still, rendering each pair as an element
//! named for its key, which is not a form the protocol describes at all.
//!
//! `QuerySerializer` adapts any serializer so that collections come out in the protocol's form.
//! It wraps the XML serializer at the point a response is rendered, which leaves the shapes
//! themselves serializing as what they are -- the same types serialize to JSON for the bootstrap
//! CLI, and nothing about the XML wire form reaches that.

use {
    serde::{
        Serialize, Serializer,
        ser::{
            Error as SerError, Impossible, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
            SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
        },
    },
    std::{fmt::Display, marker::PhantomData},
};

/// The element wrapping each value of a list.
const MEMBER: &str = "member";

/// The element wrapping each pair of a map, and the elements naming the two halves of a pair.
const ENTRY: &str = "entry";
const KEY: &str = "key";
const VALUE: &str = "value";

/// The struct name a wrapped collection is announced with.
///
/// A serializer that names elements after the fields holding them -- which is what rendering XML
/// from a structure amounts to -- never uses this, since a collection is always a field of
/// something. It stands in only for a collection serialized on its own, with no field to name it.
const COLLECTION: &str = "Collection";

/// A serializer that renders collections as the AWS query protocol spells them, forwarding
/// everything else to the serializer it wraps.
///
/// See the [module documentation](self) for what the protocol asks for and what serde does
/// without this.
pub struct QuerySerializer<S>(S);

/// A value being forwarded to the wrapped serializer, re-entering [`QuerySerializer`] as it is
/// serialized.
///
/// Every composite hands its members to the wrapped serializer through this, so a collection
/// nested anywhere -- a list of structures each carrying lists of their own -- is rendered in the
/// protocol's form at every depth.
struct Adapted<'a, T: ?Sized>(&'a T);

/// A sequence being rendered as one `<member>` element per value.
pub struct QuerySeq<S>(S);

/// A map being rendered as one `<entry>` element per pair.
///
/// A pair reaches a [`SerializeMap`] as two calls, so the key is held here until the value it
/// belongs to arrives and the two can be written as one entry.
pub struct QueryMap<S> {
    inner: S,
    key: Option<String>,
}

/// A structure whose fields are being forwarded to the wrapped serializer.
pub struct QueryStruct<S>(S);

/// A tuple variant whose fields are being forwarded to the wrapped serializer.
pub struct QueryTupleVariant<S>(S);

/// A structure variant whose fields are being forwarded to the wrapped serializer.
pub struct QueryStructVariant<S>(S);

/// One pair of a map: `<key>` and `<value>` inside an `<entry>`.
struct Entry<'a, T: ?Sized> {
    key: &'a str,
    value: &'a T,
}

/// A serializer that renders a map key as the string naming it.
///
/// A key is an element's text, so it has to be a string by the time it is written. The keys these
/// shapes carry are strings and unit-only enums; anything else has no obvious spelling and is
/// refused rather than guessed at.
struct KeySerializer<E>(PhantomData<E>);

impl<S> QuerySerializer<S> {
    /// Adapt `inner` so that collections serialized through it come out in the query protocol's
    /// form.
    pub fn new(inner: S) -> Self {
        Self(inner)
    }
}

impl<T: Serialize + ?Sized> Serialize for Adapted<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(QuerySerializer::new(serializer))
    }
}

impl<T: Serialize + ?Sized> Serialize for Entry<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut entry = serializer.serialize_struct(ENTRY, 2)?;
        entry.serialize_field(KEY, self.key)?;
        entry.serialize_field(VALUE, &Adapted(self.value))?;
        entry.end()
    }
}

/// Forward a scalar method to the wrapped serializer unchanged.
macro_rules! forward_scalar {
    ($method:ident, $type:ty) => {
        fn $method(self, value: $type) -> Result<Self::Ok, Self::Error> {
            self.0.$method(value)
        }
    };
}

impl<S: Serializer> Serializer for QuerySerializer<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = QuerySeq<S::SerializeStruct>;
    type SerializeTuple = QuerySeq<S::SerializeStruct>;
    type SerializeTupleStruct = QuerySeq<S::SerializeStruct>;
    type SerializeTupleVariant = QueryTupleVariant<S::SerializeTupleVariant>;
    type SerializeMap = QueryMap<S::SerializeStruct>;
    type SerializeStruct = QueryStruct<S::SerializeStruct>;
    type SerializeStructVariant = QueryStructVariant<S::SerializeStructVariant>;

    forward_scalar!(serialize_bool, bool);
    forward_scalar!(serialize_i8, i8);
    forward_scalar!(serialize_i16, i16);
    forward_scalar!(serialize_i32, i32);
    forward_scalar!(serialize_i64, i64);
    forward_scalar!(serialize_u8, u8);
    forward_scalar!(serialize_u16, u16);
    forward_scalar!(serialize_u32, u32);
    forward_scalar!(serialize_u64, u64);
    forward_scalar!(serialize_f32, f32);
    forward_scalar!(serialize_f64, f64);
    forward_scalar!(serialize_char, char);
    forward_scalar!(serialize_str, &str);
    forward_scalar!(serialize_bytes, &[u8]);

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_none()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_some(&Adapted(value))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_variant(name, index, variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_newtype_struct(name, &Adapted(value))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_newtype_variant(name, index, variant, &Adapted(value))
    }

    // A sequence becomes a structure with one field per value, all of them named `member`: a
    // serializer naming elements after the fields holding them then writes the wrapper element and
    // its members, and an empty sequence writes the wrapper alone.
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(QuerySeq(self.0.serialize_struct(COLLECTION, len.unwrap_or_default())?))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(QuerySeq(self.0.serialize_struct(COLLECTION, len)?))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(QuerySeq(self.0.serialize_struct(COLLECTION, len)?))
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(QueryTupleVariant(self.0.serialize_tuple_variant(name, index, variant, len)?))
    }

    // A map becomes a structure with one field per pair, all of them named `entry`, each holding
    // the key and the value it belongs to.
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(QueryMap {
            inner: self.0.serialize_struct(COLLECTION, len.unwrap_or_default())?,
            key: None,
        })
    }

    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(QueryStruct(self.0.serialize_struct(name, len)?))
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(QueryStructVariant(self.0.serialize_struct_variant(name, index, variant, len)?))
    }

    fn collect_str<T: Display + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.0.collect_str(value)
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

impl<S: SerializeStruct> SerializeSeq for QuerySeq<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_field(MEMBER, &Adapted(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<S: SerializeStruct> SerializeTuple for QuerySeq<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

impl<S: SerializeStruct> SerializeTupleStruct for QuerySeq<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

impl<S: SerializeTupleVariant> SerializeTupleVariant for QueryTupleVariant<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_field(&Adapted(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<S: SerializeStruct> SerializeMap for QueryMap<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.key = Some(key.serialize(KeySerializer(PhantomData))?);
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self.key.take().ok_or_else(|| SerError::custom("map value serialized before its key"))?;
        self.inner.serialize_field(
            ENTRY,
            &Entry {
                key: &key,
                value,
            },
        )
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}

impl<S: SerializeStruct> SerializeStruct for QueryStruct<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_field(key, &Adapted(value))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.0.skip_field(key)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<S: SerializeStructVariant> SerializeStructVariant for QueryStructVariant<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_field(key, &Adapted(value))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.0.skip_field(key)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

/// Refuse a map key that has no spelling as an element's text.
macro_rules! refuse_key {
    ($method:ident $(, $type:ty)?) => {
        fn $method(self $(, _value: $type)?) -> Result<String, E> {
            Err(SerError::custom("map key must be a string"))
        }
    };
}

/// Render a map key as the string naming it.
macro_rules! key_to_string {
    ($method:ident, $type:ty) => {
        fn $method(self, value: $type) -> Result<String, E> {
            Ok(value.to_string())
        }
    };
}

impl<E: SerError> Serializer for KeySerializer<E> {
    type Ok = String;
    type Error = E;
    type SerializeSeq = Impossible<String, E>;
    type SerializeTuple = Impossible<String, E>;
    type SerializeTupleStruct = Impossible<String, E>;
    type SerializeTupleVariant = Impossible<String, E>;
    type SerializeMap = Impossible<String, E>;
    type SerializeStruct = Impossible<String, E>;
    type SerializeStructVariant = Impossible<String, E>;

    key_to_string!(serialize_bool, bool);
    key_to_string!(serialize_i8, i8);
    key_to_string!(serialize_i16, i16);
    key_to_string!(serialize_i32, i32);
    key_to_string!(serialize_i64, i64);
    key_to_string!(serialize_u8, u8);
    key_to_string!(serialize_u16, u16);
    key_to_string!(serialize_u32, u32);
    key_to_string!(serialize_u64, u64);
    key_to_string!(serialize_f32, f32);
    key_to_string!(serialize_f64, f64);
    key_to_string!(serialize_char, char);
    key_to_string!(serialize_str, &str);

    refuse_key!(serialize_bytes, &[u8]);
    refuse_key!(serialize_none);
    refuse_key!(serialize_unit);
    refuse_key!(serialize_unit_struct, &'static str);

    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, E> {
        Err(SerError::custom("map key must be a string"))
    }

    /// A unit-only enum names its variant, which is what such a key is written as.
    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> Result<String, E> {
        Ok(variant.to_string())
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _name: &'static str, value: &T) -> Result<String, E> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeTupleStruct, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, E> {
        Err(SerError::custom("map key must be a string"))
    }

    fn collect_str<T: Display + ?Sized>(self, value: &T) -> Result<String, E> {
        Ok(value.to_string())
    }
}
