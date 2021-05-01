/// Return the basic type name, stripped of any crates.
pub(crate) fn basic_type_name<T>() -> &'static str {
    let tn = std::any::type_name::<T>();
    match tn.rsplit_once("::") {
        Some((_, basic)) => basic,
        None => tn,
    }
}

/// Implement Display for a given class by formatting it as pretty-printed JSON.
macro_rules! display_json {
    ($cls:ident) => {
        impl Display for $cls {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                let buf = Vec::new();
                let serde_formatter = ::serde_json::ser::PrettyFormatter::with_indent(b"    ");
                let mut ser = ::serde_json::Serializer::with_formatter(buf, serde_formatter);
                match self.serialize(&mut ser) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to serialize {}: {:?}", crate::macros::basic_type_name::<Self>(), e);
                        return Err(FmtError);
                    }
                };
                match from_utf8(&ser.into_inner()) {
                    Ok(s) => write!(f, "{}", s),
                    Err(e) => {
                        error!("JSON serialization of {} contained non-UTF-8 characters: {:?}", crate::macros::basic_type_name::<Self>(), e);
                        Err(FmtError)
                    }
                }
            }
        }
    }
}

/// Implement FromStr for a given class by parsing it as JSON.
macro_rules! from_str_json {
    ($cls:ident) => {
        impl FromStr for $cls {
            type Err = ::serde_json::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match ::serde_json::from_str::<Self>(s) {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        debug!("Failed to parse policy: {}: {:?}", s, e);
                        Err(e)
                    }
                }
            }
        }
    };
}

// macro_rules! create_list_enum {
//     ($list:ident, $visitor:ident, $final:ident) => {
//         #[derive(Debug, PartialEq)]
//         pub enum $list {
//             Single($final),
//             List(std::vec::Vec<$final>),
//         }

//         struct $visitor {}
//         impl<'de> ::serde::de::Visitor<'de> for $visitor {
//             type Value = $list;

//             fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
//                 write!(f, "{} or list of {}", crate::macros::basic_type_name::<$final>(), crate::macros::basic_type_name::<$final>())
//             }

//             fn visit_map<A>(self, access: A) -> Result<Self::Value, A::Error>
//             where
//                 A: ::serde::de::MapAccess<'de>
//             {
//                 let deserializer = ::serde::de::value::MapAccessDeserializer::new(access);
//                 let value = match $final::deserialize(deserializer) {
//                     Ok(value) => value,
//                     Err(e) => {
//                         ::log::debug!("Failed to deserialize {}: {:?}", crate::macros::basic_type_name::<$final>(), e);
//                         return Err(<A::Error as ::serde::de::Error>::invalid_value(::serde::de::Unexpected::Map, &self));
//                     }
//                 };
//                 Ok($list::Single(value))
//             }

//             fn visit_seq<A>(self, access: A) -> Result<Self::Value, A::Error>
//             where
//                 A: ::serde::de::SeqAccess<'de>
//             {
//                 let deserializer = ::serde::de::value::SeqAccessDeserializer::new(access);
//                 let value = match ::std::vec::Vec::<$final>::deserialize(deserializer) {
//                     Ok(l) => l,
//                     Err(e) => {
//                         ::log::debug!("Failed to deserialize {} list: {:?}", crate::macros::basic_type_name::<$final>(), e);
//                         return Err(<A::Error as ::serde::de::Error>::invalid_value(::serde::de::Unexpected::Seq, &self));
//                     }
//                 };
//                 Ok($list::List(value))
//             }
//         }

//         impl<'de> ::serde::de::Deserialize<'de> for $list {
//             fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//             where
//                 D: ::serde::de::Deserializer<'de>
//             {
//                 deserializer.deserialize_any($visitor {})
//             }
//         }

//         impl ::serde::ser::Serialize for $list {
//             fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//             where
//                 S: ::serde::ser::Serializer
//             {
//                 match self {
//                     Self::Single(v) => v.serialize(serializer),
//                     Self::List(v) => v.serialize(serializer),
//                 }
//             }
//         }
//     }
// }
