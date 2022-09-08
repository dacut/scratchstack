use std::{
    collections::{
        hash_map::{Drain, Entry, IntoIter, IntoKeys, IntoValues, Iter, IterMut, Keys, Values, ValuesMut},
        HashMap, TryReserveError,
    },
    fmt::{Display, Formatter, Result as FmtResult},
    hash::Hash,
    iter::{Extend, FromIterator, IntoIterator},
    net::IpAddr,
    ops::Index,
    panic::UnwindSafe,
};

/// Associated data about a principal. This is a map of ASCII case-insensitive strings to [SessionValue] values.
///
/// This wraps the standard Rust [HashMap] type, providing the case-insensitive key lookup and setting values to
/// the [SessionValue] type.
#[derive(Clone, Debug)]
pub struct SessionData {
    /// The variables associated with the session with the keys lower-cased.
    variables: HashMap<String, SessionValue>,
}

impl SessionData {
    /// Creates an empty HashMap.
    ///
    /// The underlying hash map is initially created with a capacity of 0, so it will not allocate until it is first
    /// inserted into.
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// Create a new session data object with a pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            variables: HashMap::with_capacity(capacity),
        }
    }

    /// Returns the number of elements the map can hold without reallocating.
    ///
    /// This number is a lower bound; the [SessionData] might be able to hold more, but is guaranteed to be able to
    /// hold at least this many.
    pub fn capacity(&self) -> usize {
        self.variables.capacity()
    }

    /// Clears the map, removing all key-value pairs. Keeps the allocated memory for reuse.
    pub fn clear(&mut self) {
        self.variables.clear();
    }

    /// Returns `true` if the map contains a value for the specified key.
    pub fn contains_key<Q: AsRef<str> + ?Sized>(&self, k: &Q) -> bool {
        self.variables.contains_key(&k.as_ref().to_lowercase())
    }

    /// Clears the map, returning all key-value pairs as an iterator. Keeps the allocated memory for reuse.
    ///
    /// If the returned iterator is dropped before being fully consumed, it drops the remaining key-value pairs. The
    /// returned iterator keeps a mutable borrow on the map to optimize its implementation.
    pub fn drain(&mut self) -> Drain<'_, String, SessionValue> {
        self.variables.drain()
    }

    /// Gets the given key’s corresponding entry in the map for in-place manipulation.
    pub fn entry<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Entry<'_, String, SessionValue> {
        self.variables.entry(key.as_ref().to_lowercase())
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<&SessionValue> {
        self.variables.get(&key.as_ref().to_lowercase())
    }

    /// Returns the key-value pair corresponding to the supplied key.
    pub fn get_key_value<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<(&str, &SessionValue)> {
        self.variables.get_key_value(&key.as_ref().to_lowercase()).map(|(key, value)| (key.as_str(), value))
    }

    /// Returns a mutable reference to the value corresponding to the key.
    pub fn get_mut<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<&mut SessionValue> {
        self.variables.get_mut(&key.as_ref().to_lowercase())
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, None is returned.
    /// If the map did have this key present, the value is updated, and the old value is returned.
    pub fn insert<Q: AsRef<str> + ?Sized>(&mut self, key: &Q, value: SessionValue) -> Option<SessionValue> {
        self.variables.insert(key.as_ref().to_lowercase(), value)
    }

    /// Creates a consuming iterator visiting all the keys in arbitrary order. The map cannot be used after calling
    /// this. The iterator element type is `String`.
    pub fn into_keys(self) -> IntoKeys<String, SessionValue> {
        self.variables.into_keys()
    }

    /// Creates a consuming iterator visiting all the values in arbitrary order. The map cannot be used after calling
    /// this. The iterator element type is `SessionValue`.
    pub fn into_values(self) -> IntoValues<String, SessionValue> {
        self.variables.into_values()
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The iterator element type is
    /// `(&'a String, &'a SessionData)`.
    pub fn iter(&self) -> Iter<'_, String, SessionValue> {
        self.variables.iter()
    }

    /// An iterator visiting all key-value pairs in arbitrary order, with mutable references to the values. The
    /// iterator element type is `(&'a String, &'a mut SessionValue)`.
    pub fn iter_mut(&mut self) -> IterMut<'_, String, SessionValue> {
        self.variables.iter_mut()
    }

    /// Returns `true` if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element type is `&'a String`.
    pub fn keys(&self) -> Keys<'_, String, SessionValue> {
        self.variables.keys()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Removes a key from the map, returning the value at the key if the key was previously in the map.
    pub fn remove<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<SessionValue> {
        self.variables.remove(&key.as_ref().to_lowercase())
    }

    /// Removes a key from the map, returning the stored key and value if the key was previously in the map.
    pub fn remove_entry<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<(String, SessionValue)> {
        self.variables.remove_entry(&key.as_ref().to_lowercase())
    }

    /// Reserves capacity for at least `additional` more elements to be inserted in the `SessionData`. The collection
    /// may reserve more space to speculatively avoid frequent reallocations. After calling `reserve`, capacity will be
    /// greater than or equal to `self.len() + additional`. Does nothing if capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new allocation size overflows [`usize`].
    pub fn reserve(&mut self, additional: usize) {
        self.variables.reserve(additional)
    }

    /// Shrinks the capacity of the map with a lower limit. It will drop down no lower than the supplied limit while
    /// maintaining the internal rules and possibly leaving some space in accordance with the resize policy.
    ///
    /// If the current capacity is less than the lower limit, this is a no-op.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.variables.shrink_to(min_capacity)
    }

    /// Shrinks the capacity of the map as much as possible. It will drop down as much as possible while maintaining
    /// the internal rules and possibly leaving some space in accordance with the resize policy.
    pub fn shrink_to_fit(&mut self) {
        self.variables.shrink_to_fit()
    }

    /// Tries to reserve capacity for at least `additional` more elements to be inserted in the `SessionData`. The
    /// collection may reserve more space to speculatively avoid frequent reallocations. After calling `try_reserve`,
    /// capacity will be greater than or equal to `self.len() + additional` if it returns `Ok(())`. Does nothing if
    /// capacity is already sufficient.
    ///
    /// # Errors
    ///
    /// If the capacity overflows, or the allocator reports a failure, then an error is returned.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.variables.try_reserve(additional)
    }

    /// An iterator visiting all values in arbitrary order. The iterator element type is `&'a SessionValue`.
    pub fn values(&self) -> Values<'_, String, SessionValue> {
        self.variables.values()
    }

    /// An iterator visiting all values mutably in arbitrary order. The iterator element type is `&'a mut SessionValue`.
    pub fn values_mut(&mut self) -> ValuesMut<'_, String, SessionValue> {
        self.variables.values_mut()
    }
}

impl Default for SessionData {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K: AsRef<str> + ?Sized> Extend<(&'a K, &'a SessionValue)> for SessionData {
    fn extend<T: IntoIterator<Item = (&'a K, &'a SessionValue)>>(&mut self, iter: T) {
        self.variables.extend(iter.into_iter().map(|(key, value)| (key.as_ref().to_lowercase(), value.clone())));
    }
}

impl From<HashMap<String, SessionValue>> for SessionData {
    fn from(variables: HashMap<String, SessionValue>) -> Self {
        let mut my_vars = HashMap::new();
        for (key, value) in variables.iter() {
            my_vars.insert(key.to_lowercase(), value.clone());
        }

        Self {
            variables: my_vars,
        }
    }
}

impl<K: AsRef<str>, const N: usize> From<[(K, SessionValue); N]> for SessionData {
    fn from(variables: [(K, SessionValue); N]) -> Self {
        let mut my_vars = HashMap::new();
        for (key, value) in variables.iter() {
            my_vars.insert(key.as_ref().to_lowercase(), value.clone());
        }

        Self {
            variables: my_vars,
        }
    }
}

impl<K: AsRef<str>> FromIterator<(K, SessionValue)> for SessionData {
    fn from_iter<T: IntoIterator<Item = (K, SessionValue)>>(iter: T) -> Self {
        let mut my_vars = HashMap::new();
        for (key, value) in iter {
            my_vars.insert(key.as_ref().to_lowercase(), value.clone());
        }

        Self {
            variables: my_vars,
        }
    }
}

impl<Q: AsRef<str> + ?Sized> Index<&'_ Q> for SessionData {
    type Output = SessionValue;

    fn index(&self, key: &Q) -> &Self::Output {
        self.variables.get(&key.as_ref().to_lowercase()).unwrap()
    }
}

impl<'a> IntoIterator for &'a SessionData {
    type Item = (&'a String, &'a SessionValue);
    type IntoIter = Iter<'a, String, SessionValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.variables.iter()
    }
}

impl<'a> IntoIterator for &'a mut SessionData {
    type Item = (&'a String, &'a mut SessionValue);
    type IntoIter = IterMut<'a, String, SessionValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.variables.iter_mut()
    }
}

impl IntoIterator for SessionData {
    type Item = (String, SessionValue);
    type IntoIter = IntoIter<String, SessionValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.variables.into_iter()
    }
}

impl UnwindSafe for SessionData {}

impl PartialEq for SessionData {
    fn eq(&self, other: &Self) -> bool {
        self.variables == other.variables
    }
}

impl PartialEq<HashMap<String, SessionValue>> for SessionData {
    fn eq(&self, other: &HashMap<String, SessionValue>) -> bool {
        if self.variables.len() != other.len() {
            return false;
        }

        for (key, other_value) in other.iter() {
            match self.variables.get(&key.to_lowercase()) {
                None => return false,
                Some(value) => {
                    if value != other_value {
                        return false;
                    }
                }
            }
        }

        true
    }
}

/// Associated data about a session key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionValue {
    /// Boolean value.
    Bool(bool),

    /// Integer value.
    Integer(i64),

    /// IP address value.
    IpAddr(IpAddr),

    /// String value.
    String(String),
}

impl Display for SessionValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Bool(b) => write!(f, "Bool({})", b),
            Self::Integer(i) => write!(f, "Integer({})", i),
            Self::IpAddr(ip) => write!(f, "IpAddr({})", ip),
            Self::String(s) => write!(f, "String({})", s),
        }
    }
}
