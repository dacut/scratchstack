use std::{
    collections::{
        hash_map::{Drain, IntoIter, IntoKeys, IntoValues, Iter, IterMut, Keys, Values, ValuesMut},
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
#[derive(Clone, Debug)]
pub struct SessionData {
    /// The variables associated with the session with the keys lower-cased.
    variables: HashMap<String, SessionValue>,
}

impl SessionData {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            variables: HashMap::with_capacity(capacity),
        }
    }

    pub fn capacity(&self) -> usize {
        self.variables.capacity()
    }

    pub fn clear(&mut self) {
        self.variables.clear();
    }

    pub fn contains_key<Q: AsRef<str> + ?Sized>(&self, k: &Q) -> bool {
        self.variables.contains_key(&k.as_ref().to_lowercase())
    }

    pub fn drain(&mut self) -> Drain<'_, String, SessionValue> {
        self.variables.drain()
    }

    pub fn get<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<&SessionValue> {
        self.variables.get(&key.as_ref().to_lowercase())
    }

    pub fn get_key_value<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<(&str, &SessionValue)> {
        self.variables.get_key_value(&key.as_ref().to_lowercase()).map(|(key, value)| (key.as_str(), value))
    }

    pub fn get_mut<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<&mut SessionValue> {
        self.variables.get_mut(&key.as_ref().to_lowercase())
    }

    pub fn insert<Q: AsRef<str> + ?Sized>(&mut self, key: &Q, value: SessionValue) -> Option<SessionValue> {
        self.variables.insert(key.as_ref().to_lowercase(), value)
    }

    pub fn into_keys(self) -> IntoKeys<String, SessionValue> {
        self.variables.into_keys()
    }

    pub fn into_values(self) -> IntoValues<String, SessionValue> {
        self.variables.into_values()
    }

    pub fn iter(&self) -> Iter<'_, String, SessionValue> {
        self.variables.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, String, SessionValue> {
        self.variables.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    pub fn keys(&self) -> Keys<'_, String, SessionValue> {
        self.variables.keys()
    }

    pub fn len(&self) -> usize {
        self.variables.len()
    }

    pub fn remove<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<SessionValue> {
        self.variables.remove(&key.as_ref().to_lowercase())
    }

    pub fn remove_entry<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<(String, SessionValue)> {
        self.variables.remove_entry(&key.as_ref().to_lowercase())
    }

    pub fn reserve(&mut self, additional: usize) {
        self.variables.reserve(additional)
    }

    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.variables.shrink_to(min_capacity)
    }

    pub fn shrink_to_fit(&mut self) {
        self.variables.shrink_to_fit()
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.variables.try_reserve(additional)
    }

    pub fn values(&self) -> Values<'_, String, SessionValue> {
        self.variables.values()
    }

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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionValue {
    Bool(bool),
    Integer(i64),
    IpAddr(IpAddr),
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
