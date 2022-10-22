//! Condition handling for Aspen policies.

mod arn;
mod binary;
mod boolean;
mod date;
mod ipaddr;
mod null;
mod numeric;

/// Operators for conditions.
#[allow(non_upper_case_globals)]
pub mod op;

#[cfg(test)]
mod op_tests;
mod string;
mod variant;

pub use {op::ConditionOp, variant::Variant};

use {
    crate::{from_str_json, serutil::StringLikeList, AspenError, Context, PolicyVersion},
    serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize},
    std::{
        borrow::Borrow,
        collections::{
            btree_map::{
                Entry, IntoIter, IntoKeys, IntoValues, Iter, IterMut, Keys, Range, RangeMut, Values, ValuesMut,
            },
            BTreeMap,
        },
        iter::{Extend, FromIterator, IntoIterator},
        ops::{Index, RangeBounds},
    },
};

/// A map of condition variables to their allowed values.
pub type ConditionMap = BTreeMap<String, StringLikeList<String>>;

/// Representation of an Aspen condition clause in a statement.
///
/// This is (logically and physically) a two-level map. The first level (this structure) maps [ConditionOp] operators
/// to a [ConditionMap]. The second level, the [ConditionMap] itself, maps condition variable names to a list of
/// allowed values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Condition {
    map: BTreeMap<ConditionOp, ConditionMap>,
}

from_str_json!(Condition);

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::deserialize(deserializer)?;

        Ok(Self {
            map,
        })
    }
}

impl Serialize for Condition {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.map.serialize(serializer)
    }
}

impl Condition {
    /// Create a new condition clause with no values.
    #[inline]
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Moves all elements from `other` into `self`, leaving `other` empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut a = Condition::new();
    /// a.insert(condop::StringEquals, ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]));
    ///
    /// let mut b = Condition::new();
    /// b.insert(condop::StringLike, ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]));
    ///
    /// a.append(&mut b);
    ///
    /// assert_eq!(a.len(), 2);
    /// assert_eq!(b.len(), 0);
    /// ```
    #[inline]
    pub fn append(&mut self, other: &mut Self) {
        self.map.append(&mut other.map);
    }

    /// Clears the condition clause, removing all elements.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut a = Condition::new();
    /// a.insert(condop::StringEquals, ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]));
    /// a.clear();
    /// assert!(a.is_empty());
    /// ```
    #[inline]
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Returns `true` if the condition clause contains a value for the specified [ConditionOp] operator.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// condition.insert(condop::StringEquals, ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]));
    /// assert_eq!(condition.contains_key(&condop::StringEquals), true);
    /// assert_eq!(condition.contains_key(&condop::NumericEquals), false);
    /// ```
    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.contains_key(key)
    }

    /// Gets the given [ConditionOp] operator's corresponding entry in the map for in-place manipulation.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap);
    /// condition.entry(condop::StringEquals).and_modify(|e| {
    ///     e.insert("b".to_string(), StringLikeList::<String>::from("B".to_string()));
    /// });
    ///
    /// assert_eq!(condition.get(&condop::StringEquals).unwrap().len(), 2);
    /// ```
    #[inline]
    pub fn entry(&mut self, key: ConditionOp) -> Entry<'_, ConditionOp, ConditionMap> {
        self.map.entry(key)
    }

    /// Returns a reference to the [ConditionMap] corresponding to the [ConditionOp] operator.
    ///
    /// The key may be any borrowed form of the map's key type, but the ordering
    /// on the borrowed form *must* match the ordering on the key type.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap.clone());
    /// assert_eq!(condition.get(&condop::StringEquals), Some(&cmap));
    /// assert_eq!(condition.get(&condop::StringLike), None);
    /// ```
    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&ConditionMap>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get(key)
    }

    /// Returns the `(ConditionOp, ConditionMap)` key-value pair corresponding to the supplied
    /// [ConditionOp] operator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap.clone());
    /// assert_eq!(condition.get_key_value(&condop::StringEquals), Some((&condop::StringEquals, &cmap)));
    /// assert_eq!(condition.get_key_value(&condop::StringLike), None);
    /// ```
    #[inline]
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&ConditionOp, &ConditionMap)>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get_key_value(key)
    }

    /// Returns a mutable reference to the [ConditionMap] corresponding to the [ConditionOp] operator.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap1);
    /// if let Some(x) = condition.get_mut(&condop::StringEquals) {
    ///     *x = cmap2.clone();
    /// }
    /// assert_eq!(condition[&condop::StringEquals], cmap2);
    /// ```
    #[inline]
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut ConditionMap>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get_mut(key)
    }

    #[inline]
    /// Inserts a key-value pair into the Condition clause.
    ///
    /// If the clause did not have this operator present, `None` is returned.
    ///
    /// If the clause did have this operator present, the value is updated, and the old
    /// value is returned.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    ///
    /// assert_eq!(condition.insert(condop::StringEquals, cmap1.clone()), None);
    /// assert_eq!(condition.insert(condop::StringEquals, cmap2.clone()), Some(cmap1));
    /// ```
    pub fn insert(&mut self, key: ConditionOp, value: ConditionMap) -> Option<ConditionMap> {
        self.map.insert(key, value)
    }

    /// Creates a consuming iterator visiting all the [ConditionOp] operators, in sorted order.
    /// The map cannot be used after calling this.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap1);
    /// condition.insert(condop::StringEqualsIgnoreCase, cmap2);
    ///
    /// let keys: Vec<ConditionOp> = condition.into_keys().collect();
    /// assert_eq!(keys, [condop::StringEquals, condop::StringEqualsIgnoreCase]);
    /// ```
    #[inline]
    pub fn into_keys(self) -> IntoKeys<ConditionOp, ConditionMap> {
        self.map.into_keys()
    }

    /// Creates a consuming iterator visiting all the values, in order by the [ConditionOp] operator.
    /// The map cannot be used after calling this.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap1.clone());
    /// condition.insert(condop::StringEqualsIgnoreCase, cmap2.clone());
    ///
    /// let values: Vec<ConditionMap> = condition.into_values().collect();
    /// assert_eq!(values, [cmap1, cmap2]);
    /// ```
    #[inline]
    pub fn into_values(self) -> IntoValues<ConditionOp, ConditionMap> {
        self.map.into_values()
    }

    /// Returns `true` if the condition clause contains no elements.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// assert!(condition.is_empty());
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// condition.insert(condop::StringEquals, cmap);
    /// assert!(!condition.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gets an iterator over the `(&ConditionOp, &ConditionMap)` entries of the condition clause, sorted by
    /// [ConditionOp] operator.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap2.clone());
    /// condition.insert(condop::ArnLike, cmap1.clone());
    /// condition.insert(condop::StringEquals, cmap3.clone());
    ///
    /// let values: Vec<(&ConditionOp, &ConditionMap)> = condition.iter().collect();
    /// assert_eq!(values, vec![(&condop::ArnLike, &cmap1), (&condop::Bool, &cmap2), (&condop::StringEquals, &cmap3)]);
    /// ```
    #[inline]
    pub fn iter(&self) -> Iter<'_, ConditionOp, ConditionMap> {
        self.map.iter()
    }

    /// Gets an mutable iterator over the `(&ConditionOp, &mut ConditionMap)` entries of the condition clause, sorted
    /// by [ConditionOp] operator.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap2.clone());
    /// condition.insert(condop::ArnLike, cmap1.clone());
    /// condition.insert(condop::StringEquals, cmap3.clone());
    ///
    /// let values: Vec<(&ConditionOp, &ConditionMap)> = condition.iter().collect();
    /// // Add a new variable to the Bool operator.
    /// for (key, value) in condition.iter_mut() {
    ///     if key == &condop::Bool {
    ///        value.insert("d".to_string(), StringLikeList::<String>::from("D".to_string()));
    ///     }
    /// }
    /// ```
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, ConditionOp, ConditionMap> {
        self.map.iter_mut()
    }

    /// Gets an iterator over the [ConditionOp] operator keys of the map, in sorted order.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap2.clone());
    /// condition.insert(condop::ArnLike, cmap1.clone());
    /// condition.insert(condop::StringEquals, cmap3.clone());
    ///
    /// let keys: Vec<ConditionOp> = condition.keys().cloned().collect();
    /// assert_eq!(keys, [condop::ArnLike, condop::Bool, condop::StringEquals]);
    /// ```
    #[inline]
    pub fn keys(&self) -> Keys<'_, ConditionOp, ConditionMap> {
        self.map.keys()
    }

    /// Returns the number of elements in the condition clause.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// assert_eq!(condition.len(), 0);
    /// condition.insert(condop::StringEquals, cmap);
    /// assert_eq!(condition.len(), 1);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Constructs a double-ended iterator over a sub-range of elements in the condition clause.
    /// The simplest way is to use the range syntax `min..max`, thus `range(min..max)` will
    /// yield elements from min (inclusive) to max (exclusive).
    /// The range may also be entered as `(Bound<T>, Bound<T>)`, so for example
    /// `range((Excluded(condop::ArnLike), Included(condop::StringEquals)))` will yield a
    /// left-exclusive, right-inclusive range.
    ///
    /// # Panics
    ///
    /// Panics if range `start > end`.
    /// Panics if range `start == end` and both bounds are `Excluded`.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    /// use std::ops::Bound::Included;
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::ArnLike, cmap1.clone());
    /// condition.insert(condop::Bool, cmap2.clone());
    /// condition.insert(condop::StringEquals, cmap3.clone());
    ///
    /// let result: Vec<(&ConditionOp, &ConditionMap)> = condition.range((Included(condop::Bool), Included(condop::NumericEquals))).collect();
    /// assert_eq!(result, vec![(&condop::Bool, &cmap2)]);
    /// ```
    #[inline]
    pub fn range<T, R>(&self, range: R) -> Range<'_, ConditionOp, ConditionMap>
    where
        ConditionOp: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.map.range(range)
    }

    /// Constructs a mutable double-ended iterator over a sub-range of elements in the condition clause.
    /// The simplest way is to use the range syntax `min..max`, thus `range(min..max)` will
    /// yield elements from min (inclusive) to max (exclusive).
    /// The range may also be entered as `(Bound<T>, Bound<T>)`, so for example
    /// `range((Excluded(condop::ArnLike), Included(condop::StringEquals)))` will yield a
    /// left-exclusive, right-inclusive range.
    ///
    /// # Panics
    ///
    /// Panics if range `start > end`.
    /// Panics if range `start == end` and both bounds are `Excluded`.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    /// use std::ops::Bound::Included;
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::ArnLike, cmap1);
    /// condition.insert(condop::Bool, cmap2);
    /// condition.insert(condop::StringEquals, cmap3);
    ///
    /// for (_, cmap) in condition.range_mut((Included(condop::Bool), Included(condop::NumericEquals))) {
    ///     cmap.insert("d".to_string(), StringLikeList::<String>::from("D".to_string()));
    /// }
    ///
    /// assert_eq!(condition.get(&condop::Bool).unwrap().len(), 2);
    /// ```
    #[inline]
    pub fn range_mut<T, R>(&mut self, range: R) -> RangeMut<'_, ConditionOp, ConditionMap>
    where
        ConditionOp: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.map.range_mut(range)
    }

    /// Removes a [ConditionOp] operator from the condition clause, returning the [ConditionMap] corresponding to the
    /// operator if the operator was previously in the clause.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap.clone());
    ///
    /// assert_eq!(condition.remove(&condop::Bool), Some(cmap));
    /// assert_eq!(condition.remove(&condop::Bool), None);
    /// ```
    #[inline]
    pub fn remove<Q>(&mut self, key: &Q) -> Option<ConditionMap>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove(key)
    }

    /// Removes a [ConditionOp] operator from the condition clause, returning the stored operator and [ConditionMap]
    /// if the operator was previously in the clause.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap.clone());
    ///
    /// assert_eq!(condition.remove_entry(&condop::Bool), Some((condop::Bool, cmap)));
    /// assert_eq!(condition.remove(&condop::Bool), None);
    /// ```

    #[inline]
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(ConditionOp, ConditionMap)>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove_entry(key)
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all pairs `(cond_op, cond_map)` for which `f(&cond_op, &mut cond_map)` returns `false`.
    /// The elements are visited in ascending [ConditionOp] order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::ArnLike, cmap1);
    /// condition.insert(condop::Bool, cmap2.clone());
    /// condition.insert(condop::StringEquals, cmap3);
    ///
    /// // Keep only the Bool key.
    /// condition.retain(|&k, _| k == condop::Bool);
    /// assert!(condition.into_iter().eq(vec![(condop::Bool, cmap2)]));
    /// ```
    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&ConditionOp, &mut ConditionMap) -> bool,
    {
        self.map.retain(f)
    }

    /// Splits the collection into two at the given [ConditionOp] operator. Returns everything on and after the given
    /// [ConditionOp].
    ///
    /// # Examples
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut a = Condition::new();
    /// let cmap = ConditionMap::new();
    ///
    /// a.insert(condop::ArnLike, cmap.clone());
    /// a.insert(condop::Bool, cmap.clone());
    /// a.insert(condop::DateEquals, cmap.clone());
    /// a.insert(condop::NumericEquals, cmap.clone());
    /// a.insert(condop::StringEquals, cmap.clone());
    ///
    /// let b= a.split_off(&condop::DateEquals);
    /// assert_eq!(a.len(), 2);
    /// assert_eq!(b.len(), 3);
    ///
    /// assert_eq!(a.into_keys().collect::<Vec<_>>(), vec![condop::ArnLike, condop::Bool]);
    /// assert_eq!(b.into_keys().collect::<Vec<_>>(), vec![condop::DateEquals, condop::NumericEquals, condop::StringEquals]);
    /// ```

    #[inline]
    pub fn split_off<Q>(&mut self, key: &Q) -> Condition
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        Condition {
            map: self.map.split_off(key),
        }
    }

    /// Gets an iterator over the [ConditionMap] values of the map, in order by [ConditionOp] key.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap2.clone());
    /// condition.insert(condop::ArnLike, cmap1.clone());
    /// condition.insert(condop::StringEquals, cmap3.clone());
    ///
    /// let values: Vec<ConditionMap> = condition.values().cloned().collect();
    /// assert_eq!(values, [cmap1, cmap2, cmap3]);
    /// ```
    #[inline]
    pub fn values(&self) -> Values<'_, ConditionOp, ConditionMap> {
        self.map.values()
    }

    /// Gets an iterator over the mutable [ConditionMap] values of the map, in order by [ConditionOp] key.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use scratchstack_aspen::{condop, Condition, ConditionOp, ConditionMap, StringLikeList};
    ///
    /// let mut condition = Condition::new();
    /// let cmap1 = ConditionMap::from_iter(vec![("a".to_string(), StringLikeList::<String>::from("A".to_string()))]);
    /// let cmap2 = ConditionMap::from_iter(vec![("b".to_string(), StringLikeList::<String>::from("B".to_string()))]);
    /// let cmap3 = ConditionMap::from_iter(vec![("c".to_string(), StringLikeList::<String>::from("C".to_string()))]);
    ///
    /// condition.insert(condop::Bool, cmap2);
    /// condition.insert(condop::ArnLike, cmap1);
    /// condition.insert(condop::StringEquals, cmap3);
    ///
    /// for value in condition.values_mut() {
    ///    value.insert("d".to_string(), StringLikeList::<String>::from("D".to_string()));
    /// }
    ///
    /// assert_eq!(condition.get(&condop::ArnLike).unwrap().len(), 2);
    /// ```
    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_, ConditionOp, ConditionMap> {
        self.map.values_mut()
    }

    /// Indicates whether this condition clause matches the request [Context]. This condition is interpreted using the
    /// specified [PolicyVersion].
    ///
    /// # Errors
    ///
    /// If a condition clause contains a malformed variable, [AspenError::InvalidSubstitution] is returned.
    pub fn matches(&self, context: &Context, pv: PolicyVersion) -> Result<bool, AspenError> {
        for (op, map) in self.iter() {
            if !op.matches(map, context, pv)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Default for Condition {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Extend<(ConditionOp, ConditionMap)> for Condition {
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (ConditionOp, ConditionMap)>,
    {
        self.map.extend(iter)
    }
}

impl<const N: usize> From<[(ConditionOp, ConditionMap); N]> for Condition {
    #[inline]
    fn from(array: [(ConditionOp, ConditionMap); N]) -> Self {
        Condition {
            map: BTreeMap::from(array),
        }
    }
}

impl FromIterator<(ConditionOp, ConditionMap)> for Condition {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (ConditionOp, ConditionMap)>,
    {
        Condition {
            map: BTreeMap::from_iter(iter),
        }
    }
}

impl<Q> Index<&Q> for Condition
where
    ConditionOp: Borrow<Q>,
    Q: Ord + ?Sized,
{
    type Output = ConditionMap;

    fn index(&self, key: &Q) -> &ConditionMap {
        self.map.index(key)
    }
}

impl<'a> IntoIterator for &'a Condition {
    type Item = (&'a ConditionOp, &'a ConditionMap);
    type IntoIter = Iter<'a, ConditionOp, ConditionMap>;
    fn into_iter(self) -> Iter<'a, ConditionOp, ConditionMap> {
        self.map.iter()
    }
}

impl<'a> IntoIterator for &'a mut Condition {
    type Item = (&'a ConditionOp, &'a mut ConditionMap);
    type IntoIter = IterMut<'a, ConditionOp, ConditionMap>;
    fn into_iter(self) -> IterMut<'a, ConditionOp, ConditionMap> {
        self.map.iter_mut()
    }
}

impl IntoIterator for Condition {
    type Item = (ConditionOp, ConditionMap);
    type IntoIter = IntoIter<ConditionOp, ConditionMap>;
    fn into_iter(self) -> IntoIter<ConditionOp, ConditionMap> {
        self.map.into_iter()
    }
}

#[cfg(test)]
mod test {
    use {
        crate::{condop, serutil::StringLikeList, Condition, ConditionMap, ConditionOp},
        pretty_assertions::assert_eq,
    };

    #[test_log::test]
    fn test_map_ops() {
        let mut c1 = Condition::default();
        let mut c2 = Condition::new();

        assert_eq!(c1, c2);

        let mut cmap1 = ConditionMap::default();
        cmap1.insert("a".to_string(), StringLikeList::from(vec!["A".to_string()]));
        cmap1.insert("b".to_string(), StringLikeList::from(vec!["B".to_string()]));

        let mut cmap2 = ConditionMap::default();
        cmap2.insert("c".to_string(), StringLikeList::from(vec!["C".to_string()]));

        let mut cmap3 = ConditionMap::default();
        cmap3.insert("d".to_string(), StringLikeList::from(vec!["D".to_string()]));

        c2.insert(condop::StringEquals, cmap1.clone());
        c2.insert(condop::StringEqualsIgnoreCase, cmap3.clone());
        assert_eq!(c1.len(), 0);
        assert!(c1.is_empty());
        assert_eq!(c2.len(), 2);
        assert!(!c2.is_empty());

        assert_eq!(c2[&condop::StringEquals], cmap1);

        assert!(c2.contains_key(&condop::StringEquals));
        assert!(!c1.contains_key(&condop::StringEquals));
        assert_eq!(c1.get_key_value(&condop::StringEquals), None);
        assert_eq!(c2.get_key_value(&condop::StringEquals), Some((&condop::StringEquals, &cmap1)));

        // Make this look like cmap2.
        let c2_map = c2.get_mut(&condop::StringEquals).unwrap();
        c2_map.insert("c".to_string(), StringLikeList::from(vec!["C".to_string()]));
        c2_map.remove("a");
        c2_map.remove("b");
        assert_eq!(c2_map, &cmap2);

        c1.append(&mut c2);
        assert_eq!(c1.len(), 2);
        assert_eq!(c2.len(), 0);
        assert!(!c1.is_empty());
        assert!(c2.is_empty());
        assert!(c1.contains_key(&condop::StringEquals));
        assert_eq!(c1[&condop::StringEquals], cmap2);
        c1.retain(|k, _| k == &condop::StringEquals);
        assert_eq!(c1.keys().collect::<Vec<_>>(), vec![&condop::StringEquals]);
        assert_eq!(c1.values().collect::<Vec<_>>(), vec![&cmap2]);

        c1.clear();
        assert_eq!(c1.len(), 0);
        assert!(c1.is_empty());
        assert!(!c1.contains_key(&condop::StringEquals));

        let c1_array: [(ConditionOp, ConditionMap); 4] = [
            (condop::DateEquals, cmap1.clone()),
            (condop::NumericEquals, cmap1.clone()),
            (condop::StringEquals, cmap2.clone()),
            (condop::StringEqualsIgnoreCase, cmap3.clone()),
        ];

        let mut c1 = Condition::from(c1_array);
        c1.entry(condop::NumericEquals).and_modify(|v| {
            v.remove("a");
            v.remove("b");
            v.insert("c".to_string(), StringLikeList::from(vec!["C".to_string()]));
        });
        assert_eq!(c1[&condop::NumericEquals], cmap2);
        assert!(c1.remove(&condop::Bool).is_none());
        assert!(c1.remove_entry(&condop::Bool).is_none());
        assert_eq!(c1.remove_entry(&condop::NumericEquals), Some((condop::NumericEquals, cmap2.clone())));
        c1.insert(condop::NumericEquals, cmap1.clone());

        c1.range_mut(condop::Bool..condop::NumericEquals).for_each(|(k, v)| {
            assert_eq!(k, &condop::DateEquals);
            assert_eq!(v, &cmap1);

            // Make this look like cmap2
            v.remove("a");
            v.remove("b");
            v.insert("c".to_string(), StringLikeList::from(vec!["C".to_string()]));
        });

        c1.range(condop::Bool..condop::NumericEquals).for_each(|(k, v)| {
            assert_eq!(k, &condop::DateEquals);
            assert_eq!(v, &cmap2);
        });

        let c2 = c1.split_off(&condop::StringEquals);
        let c1_vec = (&mut c1).into_iter().collect::<Vec<_>>();
        assert_eq!(c1_vec, vec![(&condop::DateEquals, &mut cmap2), (&condop::NumericEquals, &mut cmap1)]);
        let c1_vec = (&c1).into_iter().collect::<Vec<_>>();
        assert_eq!(c1_vec, vec![(&condop::DateEquals, &cmap2), (&condop::NumericEquals, &cmap1)]);
        let c2 = c2.into_iter().collect::<Vec<_>>();
        assert_eq!(c2, vec![(condop::StringEquals, cmap2.clone()), (condop::StringEqualsIgnoreCase, cmap3.clone())]);

        assert_eq!(c1.clone().into_keys().collect::<Vec<_>>(), vec![condop::DateEquals, condop::NumericEquals]);
        assert_eq!(c1.clone().into_values().collect::<Vec<_>>(), vec![cmap2.clone(), cmap1.clone()]);

        c1.extend([(condop::StringEquals, cmap2.clone()), (condop::StringEqualsIgnoreCase, cmap3.clone())]);
        c1.values_mut().for_each(|v| {
            if v == &cmap3 {
                // Make this look like cmap2.
                v.remove("d");
                v.insert("c".to_string(), StringLikeList::from(vec!["C".to_string()]));
            }
        });
        assert_eq!(c1[&condop::StringEqualsIgnoreCase], cmap2);

        c1.iter_mut().for_each(|(k, v)| {
            if k == &condop::NumericEquals {
                // Make this look like cmap3.
                v.clear();
                v.insert("d".to_string(), StringLikeList::from(vec!["D".to_string()]));
            }
        });
        assert_eq!(c1[&condop::NumericEquals], cmap3);

        let c2 = Condition::from_iter(c1.iter().map(|(k, v)| (*k, v.clone())));
        assert_eq!(c1, c2);
    }
}
