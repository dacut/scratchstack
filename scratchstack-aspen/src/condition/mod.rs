mod arn;
mod binary;
mod boolean;
mod date;
mod ipaddr;
mod null;
mod numeric;
mod op;
mod string;
mod variant;
#[cfg(test)]
mod tests;

pub use op::ConditionOp;
use {
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
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

pub type ConditionMap = BTreeMap<String, StringLikeList<String>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Condition {
    map: BTreeMap<ConditionOp, ConditionMap>,
}

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
    #[inline]
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn append(&mut self, other: &mut Self) {
        self.map.append(&mut other.map);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.map.clear();
    }

    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.contains_key(key)
    }

    #[inline]
    pub fn entry(&mut self, key: ConditionOp) -> Entry<'_, ConditionOp, ConditionMap> {
        self.map.entry(key)
    }

    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&ConditionMap>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get(key)
    }

    #[inline]
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&ConditionOp, &ConditionMap)>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get_key_value(key)
    }

    #[inline]
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut ConditionMap>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get_mut(key)
    }

    #[inline]
    pub fn insert(&mut self, key: ConditionOp, value: ConditionMap) -> Option<ConditionMap> {
        self.map.insert(key, value)
    }

    #[inline]
    pub fn into_keys(self) -> IntoKeys<ConditionOp, ConditionMap> {
        self.map.into_keys()
    }

    #[inline]
    pub fn into_values(self) -> IntoValues<ConditionOp, ConditionMap> {
        self.map.into_values()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, ConditionOp, ConditionMap> {
        self.map.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, ConditionOp, ConditionMap> {
        self.map.iter_mut()
    }

    #[inline]
    pub fn keys(&self) -> Keys<'_, ConditionOp, ConditionMap> {
        self.map.keys()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn range<T, R>(&self, range: R) -> Range<'_, ConditionOp, ConditionMap>
    where
        ConditionOp: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.map.range(range)
    }

    #[inline]
    pub fn range_mut<T, R>(&mut self, range: R) -> RangeMut<'_, ConditionOp, ConditionMap>
    where
        ConditionOp: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.map.range_mut(range)
    }

    #[inline]
    pub fn remove<Q>(&mut self, key: &Q) -> Option<ConditionMap>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove(key)
    }

    #[inline]
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(ConditionOp, ConditionMap)>
    where
        ConditionOp: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove_entry(key)
    }

    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&ConditionOp, &mut ConditionMap) -> bool,
    {
        self.map.retain(f)
    }

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

    #[inline]
    pub fn values(&self) -> Values<'_, ConditionOp, ConditionMap> {
        self.map.values()
    }

    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_, ConditionOp, ConditionMap> {
        self.map.values_mut()
    }

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

const NULL: SessionValue = SessionValue::Null;
