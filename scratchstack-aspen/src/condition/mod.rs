mod arn;
mod binary;
mod boolean;
mod date;
mod ipaddr;
mod null;
mod numeric;

#[allow(non_upper_case_globals)]
pub mod op;

#[cfg(test)]
mod op_tests;
mod string;
mod variant;

pub use op::ConditionOp;
use {
    crate::{from_str_json, serutil::StringLikeList, AspenError, Context, PolicyVersion},
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
