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

#[cfg(test)]
mod tests {
    use {
        crate::{Condition, ConditionOp, Context, PolicyVersion},
        chrono::DateTime,
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{Principal, PrincipalIdentity, Service, SessionData, SessionValue},
        std::str::FromStr,
    };

    #[test_log::test]
    fn test_display() {
        let items = vec![
            "ArnEquals",
            "ArnEqualsIfExists",
            "ArnLike",
            "ArnLikeIfExists",
            "ArnNotEquals",
            "ArnNotEqualsIfExists",
            "ArnNotLike",
            "ArnNotLikeIfExists",
            "BinaryEquals",
            "BinaryEqualsIfExists",
            "Bool",
            "BoolIfExists",
            "DateEquals",
            "DateEqualsIfExists",
            "DateGreaterThan",
            "DateGreaterThanEquals",
            "DateGreaterThanEqualsIfExists",
            "DateGreaterThanIfExists",
            "DateLessThan",
            "DateLessThanEquals",
            "DateLessThanEqualsIfExists",
            "DateLessThanIfExists",
            "DateNotEquals",
            "DateNotEqualsIfExists",
            "IpAddress",
            "IpAddressIfExists",
            "NotIpAddress",
            "NotIpAddressIfExists",
            "Null",
            "NumericEquals",
            "NumericEqualsIfExists",
            "NumericGreaterThan",
            "NumericGreaterThanEquals",
            "NumericGreaterThanEqualsIfExists",
            "NumericGreaterThanIfExists",
            "NumericLessThan",
            "NumericLessThanEquals",
            "NumericLessThanEqualsIfExists",
            "NumericLessThanIfExists",
            "NumericNotEquals",
            "NumericNotEqualsIfExists",
            "StringEquals",
            "StringEqualsIfExists",
            "StringEqualsIgnoreCase",
            "StringEqualsIgnoreCaseIfExists",
            "StringLike",
            "StringLikeIfExists",
            "StringNotEquals",
            "StringNotEqualsIfExists",
            "StringNotEqualsIgnoreCase",
            "StringNotEqualsIgnoreCaseIfExists",
            "StringNotLike",
            "StringNotLikeIfExists",
        ];

        for item in items {
            let op = ConditionOp::from_str(item).unwrap();
            assert_eq!(format!("{}", op), item);
        }
    }

    fn session_matches(cmap: &Condition, session_data: &SessionData) -> bool {
        let principal: Principal =
            vec![PrincipalIdentity::from(Service::new("example", None, "amazonaws.com").unwrap())].into();
        let context = Context::builder()
            .action("service:action")
            .actor(principal)
            .resource(Arn::new("aws", "s3", "", "", "example").unwrap())
            .session_data(session_data.clone())
            .service("service")
            .build()
            .unwrap();
        cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap()
    }

    #[test_log::test]
    fn test_arn_equals() {
        let cmap: Condition =
            serde_json::from_str(r#"{"ArnEquals": {"hello": "arn:aw*:ec?:us-*-1:*:instance/i-*"}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "hello",
            SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from("not an arn"));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"ArnEqualsIfExists": {"hello": "arn:aw*:ec?:us-*-1:*:instance/i-*"}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "hello",
            SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from("not an arn"));
        assert!(!session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_arn_equals_variables() {
        let cmap: Condition =
            serde_json::from_str(r#"{"ArnEquals": {"hello": "arn:aws:s3:::bucket/${aws:username}/*"}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from("arn:aws:s3:::bucket/bob/object"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:username", SessionValue::from("bob"));
        assert!(session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_arn_not_equals() {
        let cmap: Condition =
            serde_json::from_str(r#"{"ArnNotEquals": {"hello": "arn:aw*:ec?:us-*-1:*:instance/i-*"}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "hello",
            SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from("not an arn"));
        assert!(session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"ArnNotEqualsIfExists": {"hello": "arn:aw*:ec?:us-*-1:*:instance/i-*"}}"#)
                .unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(!session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data
            .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "hello",
            SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from("not an arn"));
        assert!(session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_bool() {
        let cmap: Condition = serde_json::from_str(r#"{"Bool": {"hello": ["false"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(false));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(true));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition = serde_json::from_str(r#"{"Bool": {"hello": ["true"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(true));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(false));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition = serde_json::from_str(r#"{"Bool": {"hello": []}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(true));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(false));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition = serde_json::from_str(r#"{"BoolIfExists": {"hello": "false"}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(false));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(true));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition = serde_json::from_str(r#"{"BoolIfExists": {"hello": "true"}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(true));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(false));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition = serde_json::from_str(r#"{"BoolIfExists": {"hello": []}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(true));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("hello", SessionValue::from(false));
        assert!(!session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_date_equals() {
        let cmap: Condition =
            serde_json::from_str(r#"{"DateEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"DateEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_date_not_equals() {
        let cmap: Condition =
            serde_json::from_str(r#"{"DateNotEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"DateNotEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
                .unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_date_less_than() {
        let cmap: Condition =
            serde_json::from_str(r#"{"DateLessThan": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"DateLessThanIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_date_less_than_equals() {
        let cmap: Condition =
            serde_json::from_str(r#"{"DateLessThanEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"DateLessThanEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
                .unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_date_greater_than() {
        let cmap: Condition =
            serde_json::from_str(r#"{"DateGreaterThan": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"DateGreaterThanIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
                .unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));
    }

    #[test_log::test]
    fn test_date_greater_than_equals() {
        let cmap: Condition =
            serde_json::from_str(r#"{"DateGreaterThanEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
                .unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));

        let cmap: Condition =
            serde_json::from_str(r#"{"DateGreaterThanEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
                .unwrap();

        let mut session_data = SessionData::new();
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()),
        );
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert(
            "aws:CurrentDate",
            SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()),
        );
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
        assert!(!session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
        assert!(session_matches(&cmap, &session_data));

        session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
        assert!(!session_matches(&cmap, &session_data));
    }
}
