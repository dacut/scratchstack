//! AWS request id implementation.
//!
//! This implementation uses the UUIDv7 format the embed a timestamp in the UUID to make it easier to track down the
//! request in the logs. This timestamp has a resolution of 1 microsecond.

use {
    chrono::{DateTime, TimeZone, Utc},
    rand::random,
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
        time::SystemTime,
    },
    uuid::Uuid,
};

/// AWS request id implementation.
///
/// This implementation uses the UUIDv7 format the embed a timestamp in the UUID to make it easier to track down the
/// request in the logs. This timestamp has a resolution of 1s and is based on the system clock, so it's not guaranteed
/// to be unique; thus, a random number is also embedded in the UUID.
///
/// The format of the UUID is as follows:
///
/// | 0-47           | 48-51      | 52-63      | 64-65    | 66-127 |
/// | -------------- | ---------- | ---------- | -------- | ------ |
/// | Timestamp (ms) | Ver (0111) | Microsecs  | Var (10) | Random |
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId {
    id: Uuid,
}

impl RequestId {
    /// Create a new request id from the current system time and a random number.
    pub fn new() -> Self {
        let now = SystemTime::now();
        let offset = match now.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(offset) => offset,
            Err(_) => SystemTime::UNIX_EPOCH
                .duration_since(now)
                .expect("SystemTime cannot be represented as a duration since the Unix epoch"),
        };

        let timestamp = offset.as_micros();

        // If this code is still in use on Jan 10, 294247, I'm sorry, but you're going to deal with
        // this wrapping back to Dec 22, 290309 BCE.
        let timestamp = timestamp as i64;
        Self::from_microseconds(timestamp)
    }

    /// Create a new request id from the given timestamp, in seconds from the Unix epoch (January 1, 1970 at
    /// 00:00:00 UTC) and a random number.
    pub fn from_timestamp_and_random(unix_timestamp: i64, random: u64) -> Self {
        let microseconds = unix_timestamp * 1_000_000;
        Self::from_microseconds_and_random(microseconds, random)
    }

    /// Create a new request id from the given timestamp, in microseconds from the Unix epoch (January 1, 1970 at
    /// 00:00:00 UTC).
    pub fn from_microseconds(ts_microseconds: i64) -> Self {
        Self::from_microseconds_and_random(ts_microseconds, random())
    }

    /// Create a new request id from the given timestamp, in microseconds from the Unix epoch (January 1, 1970 at
    /// 00:00:00 UTC) and a random number.
    pub fn from_microseconds_and_random(ts_microseconds: i64, random: u64) -> Self {
        let mut bytes = [0u8; 16];

        let milliseconds = ts_microseconds / 1_000;
        let microseconds = ts_microseconds % 1_000;

        // Version and microseconds are combined into a single 16-bit field.
        let ver_and_microseconds = ((microseconds as u16) & 0x0FFF) | (0b0111 << 12);

        // Random is combined with the variant into a single 64-bit field.
        let var_and_random = (random & 0x3FFF_FFFF_FFFF_FFFF) | (0b10 << 62);

        bytes[0..6].copy_from_slice(&milliseconds.to_be_bytes()[2..8]);
        bytes[6..8].copy_from_slice(&ver_and_microseconds.to_be_bytes());
        bytes[8..16].copy_from_slice(&var_and_random.to_be_bytes());

        Self {
            id: Uuid::from_bytes(bytes),
        }
    }

    /// Create a new request id from the given timestamp and random number.
    #[inline(always)]
    pub fn from_datetime_and_random<Tz: TimeZone>(datetime: DateTime<Tz>, random: u64) -> Self {
        let microseconds = datetime.timestamp_micros();
        Self::from_microseconds_and_random(microseconds, random)
    }

    /// Create a new request id from the given timestamp, in seconds from the Unix epoch (January 1, 1970 at
    /// 00:00:00 UTC).
    pub fn from_timestamp(unix_timestamp: i64) -> Self {
        let random: u64 = random();
        Self::from_timestamp_and_random(unix_timestamp, random)
    }

    /// Create a new request id from the given timestamp.
    #[inline(always)]
    pub fn from_datetime<Tz: TimeZone>(datetime: DateTime<Tz>) -> Self {
        let microseconds = datetime.timestamp_micros();
        Self::from_microseconds_and_random(microseconds, random())
    }

    /// Returns the Unix timestamp, in seconds from the Unix epoch (January 1, 1970 at 00:00:00 UTC), embedded in
    /// this request id.
    #[inline(always)]
    pub fn unix_timestamp(&self) -> u64 {
        let milliseconds = u64::from_be_bytes(self.id.as_bytes()[0..8].try_into().unwrap());
        milliseconds / 1_000
    }

    /// Returns the microseconds from the Unix epoch (January 1, 1970 at 00:00:00 UTC) embedded in this request id.
    #[inline(always)]
    pub fn microseconds(&self) -> i64 {
        let milliseconds = u64::from_be_bytes(self.id.as_bytes()[0..8].try_into().unwrap());
        let ver_and_microseconds = u16::from_be_bytes(self.id.as_bytes()[8..10].try_into().unwrap());
        let microseconds = (ver_and_microseconds & 0x0FFF) as i64;
        (milliseconds as i64) * 1_000 + microseconds
    }

    /// Returns the timestamp embedded in this request id.
    #[inline(always)]
    pub fn datetime(&self) -> DateTime<Utc> {
        let microseconds = self.microseconds();
        Utc.timestamp_opt(microseconds / 1_000_000, ((microseconds % 1_000_000) * 1000) as u32).unwrap()
    }

    /// Returns this request id as a UUID.
    #[inline(always)]
    pub fn uuid(&self) -> Uuid {
        self.id
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.id)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(RequestId {
            id: Uuid::deserialize(deserializer)?,
        })
    }
}

impl FromStr for RequestId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RequestId {
            id: Uuid::parse_str(s)?,
        })
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.id.to_string())
    }
}

#[cfg(feature = "axum")]
impl<S> axum::extract::FromRequestParts<S> for RequestId
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(request_id) = parts.extensions.get::<RequestId>() {
            Ok(*request_id)
        } else {
            let request_id = RequestId::new();
            parts.extensions.insert(request_id);
            Ok(request_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        uuid::{Uuid, Variant},
    };

    #[test_log::test]
    fn test_create_request_id() {
        let request_id = RequestId::new();
        println!("Request ID: {request_id}");
    }

    #[test_log::test]
    fn check_uuid_v7_compatibility() {
        let request_id = RequestId::new();
        let uuid_now = Uuid::now_v7();
        let uuid = request_id.uuid();
        assert_eq!(uuid.get_variant(), Variant::RFC4122);
        assert_eq!(uuid.get_version_num(), 7);
        assert!(uuid.get_timestamp().is_some());

        let request_id_timestamp = uuid.get_timestamp().unwrap().to_unix().0;
        let uuid_now_timestamp = uuid_now.get_timestamp().unwrap().to_unix().0;

        // The timestamps should be within a few seconds of each other, since they were generated at
        // roughly the same time. We allow a large window here (2 minutes) to account for any delays in the
        // test execution.
        assert!((request_id_timestamp as i64 - uuid_now_timestamp as i64).abs() < 120);
    }
}
