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
/// This implementation abuses the UUID format the embed a timestamp in the UUID to make it easier to track down the
/// request in the logs. This timestamp has a resolution of 1s and is based on the system clock, so it's not guaranteed
/// to be unique; thus, a random number is also embedded in the UUID.
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

        let timestamp = offset.as_secs();
        Self::from_timestamp(timestamp as i64)
    }

    /// Create a new request id from the given timestamp, in seconds from the Unix epoch (January 1, 1970 at
    /// 00:00:00 UTC) and random number.
    pub fn from_timestamp_and_random(unix_timestamp: i64, random: u64) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&unix_timestamp.to_be_bytes());
        bytes[8..16].copy_from_slice(&random.to_be_bytes());

        Self {
            id: Uuid::from_bytes(bytes),
        }
    }

    /// Create a new request id from the given timestamp and random number.
    pub fn from_datetime_and_random<Tz: TimeZone>(datetime: DateTime<Tz>, random: u64) -> Self {
        let unix_timestamp = datetime.timestamp();
        Self::from_timestamp_and_random(unix_timestamp, random)
    }

    /// Create a new request id from the given timestamp, in seconds from the Unix epoch (January 1, 1970 at
    /// 00:00:00 UTC).
    pub fn from_timestamp(unix_timestamp: i64) -> Self {
        let random: u64 = random();
        Self::from_timestamp_and_random(unix_timestamp, random)
    }

    /// Create a new request id from the given timestamp.
    pub fn from_datetime<Tz: TimeZone>(datetime: DateTime<Tz>) -> Self {
        let unix_timestamp = datetime.timestamp();
        Self::from_timestamp(unix_timestamp)
    }

    /// Returns the Unix timestamp, in seconds from the Unix epoch (January 1, 1970 at 00:00:00 UTC), embedded in
    /// this request id.
    #[inline]
    pub fn unix_timestamp(&self) -> u64 {
        u64::from_be_bytes(self.id.as_bytes()[0..8].try_into().unwrap())
    }

    /// Returns the timestamp embedded in this request id.
    #[inline]
    pub fn datetime(&self) -> DateTime<Utc> {
        Utc.timestamp(self.unix_timestamp() as i64, 0)
    }

    /// Returns this request id as a UUID.
    #[inline]
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
