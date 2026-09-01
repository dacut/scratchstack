//! AWS request id implementation.
//!
//! This implementation uses the UUIDv7 format to embed a timestamp in the UUID, to make it easier to track down the
//! request in the logs. The timestamp has a resolution of 1 microsecond.

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
/// This implementation uses the UUIDv7 format to embed a timestamp in the UUID, to make it easier to track down the
/// request in the logs. The timestamp has a resolution of 1 microsecond and is based on the system clock, so it is not
/// guaranteed to be unique; a random number is embedded alongside it.
///
/// The bit layout is:
///
/// | 0-47           | 48-51      | 52-63     | 64-65    | 66-127 |
/// | -------------- | ---------- | --------- | -------- | ------ |
/// | Timestamp (ms) | Ver (0111) | Microsecs | Var (10) | Random |
///
/// The whole-millisecond part of the timestamp occupies the first 48 bits, and the remainder, 0 through 999
/// microseconds, shares the following 16 bits with the version nibble. [`RequestId::microseconds`] recombines the two.
///
/// Timestamps before the Unix epoch are not representable: the layout has no sign bit, and negative inputs to the
/// constructors below produce a request id whose accessors do not round-trip.
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
        self.milliseconds() / 1_000
    }

    /// Returns the microseconds from the Unix epoch (January 1, 1970 at 00:00:00 UTC) embedded in this request id.
    #[inline(always)]
    pub fn microseconds(&self) -> i64 {
        let ver_and_microseconds = u16::from_be_bytes(self.id.as_bytes()[6..8].try_into().unwrap());
        let microseconds = (ver_and_microseconds & 0x0FFF) as i64;
        (self.milliseconds() as i64) * 1_000 + microseconds
    }

    /// Returns the milliseconds from the Unix epoch held in the first 48 bits of this request id.
    #[inline(always)]
    fn milliseconds(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes[2..8].copy_from_slice(&self.id.as_bytes()[0..6]);
        u64::from_be_bytes(bytes)
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

impl From<&RequestId> for String {
    fn from(request_id: &RequestId) -> Self {
        request_id.to_string()
    }
}

impl From<RequestId> for String {
    fn from(request_id: RequestId) -> Self {
        request_id.to_string()
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
    fn timestamp_accessors_round_trip() {
        // 2024-01-01T00:00:00Z. These accessors read the milliseconds out of the first 48 bits and
        // the microsecond remainder out of the next 16; reading the wrong ranges made
        // unix_timestamp off by a factor of 65536 and made microseconds overflow.
        let secs: i64 = 1_704_067_200;
        let id = RequestId::from_timestamp_and_random(secs, 0x0123_4567_89AB_CDEF);

        assert_eq!(id.unix_timestamp(), secs as u64);
        assert_eq!(id.microseconds(), secs * 1_000_000);
        assert_eq!(id.datetime().timestamp(), secs);

        // Agree with the uuid crate's own view of the same bits.
        assert_eq!(id.uuid().get_timestamp().unwrap().to_unix().0, secs as u64);
    }

    #[test_log::test]
    fn sub_millisecond_component_survives() {
        // The microsecond remainder shares its 16 bits with the version nibble, so it has to be
        // masked back out rather than read whole.
        let micros = 1_704_067_200_000_123;
        let id = RequestId::from_microseconds(micros);

        assert_eq!(id.microseconds(), micros);
        assert_eq!(id.unix_timestamp(), 1_704_067_200);
        assert_eq!(id.datetime().timestamp_micros(), micros);

        // 999 is the largest remainder that fits; 1000 would carry into the milliseconds.
        for remainder in [0, 1, 500, 999] {
            let id = RequestId::from_microseconds(1_704_067_200_000_000 + remainder);
            assert_eq!(id.microseconds(), 1_704_067_200_000_000 + remainder, "remainder {remainder}");
        }
    }

    #[test_log::test]
    fn accessors_agree_with_generated_ids() {
        // A freshly generated id must also read back sensibly; new() is the common path.
        let id = RequestId::new();
        let from_micros = RequestId::from_microseconds(id.microseconds());
        assert_eq!(from_micros.microseconds(), id.microseconds());
        assert_eq!(from_micros.unix_timestamp(), id.unix_timestamp());
        assert_eq!(id.datetime().timestamp_micros(), id.microseconds());
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
