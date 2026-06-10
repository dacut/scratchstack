use {
    crate::{KeyLengthError, constants::*, crypto::hmac_sha256},
    chrono::NaiveDate,
    derive_builder::Builder,
    scratchstack_aws_principal::{Principal, SessionData},
    serde::{
        Deserialize, Serialize,
        de::{Deserializer, Visitor},
        ser::Serializer,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        future::Future,
        str::FromStr,
    },
    subtle::{Choice, ConstantTimeEq},
    tower::{BoxError, service_fn, util::ServiceFn},
    zeroize::{Zeroize, ZeroizeOnDrop},
};

/// A raw AWS secret key (`kSecret`).
///
/// The key material is heap-allocated, zeroized on drop, compared in constant time, and redacted
/// from the [`Debug`] and [`Display`] implementations. Some care is still required when handling
/// this type:
/// * The [`Serialize`] implementation emits the raw secret key. Only serialize this type into a
///   buffer that is subsequently encrypted and zeroized, such as the default session token
///   format.
/// * [`FromStr`] copies the key from a caller-owned string that this type cannot scrub. Zeroize
///   the source string if it is not short-lived.
/// * Protecting key material from swap and core dumps (encrypted swap, `RLIMIT_CORE`, etc.) is a
///   deployment concern that this type does not address.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KSecretKey {
    /// The secret key, prefixed with "AWS4".
    prefixed_key: Box<[u8]>,
}

/// The `kDate` key: `HMAC_SHA256("AWS4" + KSecretKey, "YYYYMMDD")`
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KDateKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

/// The `kRegion` key: an AWS `kDate` key, HMAC-SHA256 hashed with the region.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KRegionKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

/// The `kService` key: an AWS `kRegion` key, HMAC-SHA256 hashed with the service.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KServiceKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

/// The `kSigning` key: an AWS `kService` key, HMAC-SHA256 hashed with the "aws4_request" string.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KSigningKey {
    /// The resulting raw signing key.
    key: [u8; SHA256_OUTPUT_LEN],
}

impl KSecretKey {
    /// Create a new `KDateKey` from this `KSecretKey` and a date.
    pub fn to_kdate(&self, date: NaiveDate) -> KDateKey {
        let date = date.format("%Y%m%d").to_string();
        KDateKey {
            key: hmac_sha256(&self.prefixed_key, date.as_bytes()),
        }
    }

    /// Create a new `KRegionKey` from this `KSecretKey`, a date, and a region.
    pub fn to_kregion(&self, date: NaiveDate, region: &str) -> KRegionKey {
        self.to_kdate(date).to_kregion(region)
    }

    /// Create a new `KServiceKey` from this `KSecretKey`, a date, a region, and a service.
    pub fn to_kservice(&self, date: NaiveDate, region: &str, service: &str) -> KServiceKey {
        self.to_kdate(date).to_kservice(region, service)
    }

    /// Create a new `KSigningKey` from this `KSecretKey`, a date, a region, and a service.
    pub fn to_ksigning(&self, date: NaiveDate, region: &str, service: &str) -> KSigningKey {
        self.to_kdate(date).to_ksigning(region, service)
    }
}

impl AsRef<[u8]> for KSecretKey {
    fn as_ref(&self) -> &[u8] {
        // Remove the "AWS4" prefix.
        &self.prefixed_key[4..]
    }
}

impl ConstantTimeEq for KSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.prefixed_key.ct_eq(&other.prefixed_key)
    }
}

impl Eq for KSecretKey {}

impl PartialEq for KSecretKey {
    /// Compares the keys in constant time.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Debug for KSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSecretKey")
    }
}

impl<'de> Deserialize<'de> for KSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KSecretKeyVisitor;

        impl Visitor<'_> for KSecretKeyVisitor {
            type Value = KSecretKey;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("AWS secret key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                KSecretKey::from_str(v).map_err(|e| E::custom(format!("invalid key length: {e}")))
            }
        }

        deserializer.deserialize_str(KSecretKeyVisitor)
    }
}

impl Display for KSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSecretKey")
    }
}

impl FromStr for KSecretKey {
    type Err = KeyLengthError;

    /// Create a new `KSecretKey` from a raw AWS secret key.
    ///
    /// This copies the key out of `raw`; zeroize the source string if it is not short-lived.
    fn from_str(raw: &str) -> Result<Self, KeyLengthError> {
        let len = raw.len();
        if len == 0 {
            return Err(KeyLengthError::TooShort);
        }

        // Reserve the exact size up front so the buffer is never reallocated; a reallocation
        // would leave an unscrubbed copy of the key on the heap.
        let mut prefixed_key = Vec::with_capacity(4 + len);
        prefixed_key.extend_from_slice(b"AWS4");
        prefixed_key.extend_from_slice(raw.as_bytes());
        Ok(Self {
            prefixed_key: prefixed_key.into_boxed_slice(),
        })
    }
}

/// Serializes the **raw secret key**, bypassing the redaction that `Debug` and `Display`
/// provide. Only serialize a `KSecretKey` into a buffer that is subsequently encrypted and
/// zeroized, such as the default session token format.
impl Serialize for KSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let prefixed_key_str = str::from_utf8(&self.prefixed_key[4..])
            .map_err(|e| serde::ser::Error::custom(format!("invalid UTF-8 in key: {e}")))?;
        serializer.serialize_str(prefixed_key_str)
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KDateKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KRegionKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KServiceKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KSigningKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl ConstantTimeEq for KDateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl ConstantTimeEq for KRegionKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl ConstantTimeEq for KServiceKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl ConstantTimeEq for KSigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl Debug for KDateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KDateKey")
    }
}

impl Debug for KRegionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KRegionKey")
    }
}

impl Debug for KServiceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KServiceKey")
    }
}

impl Debug for KSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSigningKey")
    }
}

impl Display for KDateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KDateKey")
    }
}

impl Display for KRegionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KRegionKey")
    }
}

impl Display for KServiceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KServiceKey")
    }
}

impl Display for KSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSigningKey")
    }
}

impl Eq for KDateKey {}

impl Eq for KRegionKey {}

impl Eq for KServiceKey {}

impl Eq for KSigningKey {}

impl PartialEq for KDateKey {
    /// Compares the keys in constant time.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl PartialEq for KRegionKey {
    /// Compares the keys in constant time.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl PartialEq for KServiceKey {
    /// Compares the keys in constant time.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl PartialEq for KSigningKey {
    /// Compares the keys in constant time.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl KDateKey {
    /// Create a new `KRegionKey` from this `KDateKey` and a region.
    pub fn to_kregion(&self, region: &str) -> KRegionKey {
        KRegionKey {
            key: hmac_sha256(self.key.as_slice(), region.as_bytes()),
        }
    }

    /// Create a new `KServiceKey` from this `KDateKey`, a region, and a service.
    pub fn to_kservice(&self, region: &str, service: &str) -> KServiceKey {
        self.to_kregion(region).to_kservice(service)
    }

    /// Create a new `KSigningKey` from this `KDateKey`, a region, and a service.
    pub fn to_ksigning(&self, region: &str, service: &str) -> KSigningKey {
        self.to_kregion(region).to_ksigning(service)
    }
}

impl KRegionKey {
    /// Create a new `KServiceKey` from this `KRegionKey` and a service.
    pub fn to_kservice(&self, service: &str) -> KServiceKey {
        KServiceKey {
            key: hmac_sha256(self.key.as_slice(), service.as_bytes()),
        }
    }

    /// Create a new `KSigningKey` from this `KRegionKey` and a service.
    pub fn to_ksigning(&self, service: &str) -> KSigningKey {
        self.to_kservice(service).to_ksigning()
    }
}

impl KServiceKey {
    /// Create a new `KSigningKey` from this `KServiceKey`.
    pub fn to_ksigning(&self) -> KSigningKey {
        KSigningKey {
            key: hmac_sha256(self.key.as_slice(), AWS4_REQUEST.as_bytes()),
        }
    }
}

/// A request for a signing key of a given kind for the specified request.
///
/// GetSigningKeyRequest structs are immutable. Use [`GetSigningKeyRequestBuilder`] to programmatically construct a
/// request.
#[derive(Builder, Clone)]
#[non_exhaustive]
pub struct GetSigningKeyRequest {
    /// The access key used in the request.
    #[builder(setter(into))]
    access_key: String,

    /// The session token provided in the request, if any.
    #[builder(setter(into), default)]
    session_token: Option<String>,

    /// The date of the request.
    request_date: NaiveDate,

    /// The region of the request.
    #[builder(setter(into))]
    region: String,

    /// The service of the request.
    #[builder(setter(into))]
    service: String,
}

impl GetSigningKeyRequest {
    /// Create a [GetSigningKeyRequestBuilder] to construct a [GetSigningKeyRequest].
    #[inline]
    pub fn builder() -> GetSigningKeyRequestBuilder {
        GetSigningKeyRequestBuilder::default()
    }

    /// Retrieve the access key used in the request.
    #[inline]
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    /// Retrieve the session token provided in the request, if any.
    #[inline]
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    /// Retrieve the date of the request.
    #[inline]
    pub fn request_date(&self) -> NaiveDate {
        self.request_date
    }

    /// Retrieve the region of the request.
    #[inline]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Retrieve the service of the request.
    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }
}

impl Debug for GetSigningKeyRequest {
    /// Formats the request with the session token redacted: the token is bearer-credential
    /// material and must not end up in logs.
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("GetSigningKeyRequest")
            .field("access_key", &self.access_key)
            .field("session_token", &"<redacted>")
            .field("request_date", &self.request_date)
            .field("region", &self.region)
            .field("service", &self.service)
            .finish()
    }
}

/// A response from the signing key provider.
///
/// GetSigningKeyResponse structs are immutable. Use [GetSigningKeyResponseBuilder] to programmatically construct a
/// response.
#[derive(Builder, Clone, Debug)]
pub struct GetSigningKeyResponse {
    /// The principal actors of the request.
    #[builder(setter(into))]
    pub(crate) principal: Principal,

    /// The session data associated with the principal.
    #[builder(setter(into), default)]
    pub(crate) session_data: SessionData,

    /// The signing key.
    pub(crate) signing_key: KSigningKey,
}

impl GetSigningKeyResponse {
    /// Create a [`GetSigningKeyResponseBuilder`] to construct a `GetSigningKeyResponse`.
    #[inline]
    pub fn builder() -> GetSigningKeyResponseBuilder {
        GetSigningKeyResponseBuilder::default()
    }

    /// Retrieve the principal actors of the request.
    #[inline]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Retrieve the session data associated with the principal.
    #[inline]
    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }

    /// Retrieve the signing key.
    #[inline]
    pub fn signing_key(&self) -> &KSigningKey {
        &self.signing_key
    }
}

// A trait alias that describes how we obtain a signing key of a given type given a request. If you need to encapsulate
// additional data (e.g. a database connection) to look up a key, use this to implement a struct.
//
// This requires the trait_alias feature to be stabilized and is commented out until then.
// https://github.com/rust-lang/rust/issues/41517
//
// I find trait bounds annoying since they have to be repeated everywhere.
//
// pub trait GetSigningKey<F> = Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static;

/// Create a Service that wraps a function that can produce a signing key.
pub fn service_for_signing_key_fn<F, Fut>(f: F) -> ServiceFn<F>
where
    F: FnOnce(GetSigningKeyRequest) -> Fut + Send + 'static,
    Fut: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send + 'static,
{
    service_fn(f)
}

#[cfg(test)]
mod tests {
    use {
        crate::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey},
        chrono::NaiveDate,
        scratchstack_aws_principal::{AssumedRole, Principal},
        std::str::FromStr,
    };

    #[test_log::test]
    fn test_signing_key_derived() {
        let date = NaiveDate::from_ymd_opt(2015, 8, 30).unwrap();

        let ksecret1a = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let ksecret1b = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let ksecret2 = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCZEXAMPLEKEY").unwrap();

        assert_eq!(ksecret1a, ksecret1b);
        assert_eq!(ksecret1a, ksecret1a.clone());
        assert_ne!(ksecret1a, ksecret2);
        assert_eq!(format!("{:?}", ksecret1a).as_str(), "KSecretKey");
        assert_eq!(format!("{}", ksecret1a).as_str(), "KSecretKey");
        assert_eq!(ksecret1a.as_ref(), b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

        let kdate1a = ksecret1a.to_kdate(date);
        let kdate1b = ksecret1b.to_kdate(date);
        let kdate2 = ksecret2.to_kdate(date);
        assert_eq!(
            kdate1a.as_ref(),
            &[
                0x01u8, 0x38u8, 0xc7u8, 0xa6u8, 0xcbu8, 0xd6u8, 0x0au8, 0xa7u8, 0x27u8, 0xb2u8, 0xf6u8, 0x53u8, 0xa5u8,
                0x22u8, 0x56u8, 0x74u8, 0x39u8, 0xdfu8, 0xb9u8, 0xf3u8, 0xe7u8, 0x2bu8, 0x21u8, 0xf9u8, 0xb2u8, 0x59u8,
                0x41u8, 0xa4u8, 0x2fu8, 0x04u8, 0xa7u8, 0xcdu8
            ]
        );
        assert_eq!(kdate1a, kdate1b);
        assert_eq!(kdate1a, kdate1a.clone());
        assert_ne!(kdate1a, kdate2);
        assert_eq!(format!("{:?}", kdate1a).as_str(), "KDateKey");
        assert_eq!(format!("{}", kdate1a).as_str(), "KDateKey");

        let kregion1a = kdate1a.to_kregion("us-east-1");
        let kregion1b = kdate1b.to_kregion("us-east-1");
        let kregion2 = kdate2.to_kregion("us-east-1");
        assert_eq!(
            kregion1a.as_ref(),
            &[
                0xf3u8, 0x3du8, 0x58u8, 0x08u8, 0x50u8, 0x4bu8, 0xf3u8, 0x48u8, 0x12u8, 0xe5u8, 0xfau8, 0xdeu8, 0x63u8,
                0x30u8, 0x8bu8, 0x42u8, 0x4bu8, 0x24u8, 0x4cu8, 0x59u8, 0x18u8, 0x9bu8, 0xe2u8, 0xa5u8, 0x91u8, 0xddu8,
                0x22u8, 0x82u8, 0xc7u8, 0xcbu8, 0x56u8, 0x3fu8
            ]
        );
        assert_eq!(kregion1a, kregion1b);
        assert_eq!(kregion1a, kregion1a.clone());
        assert_ne!(kregion1a, kregion2);
        assert_eq!(format!("{:?}", kregion1a).as_str(), "KRegionKey");
        assert_eq!(format!("{}", kregion1a).as_str(), "KRegionKey");

        let kservice1a = kregion1a.to_kservice("example");
        let kservice1b = kregion1b.to_kservice("example");
        let kservice2 = kregion2.to_kservice("example");
        assert_eq!(
            kservice1a.as_ref(),
            &[
                0xc6u8, 0x0cu8, 0xc4u8, 0xb1u8, 0xd0u8, 0x34u8, 0xc7u8, 0x57u8, 0x34u8, 0x8fu8, 0x2cu8, 0x67u8, 0x30u8,
                0x04u8, 0xc1u8, 0x89u8, 0x08u8, 0xbbu8, 0xa9u8, 0xa4u8, 0x6fu8, 0xa1u8, 0xdbu8, 0x87u8, 0xa9u8, 0x83u8,
                0x50u8, 0xf2u8, 0x7eu8, 0x7bu8, 0x2du8, 0xf6u8
            ]
        );
        assert_eq!(kservice1a, kservice1b);
        assert_eq!(kservice1a, kservice1a.clone());
        assert_ne!(kservice1a, kservice2);
        assert_eq!(format!("{:?}", kservice1a).as_str(), "KServiceKey");
        assert_eq!(format!("{}", kservice1a).as_str(), "KServiceKey");

        let ksigning1a = kservice1a.to_ksigning();
        let ksigning1b = kservice1b.to_ksigning();
        let ksigning2 = kservice2.to_ksigning();
        assert_eq!(
            ksigning1a.as_ref(),
            &[
                0x43u8, 0x1cu8, 0xc9u8, 0xefu8, 0x58u8, 0x76u8, 0x28u8, 0x7du8, 0xbbu8, 0x92u8, 0x5du8, 0x4bu8, 0xa4u8,
                0x62u8, 0x9fu8, 0x45u8, 0x90u8, 0x02u8, 0xadu8, 0x1du8, 0x26u8, 0xb7u8, 0xc7u8, 0x51u8, 0x60u8, 0x1bu8,
                0xb2u8, 0x04u8, 0xe1u8, 0x17u8, 0x18u8, 0xb8u8
            ]
        );
        assert_eq!(ksigning1a, ksigning1b);
        assert_eq!(ksigning1a, ksigning1a.clone());
        assert_ne!(ksigning1a, ksigning2);
        assert_eq!(format!("{:?}", ksigning1a).as_str(), "KSigningKey");
        assert_eq!(format!("{}", ksigning1a).as_str(), "KSigningKey");

        assert_eq!(ksecret1a.to_kregion(date, "us-east-1"), kregion1a);
        assert_eq!(ksecret1a.to_kservice(date, "us-east-1", "example"), kservice1a);
        assert_eq!(ksecret1a.to_ksigning(date, "us-east-1", "example"), ksigning1a);

        assert_eq!(kdate1a.to_kservice("us-east-1", "example"), kservice1a);
        assert_eq!(kdate1a.to_ksigning("us-east-1", "example"), ksigning1a);

        assert_eq!(kregion1a.to_kservice("example"), kservice1a);
    }

    #[test_log::test]
    fn test_gsk_derived() {
        let date = NaiveDate::from_ymd_opt(2015, 8, 30).unwrap();

        let gsk_req1a = GetSigningKeyRequest {
            access_key: "AKIDEXAMPLE".to_string(),
            session_token: Some("token".to_string()),
            request_date: date,
            region: "us-east-1".to_string(),
            service: "example".to_string(),
        };

        // Make sure we can debug print the request, and that the session token is redacted.
        let debug = format!("{gsk_req1a:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("\"token\""));

        // Make sure clones are field-by-field equal.
        let gsk_req1b = gsk_req1a.clone();
        assert_eq!(gsk_req1a.access_key, gsk_req1b.access_key);
        assert_eq!(gsk_req1a.session_token, gsk_req1b.session_token);
        assert_eq!(gsk_req1a.request_date, gsk_req1b.request_date);
        assert_eq!(gsk_req1a.region, gsk_req1b.region);
        assert_eq!(gsk_req1a.service, gsk_req1b.service);

        let signing_key = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap().to_ksigning(
            date,
            "us-east-1",
            "example",
        );
        let principal = Principal::from(AssumedRole::new("aws", "123456789012", "role", "session").unwrap());

        let gsk_resp1a =
            GetSigningKeyResponse::builder().signing_key(signing_key).principal(principal).build().unwrap();

        // Make sure we can debug print the response.
        let _ = format!("{:?}", gsk_resp1a);

        // Make sure clones are field-by-field equal.
        let gsk_resp1b = gsk_resp1a.clone();
        assert_eq!(gsk_resp1a.signing_key, gsk_resp1b.signing_key);
        assert_eq!(gsk_resp1a.principal, gsk_resp1b.principal);
    }

    #[test_log::test]
    fn test_response_builder() {
        let date = NaiveDate::from_ymd_opt(2015, 8, 30).unwrap();
        let signing_key = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap().to_ksigning(
            date,
            "us-east-1",
            "example",
        );
        let principal = Principal::from(AssumedRole::new("aws", "123456789012", "role", "session").unwrap());
        let response = GetSigningKeyResponse::builder().principal(principal).signing_key(signing_key).build().unwrap();
        assert!(response.principal().as_assumed_role().is_some());
        assert!(response.session_data().is_empty());
    }

    #[test]
    fn test_key_from_str_length() {
        assert_eq!(KSecretKey::from_str(""), Err(crate::KeyLengthError::TooShort));
        assert!(KSecretKey::from_str("1234567890123456789012345678901234567890").is_ok());
    }
}
