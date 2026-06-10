//! Default session token extractor implementation.
use {
    crate::{ExtractSessionToken, SessionTokenData, SignatureError},
    aes_gcm::{AeadInPlace as _, Aes256Gcm, Key as AesKey, KeyInit as _, Nonce},
    base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD},
    std::{
        collections::HashMap,
        future::Future,
        marker::PhantomData,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::Service,
    zeroize::Zeroizing,
};

/// The length of an AWS account id in characters/bytes.
const ACCOUNT_ID_LENGTH: usize = 12;

/// The current token version (ASCII `0`).
pub const CURRENT_TOKEN_VERSION: u8 = b'0';

/// The length of the nonce used for AES256-GCM encryption in bytes.
const NONCE_LENGTH: usize = 12;

/// The length of the keys used for AES256-GCM encryption in bytes.
const AES256_KEY_LENGTH: usize = 32;

/// The default Scratchstack implementation of the `ExtractSessionToken` trait that relies on the
/// [postcard] serialization format. This is enabled by the `default_session_token` feature.
///
/// The format of the session token used in this implementation is:
/// * Version: 1 byte, currently always ASCII `0`.
/// * Base64Payload: base-64 encoded string representing an [`EncryptedSessionTokenData`] struct.
#[derive(Clone)]
pub struct DefaultSessionTokenExtractor<KeyService> {
    /// An underlying Tower service that converts a `KeyId` into an AES256-GCM key for decrypting
    /// the session token data.
    key_service: KeyService,
}

/// The encrypted session token data.
///
/// This is parsed from the Base64Payload of the session token. After base64 decoding, the format
/// of the encrypted session token data is:
/// * KeyIdLength: u8
/// * KeyId: variable length, an ASCII string representing the KeyId of the signing key associated
///   with the session token.
/// * AccountId: 12 bytes, the 12-digit AWS account ID associated with the session token,
///   represented as an ASCII string.
/// * Nonce: 12 bytes, a random nonce used for AES256-GCM encryption.
/// * EncryptedPayloadLength: u32 in little-endian format
/// * EncryptedPayload: variable length AES256-GCM encrypted data with associated authentication
///   tag of
///   "AccountId=<i>account-id</i>". The underlying plaintext data is a postcard-serialized
///   `SessionTokenData` struct.
#[derive(Clone)]
pub struct EncryptedSessionTokenData {
    /// The KeyId of the signing key associated with the session token.
    key_id: String,

    /// The AWS account ID associated with the session token.
    account_id: String,

    /// The nonce used for AES256-GCM encryption.
    nonce: [u8; NONCE_LENGTH],

    /// The AES256-GCM encrypted session token data. The associated authentication tag is
    /// "AccountId=<i>account-id</i>".
    encrypted_payload: Vec<u8>,
}

/// A static key service, primarily for testing.
#[derive(Clone)]
#[repr(transparent)]
pub struct StaticKeyService(pub HashMap<String, [u8; AES256_KEY_LENGTH]>);

impl<KeyService> DefaultSessionTokenExtractor<KeyService> {
    /// Create a new `DefaultSessionTokenExtractor` with the given key service.
    pub fn new(key_service: KeyService) -> Self {
        Self {
            key_service,
        }
    }
}

impl<KeyService> DefaultSessionTokenExtractor<KeyService>
where
    KeyService: Service<String, Response = [u8; AES256_KEY_LENGTH], Error = SignatureError> + Clone + Send + 'static,
    KeyService::Future: Send,
{
    /// Extract the session token data from the given session token string.
    async fn extract(&mut self, session_token: &[u8]) -> Result<SessionTokenData, SignatureError> {
        let EncryptedSessionTokenData {
            key_id,
            account_id,
            nonce,
            encrypted_payload,
        } = EncryptedSessionTokenData::from_session_token(session_token)?;
        // After decryption, this buffer holds the plaintext token data -- including the raw
        // secret key -- so it must be zeroized on every exit path.
        let mut payload = Zeroizing::new(encrypted_payload);
        let key: AesKey<Aes256Gcm> = self.key_service.call(key_id).await?.into();
        let nonce = Nonce::from_slice(&nonce);
        let associated_data = format!("AccountId={account_id}");
        let cipher = Aes256Gcm::new(&key);

        cipher
            .decrypt_in_place(nonce, associated_data.as_bytes(), &mut *payload)
            .map_err(|_| invalid_session_token_error())?;

        let (result, remainder) =
            postcard::take_from_bytes(payload.as_slice()).map_err(|_| invalid_session_token_error())?;
        if !remainder.is_empty() {
            return Err(invalid_session_token_error());
        }

        Ok(result)
    }
}

impl<KeyService> Service<String> for DefaultSessionTokenExtractor<KeyService>
where
    KeyService: Service<String, Response = [u8; AES256_KEY_LENGTH], Error = SignatureError> + Clone + Send + 'static,
    KeyService::Future: Send,
{
    type Response = SessionTokenData;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.key_service.poll_ready(cx)
    }

    fn call(&mut self, session_token: String) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move { this.extract(session_token.as_bytes()).await })
    }
}

impl EncryptedSessionTokenData {
    /// Parse the encrypted session token data from the given byte slice.
    fn parse_encrypted_session_token_data(session_token: &[u8]) -> Result<Self, SignatureError> {
        if session_token.is_empty() {
            return Err(invalid_session_token_error());
        }

        let key_id_length = session_token[0] as usize;
        let key_id_start = 1;
        let key_id_end = key_id_start + key_id_length;
        if key_id_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let key_id = String::from_utf8(session_token[key_id_start..key_id_end].to_vec())
            .map_err(|_| invalid_session_token_error())?;

        let account_id_start = key_id_end;
        let account_id_end = account_id_start + ACCOUNT_ID_LENGTH;
        if account_id_end > session_token.len() {
            return Err(invalid_session_token_error());
        }

        let account_id = &session_token[account_id_start..account_id_end];
        if !account_id.iter().all(|&b| b.is_ascii_digit()) {
            return Err(invalid_session_token_error());
        }
        let account_id = String::from_utf8(account_id.to_vec()).map_err(|_| invalid_session_token_error())?;

        let nonce_start = account_id_end;
        let nonce_end = nonce_start + NONCE_LENGTH;
        if nonce_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let nonce: [u8; NONCE_LENGTH] =
            session_token[nonce_start..nonce_end].try_into().map_err(|_| invalid_session_token_error())?;

        let encrypted_payload_length_start = nonce_end;
        let encrypted_payload_length_end = encrypted_payload_length_start + 4;
        if encrypted_payload_length_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let encrypted_payload_length = u32::from_le_bytes(
            session_token[encrypted_payload_length_start..encrypted_payload_length_end]
                .try_into()
                .map_err(|_| invalid_session_token_error())?,
        ) as usize;
        let encrypted_payload_start = encrypted_payload_length_end;
        let encrypted_payload_end = encrypted_payload_start + encrypted_payload_length;
        if encrypted_payload_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let encrypted_payload = session_token[encrypted_payload_start..encrypted_payload_end].to_vec();

        Ok(Self {
            key_id,
            account_id,
            nonce,
            encrypted_payload,
        })
    }

    /// Parse a session token and return the parsed [`EncryptedSessionTokenData`].
    pub(crate) fn from_session_token(session_token: &[u8]) -> Result<Self, SignatureError> {
        if session_token.is_empty() {
            return Err(invalid_session_token_error());
        }

        if session_token[0] != CURRENT_TOKEN_VERSION {
            return Err(invalid_session_token_error());
        }

        URL_SAFE_NO_PAD
            .decode(&session_token[1..])
            .map_err(|_| invalid_session_token_error())
            .and_then(|decoded| Self::parse_encrypted_session_token_data(&decoded))
    }
}

impl Default for StaticKeyService {
    #[inline(always)]
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl StaticKeyService {
    /// Creates an empty `StaticKeyService`.
    #[inline(always)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty `StaticKeyService` with at least the specified capacity.
    #[inline(always)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }
}

impl Service<String> for StaticKeyService {
    type Response = [u8; AES256_KEY_LENGTH];
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, key_id: String) -> Self::Future {
        let key = self.0.get(&key_id).cloned();
        Box::pin(async move {
            key.ok_or_else(|| {
                SignatureError::InvalidSessionToken(format!("KeyId {key_id} not found in StaticKeyService"))
            })
        })
    }
}

/// Helper function to create a `SignatureError::InvalidSessionToken` error with a default message.
fn invalid_session_token_error() -> SignatureError {
    SignatureError::InvalidSessionToken("Invalid session token".to_string())
}

// Compile-time checks that `DefaultSessionTokenExtractor` satisfies the bounds the rest of the
// framework expects: the `Service` associated types (asserted individually so a mismatch produces
// a plain type error naming the offending type), a `Send` future, and `ExtractSessionToken`.
const _: () = {
    fn assert_extract_session_token<T: ExtractSessionToken>() {}
    fn assert_send<T: Send>() {}

    fn assoc<S: Service<R>, R>() -> (PhantomData<S::Response>, PhantomData<S::Error>) {
        (PhantomData, PhantomData)
    }

    #[allow(dead_code)]
    fn check<K>()
    where
        K: Service<String, Response = [u8; AES256_KEY_LENGTH], Error = SignatureError> + Clone + Send + 'static,
        K::Future: Send,
    {
        let (response, error) = assoc::<DefaultSessionTokenExtractor<K>, String>();
        let _: PhantomData<SessionTokenData> = response;
        let _: PhantomData<SignatureError> = error;
        assert_send::<<DefaultSessionTokenExtractor<K> as Service<String>>::Future>();
        assert_extract_session_token::<DefaultSessionTokenExtractor<K>>();
    }
};

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{KSecretKey, SessionTokenPermissions},
        chrono::{DateTime, Duration},
        scratchstack_aws_principal::{AssumedRole, SessionData, SessionValue},
        std::str::FromStr as _,
        tower::ServiceExt as _,
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";
    const TEST_KEY: [u8; AES256_KEY_LENGTH] = [0x42; AES256_KEY_LENGTH];
    const TEST_KEY_ID: &str = "test-key-1";
    const TEST_NONCE: [u8; NONCE_LENGTH] = [0x07; NONCE_LENGTH];

    /// Asserts that `result` is an `InvalidSessionToken` error carrying `expected_message`.
    fn assert_invalid_session_token<T>(result: Result<T, SignatureError>, expected_message: &str) {
        match result {
            Err(SignatureError::InvalidSessionToken(message)) => assert_eq!(message, expected_message),
            _ => panic!("expected Err(SignatureError::InvalidSessionToken), got Ok()"),
        }
    }

    /// Assembles the binary (pre-base64) form of an encrypted session token.
    fn build_token_body(key_id: &str, account_id: &str, encrypted_payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(key_id.len() as u8);
        body.extend_from_slice(key_id.as_bytes());
        body.extend_from_slice(account_id.as_bytes());
        body.extend_from_slice(&TEST_NONCE);
        body.extend_from_slice(&(encrypted_payload.len() as u32).to_le_bytes());
        body.extend_from_slice(encrypted_payload);
        body
    }

    /// Prefixes the version byte and base64-encodes `body` to form a session token string.
    fn encode_token(body: &[u8]) -> String {
        format!("{}{}", CURRENT_TOKEN_VERSION as char, URL_SAFE_NO_PAD.encode(body))
    }

    /// Encrypts `plaintext` in place with AES256-GCM using `key`, `TEST_NONCE`, and the
    /// "AccountId=<account_id>" associated data, returning the ciphertext with the appended tag.
    fn encrypt_payload(key: &[u8; AES256_KEY_LENGTH], account_id: &str, mut plaintext: Vec<u8>) -> Vec<u8> {
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
        cipher
            .encrypt_in_place(
                Nonce::from_slice(&TEST_NONCE),
                format!("AccountId={account_id}").as_bytes(),
                &mut plaintext,
            )
            .unwrap();
        plaintext
    }

    /// Serializes `data` into the postcard plaintext that a session token carries.
    fn serialize_session_token_data(data: &SessionTokenData) -> Vec<u8> {
        let mut buffer = [0u8; 4096];
        postcard::to_slice(data, &mut buffer).unwrap().to_vec()
    }

    /// Returns a `StaticKeyService` holding `TEST_KEY` under `TEST_KEY_ID`.
    fn test_key_service() -> StaticKeyService {
        let mut service = StaticKeyService::new();
        service.0.insert(TEST_KEY_ID.to_string(), TEST_KEY);
        service
    }

    /// Builds a complete, valid session token for `data`, encrypted with `TEST_KEY`.
    fn test_session_token(data: &SessionTokenData) -> String {
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(data));
        encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload))
    }

    /// Returns a representative `SessionTokenData` with an assumed-role principal.
    fn test_session_token_data() -> SessionTokenData {
        // 2026-01-01T00:00:00Z; a fixed timestamp since chrono's `clock` feature is not enabled.
        let issued_at = DateTime::from_timestamp(1_767_225_600, 0).unwrap();
        let mut metadata = SessionData::new();
        metadata.insert("MultiFactorAuthPresent", SessionValue::Bool(true));

        SessionTokenData {
            access_key_id: "ASIAEXAMPLEACCESSKEY".to_string(),
            secret_key: KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap(),
            principal: AssumedRole::new("aws", TEST_ACCOUNT_ID, "TestRole", "test-session").unwrap().into(),
            expires_at: issued_at + Duration::hours(1),
            issued_at,
            permissions: SessionTokenPermissions::None,
            session_name: "test-session".to_string(),
            metadata,
        }
    }

    #[tokio::test]
    async fn test_extractor_round_trip() {
        let expected = test_session_token_data();
        let token = test_session_token(&expected);
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        let actual = extractor.ready().await.unwrap().call(token).await.unwrap();
        assert_eq!(actual.access_key_id, expected.access_key_id);
        assert_eq!(actual.secret_key, expected.secret_key);
        assert_eq!(actual.principal, expected.principal);
        assert_eq!(actual.expires_at, expected.expires_at);
        assert_eq!(actual.issued_at, expected.issued_at);
        assert_eq!(actual.permissions, expected.permissions);
        assert_eq!(actual.session_name, expected.session_name);
        assert!(matches!(actual.metadata.get("MultiFactorAuthPresent"), Some(SessionValue::Bool(true))));
    }

    #[tokio::test]
    async fn test_extractor_unknown_key_id() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body("unknown-key", TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(token).await,
            "KeyId unknown-key not found in StaticKeyService",
        );
    }

    #[tokio::test]
    async fn test_extractor_wrong_key() {
        let wrong_key = [0x99; AES256_KEY_LENGTH];
        let payload =
            encrypt_payload(&wrong_key, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(extractor.ready().await.unwrap().call(token).await, "Invalid session token");
    }

    #[tokio::test]
    async fn test_extractor_tampered_account_id() {
        // The associated data says TEST_ACCOUNT_ID, but the token body claims a different
        // (well-formed) account id, so authentication must fail.
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, "999999999999", &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(extractor.ready().await.unwrap().call(token).await, "Invalid session token");
    }

    #[tokio::test]
    async fn test_extractor_undecodable_plaintext() {
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, vec![0xff; 4]);
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(extractor.ready().await.unwrap().call(token).await, "Invalid session token");
    }

    #[tokio::test]
    async fn test_extractor_trailing_plaintext() {
        let mut plaintext = serialize_session_token_data(&test_session_token_data());
        plaintext.push(0x00);
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, plaintext);
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(extractor.ready().await.unwrap().call(token).await, "Invalid session token");
    }

    #[test_log::test]
    fn test_extractor_clone() {
        let _extractor = DefaultSessionTokenExtractor::new(test_key_service()).clone();
    }

    #[test_log::test]
    fn test_from_session_token_valid() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));

        let parsed = EncryptedSessionTokenData::from_session_token(token.as_bytes()).unwrap();
        assert_eq!(parsed.key_id, TEST_KEY_ID);
        assert_eq!(parsed.account_id, TEST_ACCOUNT_ID);
        assert_eq!(parsed.nonce, TEST_NONCE);
        assert_eq!(parsed.encrypted_payload, payload);

        let cloned = parsed.clone();
        assert_eq!(cloned.key_id, parsed.key_id);
    }

    #[test_log::test]
    fn test_from_session_token_empty() {
        assert_invalid_session_token(EncryptedSessionTokenData::from_session_token(b""), "Invalid session token");
    }

    #[test_log::test]
    fn test_from_session_token_wrong_version() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload);
        let token = format!("1{}", URL_SAFE_NO_PAD.encode(&body));

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(token.as_bytes()),
            "Invalid session token",
        );
    }

    #[test_log::test]
    fn test_from_session_token_invalid_base64() {
        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(b"0!not-base64!"),
            "Invalid session token",
        );
    }

    #[test_log::test]
    fn test_from_session_token_truncated() {
        // Every strict prefix of a valid body fails: the empty body, a truncated key id, a
        // truncated account id, a truncated nonce, a truncated payload length, and a payload
        // shorter than its declared length.
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload);

        for length in 0..body.len() {
            assert_invalid_session_token(
                EncryptedSessionTokenData::from_session_token(encode_token(&body[..length]).as_bytes()),
                "Invalid session token",
            );
        }
    }

    #[test_log::test]
    fn test_from_session_token_non_utf8_key_id() {
        let mut body = vec![2, 0xff, 0xfe];
        body.extend_from_slice(TEST_ACCOUNT_ID.as_bytes());
        body.extend_from_slice(&TEST_NONCE);
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes()),
            "Invalid session token",
        );
    }

    #[test_log::test]
    fn test_from_session_token_non_digit_account_id() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, "12345678901a", &payload);

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes()),
            "Invalid session token",
        );
    }

    #[test_log::test]
    fn test_static_key_service_construction() {
        assert!(StaticKeyService::new().0.is_empty());
        assert!(StaticKeyService::default().0.is_empty());

        let service = StaticKeyService::with_capacity(10);
        assert!(service.0.is_empty());
        assert!(service.0.capacity() >= 10);
    }

    #[tokio::test]
    async fn test_static_key_service_call() {
        let mut service = test_key_service().clone();

        let key = service.ready().await.unwrap().call(TEST_KEY_ID.to_string()).await.unwrap();
        assert_eq!(key, TEST_KEY);

        assert_invalid_session_token(
            service.ready().await.unwrap().call("missing".to_string()).await,
            "KeyId missing not found in StaticKeyService",
        );
    }
}
