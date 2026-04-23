use {
    serde::{
        Deserialize, Serialize,
        de::{Deserializer, Visitor},
        ser::Serializer,
    },
    std::fmt::{Formatter, Result as FmtResult},
    strum_macros::{Display, EnumString},
};

/// Trait identifiers.
#[derive(Clone, Copy, Debug, Display, EnumString, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TraitId {
    /// Service trait: `aws.api#service`
    #[strum(serialize = "aws.api#service")]
    AwsApiService,

    /// AWS SigV4 authentication trait: `aws.auth#sigv4`
    #[strum(serialize = "aws.auth#sigv4")]
    AwsAuthSigV4,

    /// AWSQuery protocol marker trait: `aws.protocols#awsQuery`
    #[strum(serialize = "aws.protocols#awsQuery")]
    AwsProtocolsAwsQuery,

    /// AWSQuery error marker trait: `aws.protocols#awsQueryError`
    #[strum(serialize = "aws.protocols#awsQueryError")]
    AwsProtocolsAwsQueryError,

    /// Added default trait (service-generated default): `smithy.api#addedDefault`
    #[strum(serialize = "smithy.api#addedDefault")]
    SmithyApiAddedDefault,

    /// Default value trait: `smithy.api#default`
    #[strum(serialize = "smithy.api#default")]
    SmithyApiDefault,

    /// Documentation trait: `smithy.api#documentation`
    #[strum(serialize = "smithy.api#documentation")]
    SmithyApiDocumentation,

    /// Enum value trait: `smithy.api#enumValue`
    #[strum(serialize = "smithy.api#enumValue")]
    SmithyApiEnumValue,

    /// Error marker trait: `smithy.api#error`
    #[strum(serialize = "smithy.api#error")]
    SmithyApiError,

    /// Examples trait: `smithy.api#examples`
    #[strum(serialize = "smithy.api#examples")]
    SmithyApiExamples,

    /// HTTP error code trait: `smithy.api#httpError`
    #[strum(serialize = "smithy.api#httpError")]
    SmithyApiHttpError,

    /// Input marker trait: `smithy.api#input`
    #[strum(serialize = "smithy.api#input")]
    SmithyApiInput,

    /// Length constraint trait: `smithy.api#length`
    #[strum(serialize = "smithy.api#length")]
    SmithyApiLength,

    /// Output marker trait: `smithy.api#output`
    #[strum(serialize = "smithy.api#output")]
    SmithyApiOutput,

    /// Pagination information trait: `smithy.api#paginated`
    #[strum(serialize = "smithy.api#paginated")]
    SmithyApiPaginated,

    /// Regular expression pattern trait: `smithy.api#pattern`
    #[strum(serialize = "smithy.api#pattern")]
    SmithyApiPattern,

    /// Range constraint trait: `smithy.api#range`
    #[strum(serialize = "smithy.api#range")]
    SmithyApiRange,

    /// Required trait: `smithy.api#required`
    #[strum(serialize = "smithy.api#required")]
    SmithyApiRequired,

    /// Sensitive trait: `smithy.api#sensitive`
    #[strum(serialize = "smithy.api#sensitive")]
    SmithyApiSensitive,

    /// Suppressions trait: `smithy.api#suppress`
    #[strum(serialize = "smithy.api#suppress")]
    SmithyApiSuppress,

    /// Title trait: `smithy.api#title`
    #[strum(serialize = "smithy.api#title")]
    SmithyApiTitle,

    /// XML namespace trait: `smithy.api#xmlNamespace`
    #[strum(serialize = "smithy.api#xmlNamespace")]
    SmithyApiXmlNamespace,

    /// Endpoint rule set trait: `smithy.rules#endpointRuleSet`
    #[strum(serialize = "smithy.rules#endpointRuleSet")]
    SmithyRulesEndpointRuleSet,

    /// Endpoint tests trait: `smithy.rules#endpointTests`
    #[strum(serialize = "smithy.rules#endpointTests")]
    SmithyRulesEndpointTests,

    /// Smoke tests trait: `smithy.test#smokeTests`
    #[strum(serialize = "smithy.test#smokeTests")]
    SmithyTestSmokeTests,

    /// Waitable (polling) trait: `smithy.waiters#waitable`
    #[strum(serialize = "smithy.waiters#waitable")]
    SmithyWaitersWaitable,
}

struct TraitIdVisitor;
impl<'de> Visitor<'de> for TraitIdVisitor {
    type Value = TraitId;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("an integer between -2^31 and 2^31")
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        match s.parse() {
            Ok(trait_id) => Ok(trait_id),
            Err(e) => {
                log::error!("Failed to parse trait ID from string '{s}': {e}");
                Err(serde::de::Error::custom(e))
            }
        }
    }
}

impl<'de> Deserialize<'de> for TraitId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(TraitIdVisitor)
    }
}

impl Serialize for TraitId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
