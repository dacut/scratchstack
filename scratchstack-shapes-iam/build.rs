use {
    anyhow::Result as AnyResult,
    scratchstack_shapegen::{
        CommonErrors, DerivedMember, DerivedStructs, DocRewrite, LengthConstraint, PatternRewrite, ShapeGenerator,
    },
};

/// Documentation to use for the account id field in internal request types.
const ACCOUNT_ID_DOCUMENTATION: &str = "The Amazon Web Services account ID this delegation request is targeted to.";

/// The field name to use for the account id in internal request types.
const ACCOUNT_ID_FIELD_NAME: &str = "account_id";

/// The Smithy shape id for the account id type.
const ACCOUNT_ID_SHAPE_ID: &str = "com.amazonaws.iam#accountIdType";

/// The Smithy namespace for IAM.
const IAM_NAMESPACE: &str = "com.amazonaws.iam";

/// The IAM APIs to exclude from internal request generation.
///
/// Some of these do not have request bodies (so we can't annotate with an account id); others are
/// organization APIs that do not need an account id.
const IAM_NO_INTERNAL_REQUEST_API: &[&str] = &[
    // These use an ARN parameter that already includes the account id, so we don't need to add an
    // internal request with an account id field.
    "CreatePolicyVersion",
    "DeletePolicy",
    "DeletePolicyVersion",
    "GetPolicy",
    "GetPolicyVersion",
    "ListEntitiesForPolicy",
    "ListPolicyTags",
    "ListPolicyVersions",
    "SetDefaultPolicyVersion",
    "TagPolicy",
    "UntagPolicy",
    // These do not have request bodies, so we can't add an account id field to the object.
    // These are (or will be) implemented in scratchstack-iam-ext.json.
    "GenerateCredentialReport",
    "GetAccountPasswordPolicy",
    "GetAccountSummary",
    "GetCredentialReport",
    "GetOutboundWebIdentityFederationInfo",
    // Organization APIs that don't need an account id.
    "DeleteAccountPasswordPolicy",
    "DisableOrganizationsRootCredentialsManagement",
    "DisableOrganizationsRootSessions",
    "DisableOutboundWebIdentityFederation",
    "EnableOrganizationsRootCredentialsManagement",
    "EnableOrganizationsRootSessions",
    "EnableOutboundWebIdentityFederation",
    "GenerateOrganizationsAccessReport",
    "GetOrganizationsAccessReport",
    "ListOrganizationsFeatures",
];

/// Shapes whose member documentation contains angle-bracketed placeholders that rustdoc reads as
/// HTML tags.
const IAM_PROBLEMATIC_HTML_SHAPE_IDS: &[&str] = &[
    "com.amazonaws.iam#DeleteServiceLinkedRoleResponse",
    "com.amazonaws.iam#GetServiceLinkedRoleDeletionStatusRequest",
];

/// A pattern on various IAM string shapes that the `regex` crate cannot compile: it uses a negative
/// lookahead to forbid consecutive hyphens.
const IAM_PROBLEMATIC_REGEX_1: &str = r"^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$";

/// The replacement for [`IAM_PROBLEMATIC_REGEX_1`]. It permits consecutive hyphens; the paired
/// length constraint recovers the bound the original expressed.
const IAM_PROBLEMATIC_REGEX_1_REPLACEMENT: &str = r"^[a-z0-9]([-a-z0-9]){1,61}[a-z0-9]$";

fn main() -> AnyResult<()> {
    ShapeGenerator::builder()
        .namespace(IAM_NAMESPACE)
        .model("iam-2010-05-08.json")
        .extensions(vec!["scratchstack-iam-ext.json".into()])
        .common_errors(CommonErrors::aws_query())
        .pattern_rewrites(vec![
            PatternRewrite::new(IAM_PROBLEMATIC_REGEX_1, IAM_PROBLEMATIC_REGEX_1_REPLACEMENT)
                .with_length(LengthConstraint::new(Some(3), Some(63))),
        ])
        .doc_rewrites(vec![
            DocRewrite::new(IAM_PROBLEMATIC_HTML_SHAPE_IDS)
                .replacing("<service-principal-name>", "<i>service-principal-name</i>")
                .replacing("<role-name>", "<i>role-name</i>")
                .replacing("<task-uuid>", "<i>task-uuid</i>"),
        ])
        // Each IAM API gets a companion request type carrying an account id, so a service
        // implementation can address any account rather than inferring one from the caller. These
        // are ordinary structures once derived; nothing in the generator knows they exist.
        .derived_structs(
            DerivedStructs::new("InternalRequest")
                .with_member(DerivedMember::new(ACCOUNT_ID_FIELD_NAME, ACCOUNT_ID_SHAPE_ID, ACCOUNT_ID_DOCUMENTATION))
                .excluding(IAM_NO_INTERNAL_REQUEST_API),
        )
        .build()
        .run()?;

    Ok(())
}
