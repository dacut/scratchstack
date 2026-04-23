use {
    anyhow::{Result as AnyResult, bail},
    scratchstack_shapegen::{LengthConstraint, Member, Shape, SmithyModel, TraitMap},
    std::{cell::RefCell, env::var, fs::File, io::BufReader, path::Path, rc::Rc},
};

/// The IAM APIs to exclude from internal request generation.
///
/// Some of these do not have request bodies (so we can't annotate with an account id); others are
/// organization APIs that do not need an account id.
const IAM_NO_INTERNAL_REQUEST_API: &[&str] = &[
    "DeleteAccountPasswordPolicy",
    "DisableOrganizationsRootCredentialsManagement",
    "DisableOrganizationsRootSessions",
    "DisableOutboundWebIdentityFederation",
    "EnableOrganizationsRootCredentialsManagement",
    "EnableOrganizationsRootSessions",
    "EnableOutboundWebIdentityFederation",
    "GenerateCredentialReport",
    "GenerateOrganizationsAccessReport",
    "GetAccountPasswordPolicy",
    "GetAccountSummary",
    "GetCredentialReport",
    "GetOrganizationsAccessReport",
    "GetOutboundWebIdentityFederationInfo",
    "ListOrganizationsFeatures",
];

/// Documentation to use for the account id field in internal request types.
const ACCOUNT_ID_DOCUMENTATION: &str = "The Amazon Web Services account ID this delegation request is targeted to.";

/// The field name to use for the account id in internal request types.
const ACCOUNT_ID_FIELD_NAME: &str = "account_id";

/// The Smithy shape id for the account id type.
const ACCOUNT_ID_SHAPE_ID: &str = "com.amazonaws.iam#accountIdType";

/// Shapes with problematic HTML tags in IAM.
const IAM_PROBLEMATIC_HTML_SHAPE_IDS: &[&str] = &[
    "com.amazonaws.iam#DeleteServiceLinkedRoleResponse",
    "com.amazonaws.iam#GetServiceLinkedRoleDeletionStatusRequest",
];

/// The problematic regex pattern on various string shapes in the IAM mode.
const IAM_PROBLEMATIC_REGEX_1: &str = r"^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$";

/// The replacement regex pattern to use for the problematic regex pattern in the IAM model.
const IAM_PROBLEMATIC_REGEX_1_REPLACEMENT: &str = r"^[a-z0-9]([-a-z0-9]){1,61}[a-z0-9]$";

fn main() {
    generate_iam_shapes().expect("Failed to generate IAM shapes");
}

/// Generate the IAM shapes to include from `iam/mod.rs`.
fn generate_iam_shapes() -> AnyResult<()> {
    println!("cargo:rerun-if-changed=iam-2010-05-08.json");
    let file = File::open("iam-2010-05-08.json")?;
    let reader = BufReader::new(file);
    let mut model: SmithyModel = serde_json::from_reader(reader)?;
    model.add_default_shapes();

    let mut new_requests = Vec::with_capacity(128);

    // Fix unsupported regular expressions on various types.
    for shape in model.shapes.values_mut() {
        let mut shape = shape.borrow_mut();
        let traits = shape.traits_mut();

        let Some(pattern) = traits.pattern() else {
            continue;
        };

        if pattern == IAM_PROBLEMATIC_REGEX_1 {
            traits.set_pattern(IAM_PROBLEMATIC_REGEX_1_REPLACEMENT);
            traits.set_length_constraint(LengthConstraint::new(Some(3), Some(63)));
        }
    }

    // Fix HTML tags on documentation for a few types.
    for shape_id in IAM_PROBLEMATIC_HTML_SHAPE_IDS {
        let shape = model.shapes.get_mut(*shape_id).unwrap();
        let mut shape = shape.borrow_mut();
        for member in shape.members_mut().unwrap().values_mut() {
            let Some(doc) = member.traits.documentation() else {
                continue;
            };
            let replacement = doc
                .replace("<service-principal-name>", "<i>service-principal-name</i>")
                .replace("<role-name>", "<i>role-name</i>")
                .replace("<task-uuid>", "<i>task-uuid</i>");
            member.traits.set_documentation(replacement);
        }
    }

    // Add internal request types to all IAM operations except those in the exclusion list.
    for (api_name, shape) in &model.shapes {
        let Shape::Operation(op) = &*shape.borrow() else {
            continue;
        };

        let Some(base_api_name) = api_name.strip_prefix("com.amazonaws.iam#") else {
            continue;
        };

        if IAM_NO_INTERNAL_REQUEST_API.contains(&base_api_name) {
            continue;
        }

        let request_name = op.input.target.as_str();
        let Some(request_shape) = model.get_shape(request_name) else {
            bail!("Operation {base_api_name} has input shape {request_name} that does not exist in the model");
        };
        let Shape::Structure(request_struct) = &*request_shape.borrow() else {
            bail!("Operation {base_api_name} has input shape {request_name} that is not a structure");
        };

        // Create a new structure that represents the internal request.
        let mut internal_request = request_struct.clone();
        let internal_request_shape_name = format!("{}InternalRequest", base_api_name);

        // Add the account_id field to the internal request.
        let mut traits = TraitMap::new();
        traits.set_required(true);
        traits.set_documentation(ACCOUNT_ID_DOCUMENTATION);
        let account_id_member = Member {
            shape: None,
            target: ACCOUNT_ID_SHAPE_ID.to_string(),
            traits,
        };
        internal_request.members.insert(ACCOUNT_ID_FIELD_NAME.to_string(), account_id_member);
        new_requests.push((internal_request_shape_name, internal_request));
    }

    for (new_request_name, new_request) in new_requests {
        let new_request_shape = Shape::Structure(new_request);
        model
            .shapes
            .insert(format!("com.amazonaws.iam#{}", new_request_name), Rc::new(RefCell::new(new_request_shape)));
    }

    model.resolve();

    let out_dir = var("OUT_DIR").expect("OUT_DIR environment variable not set");
    let dest_path = Path::new(&out_dir).join("iam_gen.rs");
    let mut file = File::create(dest_path)?;

    model.generate(&mut file)?;
    Ok(())
}
