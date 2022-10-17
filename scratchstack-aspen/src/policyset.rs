use crate::{AspenError, Context, Decision, Policy};

/// The source of a policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PolicySource {
    EntityInline {
        entity_arn: String,
        entity_id: String,
        policy_name: String,
    },
    EntityAttachedPolicy {
        policy_arn: String,
        policy_id: String,
        version: String,
    },
    GroupInline {
        group_arn: String,
        group_id: String,
        policy_name: String,
    },
    GroupAttached {
        group_arn: String,
        group_id: String,
        policy_arn: String,
        policy_id: String,
        version: String,
    },
    Resource {
        resource_arn: String,
        policy_name: Option<String>,
    },
    PermissionBoundary {
        policy_arn: String,
        policy_id: String,
        version: String,
    },
    OrgServiceControl {
        policy_arn: String,
        policy_name: String,
        applied_arn: String,
    },
    Session,
}

pub struct PolicySet {
    policies: Vec<(PolicySource, Policy)>,
}

impl PolicySet {
    pub fn evaluate(&self, context: &Context) -> Result<Decision, AspenError> {
        for (_, policy) in &self.policies {
            match policy.evaluate(context) {
                Ok(Decision::Allow) => return Ok(Decision::Allow),
                Ok(Decision::Deny) => return Ok(Decision::Deny),
                Ok(Decision::DefaultDeny) => (),
                Err(err) => return Err(err),
            }
        }
        Ok(Decision::DefaultDeny)
    }
}
