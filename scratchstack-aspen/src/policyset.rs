use {crate::Policy, std::collections::HashMap};

/// The source of a policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PolicySource {
    Inline {
        entity_arn: String,
        entity_id: String,
        policy_name: String,
    },
    DirectAttached {
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
}

pub type PolicySet = HashMap<PolicySource, Policy>;
