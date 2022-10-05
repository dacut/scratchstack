#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountLimit {
    pub account_id: String,
    pub limit_id: i128,
    pub region: String,
    pub int_value: Option<i64>,
    pub string_value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitDefinition {
    pub limit_id: i128,
    pub service_name: String,
    pub limit_name: String,
    pub description: Option<String>,
    pub value_type: String,
    pub default_int_value: Option<i64>,
    pub default_string_value: Option<String>,
    pub min_value: Option<i64>,
    pub max_value: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Region {
    pub region_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueType {
    pub name: String,
}
