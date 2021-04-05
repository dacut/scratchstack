table! {
    limitstore.account_limit (account_id, limit_id, region) {
        account_id -> Bpchar,
        limit_id -> Int8,
        region -> Varchar,
        int_value -> Nullable<Int4>,
        string_value -> Nullable<Varchar>,
    }
}

table! {
    limitstore.limit_definition (limit_id) {
        limit_id -> Int8,
        service_name -> Varchar,
        limit_name -> Varchar,
        description -> Nullable<Text>,
        value_type -> Varchar,
        default_int_value -> Nullable<Int4>,
        default_string_value -> Nullable<Varchar>,
        min_value -> Nullable<Int4>,
        max_value -> Nullable<Int4>,
    }
}

table! {
    limitstore.region (region_name) {
        #[sql_name = "region"]
        region_name -> Varchar,
    }
}

table! {
    limitstore.value_type (name) {
        #[sql_name = "value_type"]
        name -> Varchar,
    }
}

joinable!(account_limit -> limit_definition (limit_id));
joinable!(account_limit -> region (region));
joinable!(limit_definition -> value_type (value_type));

allow_tables_to_appear_in_same_query!(
    account_limit,
    limit_definition,
    region,
    value_type,
);
