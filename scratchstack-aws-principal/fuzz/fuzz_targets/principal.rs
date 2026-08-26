#![no_main]
use {
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    scratchstack_aws_principal::{
        AssumedRole, CanonicalUser, FederatedUser, PrincipalError, PrincipalIdentity, RootUser, Service, User,
    },
};

#[derive(Arbitrary, Debug)]
enum PrincipalTarget {
    AssumedRole(String, String, String, String),
    CanonicalUser(String),
    FederatedUser(String, String, String),
    RootUser(String, String),
    Service(String, Option<String>, String),
    User(String, String, String, String),
}

fuzz_target!(|data: PrincipalTarget| {
    let _: Result<PrincipalIdentity, PrincipalError> = match data {
        PrincipalTarget::AssumedRole(partition, account_id, role_name, session_name) => AssumedRole::builder()
            .partition(partition)
            .account_id(account_id)
            .role_name(role_name)
            .session_name(session_name)
            .build()
            .map(|ar| ar.into()),
        PrincipalTarget::CanonicalUser(user_id) => CanonicalUser::new(&user_id).map(|cu| cu.into()),
        PrincipalTarget::FederatedUser(partition, account_id, user_name) => FederatedUser::builder()
            .partition(partition)
            .account_id(account_id)
            .user_name(user_name)
            .build()
            .map(|fu| fu.into()),
        PrincipalTarget::RootUser(partition, account_id) => {
            RootUser::builder().partition(partition).account_id(account_id).build().map(|ru| ru.into())
        }
        PrincipalTarget::Service(partition, region, service_name) => Service::builder()
            .service_name(partition)
            .maybe_region(region)
            .dns_suffix(service_name)
            .build()
            .map(|s| s.into()),
        PrincipalTarget::User(partition, account_id, path, user_name) => User::builder()
            .partition(partition)
            .account_id(account_id)
            .path(path)
            .user_name(user_name)
            .build()
            .map(|u| u.into()),
    };
});
