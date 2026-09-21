$version: "2"
namespace net.scratchstack.cloud

use aws.protocols#awsJson1_1

/// The Scratchstack Cloud Service allows for management of the cloud/partition that Scratchstack
/// services are running in.
@awsJson1_1
@unstable
service Cloud {
    version: "2026-09-03"
    operations: [
        CreateQuotaDefinition,
        CreateQuotaUnit,
        CreateRegion,
        CreateService,
        DeleteQuota,
        DeleteQuotaDefinition,
        DeleteQuotaUnit,
        DeleteRegion,
        DeleteService,
        GetCurrentPartition,
        GetQuota,
        GetQuotaDefinition,
        ListQuotaDefinitions,
        ListQuotas,
        ListQuotaUnits,
        ListRegions,
        SetCurrentPartition,
        SetQuota,
        UpdateQuotaDefinition
    ]
    errors: [
        EntityAlreadyExistsException,
        InternalFailure,
        ResourceNotFoundException,
    ]
}

/// The specified quota, service, region, or unit already exists.
@error("client")
@httpError(400)
structure EntityAlreadyExistsException {}

/// Internal failure.
@error("server")
@httpError(500)
structure InternalFailure {}

/// The specified quota, service, region, or unit was not found.
@error("client")
@httpError(400)
structure ResourceNotFoundException {}

/// A quota applied to an account.
@unstable
structure Quota {
    /// The identifier for this quota.
    @required
    QuotaId: quotaIdType

    /// The service this quota is scoped to.
    @required
    ServiceId: serviceIdType

    /// The name of the quota.
    @required
    QuotaName: quotaNameType

    /// The description of the quota.
    Description: descriptionType

    /// The region the quota is scoped to; if this is a global quota, this is unset.
    RegionName: regionNameType

    /// The 12-digit account id this quota applies to.
    @required
    AccountId: accountIdType

    /// The value of the quota.
    @required
    Value: quotaValueType

    /// The units of the quota.
    @required
    Unit: quotaUnitType

    /// The timestamp when the quota was initially created.
    CreatedAt: timestamp

    /// The timestamp when the quota was last updated.
    UpdatedAt: timestamp
}


/// A quota definition.
@unstable
structure QuotaDefinition {
    /// The unique quota id.
    @required
    QuotaId: quotaIdType

    /// The scope of the quota, either regional or global
    @required
    Scope: QuotaScope

    /// The service this quota is scoped to.
    @required
    ServiceId: serviceIdType

    /// The name of the quota.
    @required
    QuotaName: quotaNameType

    /// The description of the quota.
    Description: descriptionType

    /// The units of quotas created with this definition.
    @required
    Unit: quotaUnitType

    /// The default value for this quota.
    DefaultValue: quotaValueType,

    /// The minimum value of quotas created with this definition.
    MinValue: quotaValueType

    /// The maximum value of quotas created with this definition.
    MaxValue: quotaValueType

    /// The timestamp when the quota definition was initially created.
    CreatedAt: timestamp

    /// The timestamp when the quota definition was last updated.
    UpdatedAt: timestamp
}

/// The scope of a quota.
enum QuotaScope {
    /// The quota applies globally.
    GLOBAL = "Global"

    /// The quota is regional.
    REGIONAL = "Regional"
}

/// A quota unit definition.
@unstable
structure QuotaUnit {
    /// The name of the unit
    @required
    Unit: quotaUnitType,

    /// The timestamp when the unit was initially created.
    CreatedAt: timestamp

    /// The timestamp when the unit was last updated.
    UpdatedAt: timestamp
}

/// A region definition.
@unstable
structure Region {
    /// The name of the region
    @required
    RegionName: regionNameType

    /// The timestamp when the region was initially created.
    CreatedAt: timestamp

    /// The timestamp when the region was last updated.
    UpdatedAt: timestamp
}

/// A service definition.
@unstable
structure Service {
    /// The identifier for the service. This is the short name used in Aspen documents, e.g. `iam`
    /// for the Identity and Access Management service.
    @required
    ServiceId: serviceIdType

    /// The global DNS name for the service (which is not required to be an actual HTTP endpoint),
    /// e.g. `iam.amazonaws.com` for the AWS Identity and Access Management service.
    @required
    ServiceDnsName: dnsNameType

    /// A description of the service.
    Description: descriptionType

    /// The timestamp when the service was initially created.
    CreatedAt: timestamp

    /// The timestamp when the service was last updated.
    UpdatedAt: timestamp
}

@length(min: 12, max: 12)
@pattern("^[0-9]+$")
string accountIdType

@length(min: 1, max: 256)
string dnsNameType

string descriptionType

@range(min: 1)
integer maxItemsType

list quotaDefinitionListType {
    member: QuotaDefinition
}

@length(min: 7, max: 64)
@pattern("^quota-.*$")
string quotaIdType

list quotaListType {
    member: Quota
}

@length(min: 1, max: 64)
string quotaNameType

@length(min: 1, max: 64)
@pattern("^[-/a-zA-Z]+$")
string quotaUnitType

list quotaUnitListType {
    member: quotaUnitType
}

bigDecimal quotaValueType

string paginationTokenType

@pattern("^[a-z][-a-z0-9]+[a-z0-9]$")
string partitionType

list regionListType {
    member: Region
}

@length(min: 1, max: 64)
@pattern("^[-a-z0-9]+$")
string regionNameType

@length(min: 1, max: 32)
@pattern("^[-a-z0-9]+$")
string serviceIdType

timestamp timestamp
