# scratchstack-iam-database

IAM database schema and types for Scratchstack services.

## API Implementation Checklist

Each entry is an API this crate implements against the database. The IAM list is
the whole AWS IAM API, so the unchecked entries are the work remaining; the STS
list is the whole AWS STS API on the same basis. The Scratchstack extensions have
no AWS counterpart and are listed in full.

### IAM
* [ ] AcceptDelegationRequest
* [ ] AddClientIDToOpenIDConnectProvider
* [ ] AddRoleToInstanceProfile
* [x] AddUserToGroup
* [ ] AssociateDelegationRequest
* [x] AttachGroupPolicy
* [x] AttachRolePolicy
* [x] AttachUserPolicy
* [ ] ChangePassword
* [x] CreateAccessKey
* [x] CreateAccountAlias
* [ ] CreateDelegationRequest
* [x] CreateGroup
* [ ] CreateInstanceProfile
* [ ] CreateLoginProfile
* [ ] CreateOpenIDConnectProvider
* [x] CreatePolicy
* [x] CreatePolicyVersion
* [x] CreateRole
* [ ] CreateSAMLProvider
* [ ] CreateServiceLinkedRole
* [ ] CreateServiceSpecificCredential
* [x] CreateUser
* [ ] CreateVirtualMFADevice
* [ ] DeactivateMFADevice
* [x] DeleteAccessKey
* [ ] DeleteAccountAlias
* [ ] DeleteAccountPasswordPolicy
* [x] DeleteGroup
* [x] DeleteGroupPolicy
* [ ] DeleteInstanceProfile
* [ ] DeleteLoginProfile
* [ ] DeleteOpenIDConnectProvider
* [x] DeletePolicy
* [x] DeletePolicyVersion
* [x] DeleteRole
* [x] DeleteRolePermissionsBoundary
* [x] DeleteRolePolicy
* [ ] DeleteSAMLProvider
* [ ] DeleteServerCertificate
* [ ] DeleteServiceLinkedRole
* [ ] DeleteServiceSpecificCredential
* [ ] DeleteSigningCertificate
* [ ] DeleteSSHPublicKey
* [x] DeleteUser
* [x] DeleteUserPermissionsBoundary
* [x] DeleteUserPolicy
* [ ] DeleteVirtualMFADevice
* [x] DetachGroupPolicy
* [x] DetachRolePolicy
* [x] DetachUserPolicy
* [ ] DisableOrganizationsRootCredentialsManagement
* [ ] DisableOrganizationsRootSessions
* [ ] DisableOutboundWebIdentityFederation
* [ ] EnableMFADevice
* [ ] EnableOrganizationsRootCredentialsManagement
* [ ] EnableOrganizationsRootSessions
* [ ] EnableOutboundWebIdentityFederation
* [ ] GenerateCredentialReport
* [ ] GenerateOrganizationsAccessReport
* [ ] GenerateServiceLastAccessedDetails
* [ ] GetAccessKeyLastUsed
* [ ] GetAccountAuthorizationDetails
* [ ] GetAccountPasswordPolicy
* [ ] GetAccountSummary
* [ ] GetContextKeysForCustomPolicy
* [ ] GetContextKeysForPrincipalPolicy
* [ ] GetCredentialReport
* [ ] GetDelegationRequest
* [x] GetGroup
* [x] GetGroupPolicy
* [ ] GetHumanReadableSummary
* [ ] GetInstanceProfile
* [ ] GetLoginProfile
* [ ] GetMFADevice
* [ ] GetOpenIDConnectProvider
* [ ] GetOrganizationsAccessReport
* [ ] GetOutboundWebIdentityFederationInfo
* [x] GetPolicy
* [x] GetPolicyVersion
* [x] GetRole
* [x] GetRolePolicy
* [ ] GetSAMLProvider
* [ ] GetServerCertificate
* [ ] GetServiceLastAccessedDetails
* [ ] GetServiceLastAccessedDetailsWithEntities
* [ ] GetServiceLinkedRoleDeletionStatus
* [ ] GetSSHPublicKey
* [x] GetUser
* [x] GetUserPolicy
* [x] ListAccessKeys
* [x] ListAccountAliases
* [x] ListAttachedGroupPolicies
* [x] ListAttachedRolePolicies
* [x] ListAttachedUserPolicies
* [ ] ListDelegationRequests
* [x] ListEntitiesForPolicy
* [x] ListGroupPolicies
* [x] ListGroups
* [x] ListGroupsForUser
* [ ] ListInstanceProfiles
* [ ] ListInstanceProfilesForRole
* [ ] ListInstanceProfileTags
* [ ] ListMFADevices
* [ ] ListMFADeviceTags
* [ ] ListOpenIDConnectProviders
* [ ] ListOpenIDConnectProviderTags
* [ ] ListOrganizationsFeatures
* [x] ListPolicies
* [ ] ListPoliciesGrantingServiceAccess
* [x] ListPolicyTags
* [x] ListPolicyVersions
* [x] ListRolePolicies
* [x] ListRoles
* [x] ListRoleTags
* [ ] ListSAMLProviders
* [ ] ListSAMLProviderTags
* [ ] ListServerCertificates
* [ ] ListServerCertificateTags
* [ ] ListServiceSpecificCredentials
* [ ] ListSigningCertificates
* [ ] ListSSHPublicKeys
* [x] ListUserPolicies
* [x] ListUsers
* [x] ListUserTags
* [ ] ListVirtualMFADevices
* [x] PutGroupPolicy
* [x] PutRolePermissionsBoundary
* [x] PutRolePolicy
* [x] PutUserPermissionsBoundary
* [x] PutUserPolicy
* [ ] RejectDelegationRequest
* [ ] RemoveClientIDFromOpenIDConnectProvider
* [ ] RemoveRoleFromInstanceProfile
* [x] RemoveUserFromGroup
* [ ] ResetServiceSpecificCredential
* [ ] ResyncMFADevice
* [ ] SendDelegationToken
* [x] SetDefaultPolicyVersion
* [ ] SetSecurityTokenServicePreferences
* [ ] SimulateCustomPolicy
* [ ] SimulatePrincipalPolicy
* [ ] TagInstanceProfile
* [ ] TagMFADevice
* [ ] TagOpenIDConnectProvider
* [x] TagPolicy
* [x] TagRole
* [ ] TagSAMLProvider
* [ ] TagServerCertificate
* [x] TagUser
* [ ] UntagInstanceProfile
* [ ] UntagMFADevice
* [ ] UntagOpenIDConnectProvider
* [x] UntagPolicy
* [x] UntagRole
* [ ] UntagSAMLProvider
* [ ] UntagServerCertificate
* [x] UntagUser
* [x] UpdateAccessKey
* [ ] UpdateAccountPasswordPolicy
* [x] UpdateAssumeRolePolicy
* [ ] UpdateDelegationRequest
* [x] UpdateGroup
* [ ] UpdateLoginProfile
* [ ] UpdateOpenIDConnectProviderThumbprint
* [x] UpdateRole
* [x] UpdateRoleDescription
* [ ] UpdateSAMLProvider
* [ ] UpdateServerCertificate
* [ ] UpdateServiceSpecificCredential
* [ ] UpdateSigningCertificate
* [ ] UpdateSSHPublicKey
* [x] UpdateUser
* [ ] UploadServerCertificate
* [ ] UploadSigningCertificate
* [ ] UploadSSHPublicKey

### STS

* [x] AssumeRole
* [ ] AssumeRoleWithSAML
* [ ] AssumeRoleWithWebIdentity
* [ ] AssumeRoot
* [ ] DecodeAuthorizationMessage
* [ ] GetAccessKeyInfo
* [ ] GetCallerIdentity
* [ ] GetDelegatedAccessToken
* [ ] GetFederationToken
* [ ] GetSessionToken
* [ ] GetWebIdentityToken

### Scratchstack extensions

These have no AWS counterpart. They are declared in
`scratchstack-shapes-iam/scratchstack-iam-ext.json`, and all of them are implemented.

* [x] CreateAccount
* [x] CreateSessionTokenEncryptionKey
* [x] GetCurrentPartition
* [x] GetCurrentSessionTokenEncryptionKey
* [x] GetSessionTokenEncryptionKey
* [x] ListAccounts
* [x] ListSessionTokenEncryptionKeys
* [x] SetCurrentPartition
* [x] UpdateSessionTokenEncryptionKey
