# scratchstack-database
Scratchstack native database operations and types

## API Implementation Checklist

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
* [ ] CreateAccountAlias
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
* [ ] ListAccountAliases
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
* [ ] UpdateAssumeRolePolicy
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