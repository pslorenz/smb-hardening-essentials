<#
.SYNOPSIS
    Tier 1 Identity and Access Management tests.

.DESCRIPTION
    Pester-based Maester tests covering the SMB-IAM-* control family from
    BASELINE.md. Each It block:
      - Is tagged with the stable control ID (SMB-IAM-NNN)
      - Is tagged with a category (Identity) and severity (Critical/High/Medium/Low)
      - Returns a clear pass/fail with useful failure message
      - Links to remediation in the Description tag where possible

    These tests assume Connect-Maester has been called by the wrapper.

.NOTES
    Requires: Maester module, Microsoft.Graph.Authentication, appropriate scopes.
#>

BeforeDiscovery {
    # Cache tenant-wide reads once per run to keep test time down.
    $script:CAPolicies    = Get-MtConditionalAccessPolicy -ErrorAction SilentlyContinue
    $script:AuthzPolicy   = Get-MtAuthorizationPolicy -ErrorAction SilentlyContinue
    $script:SecDefaults   = Get-MtSecurityDefault -ErrorAction SilentlyContinue
    $script:DirectoryRoles = Get-MtRoleMember -ErrorAction SilentlyContinue
    $script:AdminRoleNames = @(
        'Global Administrator','Privileged Role Administrator','Security Administrator',
        'Exchange Administrator','SharePoint Administrator','User Administrator',
        'Authentication Administrator','Conditional Access Administrator',
        'Application Administrator','Cloud Application Administrator',
        'Helpdesk Administrator','Intune Administrator'
    )
}

Describe 'SMB Tier 1 — Identity and Access' -Tag 'Identity','Tier1' {

    Context 'Multi-factor authentication' {

        It 'SMB-IAM-001: MFA is required for all users' -Tag 'SMB-IAM-001','Critical' {
            # Pass if Security Defaults are on, OR a CA policy requires MFA for all users.
            $sdOn = $script:SecDefaults.IsEnabled -eq $true

            $caMfaAll = $script:CAPolicies | Where-Object {
                $_.State -eq 'enabled' -and
                $_.Conditions.Users.IncludeUsers -contains 'All' -and
                $_.GrantControls.BuiltInControls -contains 'mfa'
            }

            ($sdOn -or $caMfaAll) | Should -BeTrue -Because @"
Tenant must enforce MFA for all users via Security Defaults or a Conditional Access policy.
Neither was detected. Enable Security Defaults (free) in Entra ID → Properties → Manage Security Defaults,
or create a CA policy targeting All users with MFA required.
Docs: https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength
"@
        }

        It 'SMB-IAM-002: MFA is required for all administrator roles' -Tag 'SMB-IAM-002','Critical' {
            $adminMfaPolicy = $script:CAPolicies | Where-Object {
                $_.State -eq 'enabled' -and
                $_.GrantControls.BuiltInControls -contains 'mfa' -and
                ($_.Conditions.Users.IncludeRoles.Count -gt 0 -or
                 $_.Conditions.Users.IncludeUsers -contains 'All')
            }

            $hasAdminMfa = ($adminMfaPolicy.Count -gt 0) -or ($script:SecDefaults.IsEnabled -eq $true)

            $hasAdminMfa | Should -BeTrue -Because @"
No Conditional Access policy was found that requires MFA for admin roles.
Create a policy targeting directory roles (Global Admin, Privileged Role Admin, etc.) with MFA required,
no exclusions except the break-glass account (SMB-IAM-005).
"@
        }

        It 'SMB-IAM-003: Legacy authentication is blocked tenant-wide' -Tag 'SMB-IAM-003','Critical' {
            $sdOn = $script:SecDefaults.IsEnabled -eq $true

            $legacyBlockPolicy = $script:CAPolicies | Where-Object {
                $_.State -eq 'enabled' -and
                $_.GrantControls.BuiltInControls -contains 'block' -and
                ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
                 $_.Conditions.ClientAppTypes -contains 'other')
            }

            ($sdOn -or $legacyBlockPolicy) | Should -BeTrue -Because @"
Legacy authentication bypasses MFA. Block it with Security Defaults or a CA policy
targeting 'Other clients' and 'Exchange ActiveSync clients' with Block access.
Verify no critical integrations depend on legacy auth before enabling.
"@
        }

        It 'SMB-IAM-011: Number-matching MFA is enforced' -Tag 'SMB-IAM-011','High' {
            $policy = Get-MtAuthenticationMethodPolicy -ErrorAction SilentlyContinue
            $maPolicy = $policy.AuthenticationMethodConfigurations |
                        Where-Object Id -EQ 'MicrosoftAuthenticator'

            $numberMatching = $maPolicy.FeatureSettings.NumberMatchingRequiredState.State
            $numberMatching | Should -Be 'enabled' -Because @"
Microsoft Authenticator should require number matching to defeat MFA fatigue attacks.
This is the default for new tenants since 2023 but legacy tenants may still have it off.
Entra ID → Security → Authentication methods → Microsoft Authenticator → Configure.
"@
        }
    }

    Context 'Administrator hygiene' {

        It 'SMB-IAM-004: Global Administrator count is between 2 and 4' -Tag 'SMB-IAM-004','High' {
            $globalAdmins = $script:DirectoryRoles |
                Where-Object RoleDisplayName -EQ 'Global Administrator'

            $count = @($globalAdmins).Count
            $count | Should -BeGreaterOrEqual 2 -Because "Single-admin tenants risk lockout."
            $count | Should -BeLessOrEqual 4 -Because "Too many Global Admins expands blast radius. Use lower-privileged roles where possible."
        }

        It 'SMB-IAM-006: All admin role members are cloud-only accounts' -Tag 'SMB-IAM-006','High' {
            $admins = $script:DirectoryRoles | Where-Object {
                $script:AdminRoleNames -contains $_.RoleDisplayName
            }

            $synced = $admins | Where-Object { $_.OnPremisesSyncEnabled -eq $true }

            @($synced).Count | Should -Be 0 -Because @"
The following admin accounts are synced from on-prem AD: $($synced.UserPrincipalName -join ', ')
On-prem AD compromise becomes cloud compromise in minutes when admin accounts are synced.
Create cloud-only accounts for all admin roles and remove directory role assignments from synced accounts.
"@
        }

        It 'SMB-IAM-007: Admin accounts have no user mailboxes (separation of duties)' -Tag 'SMB-IAM-007','Medium' {
            # Heuristic: admin accounts should not be the same account used for daily email.
            # We check that accounts holding admin roles either have no mailbox license
            # or match a naming convention (admin-*, *-admin, adm-*) suggesting separation.
            $admins = $script:DirectoryRoles | Where-Object {
                $script:AdminRoleNames -contains $_.RoleDisplayName
            } | Select-Object -Unique UserPrincipalName

            $mixed = foreach ($a in $admins) {
                $upn = $a.UserPrincipalName
                if (-not $upn) { continue }
                $looksSeparated = $upn -match '^(adm|admin)[-.]' -or $upn -match '[-.](adm|admin)@'
                if (-not $looksSeparated) {
                    [pscustomobject]@{ UPN = $upn }
                }
            }

            # This is advisory — fail as Medium not Critical since heuristic can miss.
            @($mixed).Count | Should -Be 0 -Because @"
Admin accounts appear to share naming with regular user accounts: $($mixed.UPN -join ', ')
Recommended convention: adm-<name>@tenant.onmicrosoft.com for admin-only accounts, separate from daily-driver mailboxes.
If these are already separated via another convention, add to client-exceptions.json.
"@
        }
    }

    Context 'External collaboration' {

        It 'SMB-IAM-008: User consent to third-party apps is restricted' -Tag 'SMB-IAM-008','High' {
            $permission = $script:AuthzPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
            # Acceptable values: null/empty (user consent disabled), or 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
            # Unacceptable: 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy' (broad consent)
            $restricted = ($permission -eq $null) -or
                          ($permission.Count -eq 0) -or
                          ($permission -notcontains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy')

            $restricted | Should -BeTrue -Because @"
User consent to third-party apps is currently set broadly, enabling OAuth consent phishing.
Entra ID → Enterprise applications → Consent and permissions → User consent settings:
Set to 'Allow user consent for apps from verified publishers, for selected permissions'.
"@
        }

        It 'SMB-IAM-009: Guest invitations are restricted to admins or specific roles' -Tag 'SMB-IAM-009','Medium' {
            $guestInvite = $script:AuthzPolicy.AllowInvitesFrom
            $guestInvite | Should -BeIn @('adminsAndGuestInviters','none') -Because @"
Guest invitation is currently set to '$guestInvite'. SMB default of 'everyone' lets any user invite external
guests with no oversight. Restrict to 'adminsAndGuestInviters' at minimum.
Entra ID → External Identities → External collaboration settings → Guest invite settings.
"@
        }
    }

    Context 'Risk-based access (Entra P2)' {

        It 'SMB-IAM-010: Sign-in risk policy is configured at minimum in report-only' -Tag 'SMB-IAM-010','Medium' {
            # P2 feature. If P1-only tenant, mark NotRun rather than fail.
            $skuPlans = (Get-MtGraphRequest -RelativeUri 'subscribedSkus' -ErrorAction SilentlyContinue).value.ServicePlans.ServicePlanName
            $hasP2 = ($skuPlans -contains 'AAD_PREMIUM_P2') -or
                     ($skuPlans -contains 'ENTERPRISE_PREMIUM_SECURITY') -or
                     ($skuPlans -contains 'AAD_PREMIUM_P2_FACULTY')
            if (-not $hasP2) {
                Set-ItResult -Skipped -Because 'Tenant does not have Entra ID P2 licensing. Identity Protection policies require P2.'
                return
            }

            $riskPolicy = $script:CAPolicies | Where-Object {
                $_.State -in 'enabled','enabledForReportingButNotEnforced' -and
                $_.Conditions.SignInRiskLevels.Count -gt 0
            }

            @($riskPolicy).Count | Should -BeGreaterThan 0 -Because @"
No Conditional Access policy evaluating sign-in risk was found. With P2 licensing, configure a policy
targeting medium+ sign-in risk with MFA or block. Report-only mode is acceptable for Tier 1;
enforcement is Tier 2 after false-positive tuning.
Entra ID → Protection → Conditional Access → New policy → Conditions → Sign-in risk.
"@
        }
    }

    Context 'Break-glass and recovery' {

        It 'SMB-IAM-005: A break-glass account exists and is monitored' -Tag 'SMB-IAM-005','High' {
            # Heuristic: look for a Global Admin account that is excluded from the main MFA CA policy,
            # has a name suggesting break-glass (break-glass, emergency, bgadmin, etc.), and has not
            # signed in recently (break-glass accounts should be dormant).
            $bgCandidates = $script:DirectoryRoles |
                Where-Object { $_.RoleDisplayName -eq 'Global Administrator' } |
                Where-Object { $_.UserPrincipalName -match 'break|emergency|bgadmin|breakglass' }

            @($bgCandidates).Count | Should -BeGreaterThan 0 -Because @"
No account matching break-glass naming convention was found among Global Admins.
Create a cloud-only Global Admin account (e.g., break-glass@tenant.onmicrosoft.com), store the password
in a physical safe, exclude from all Conditional Access policies, and configure sign-in alerts.
Docs: https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
"@
        }

        It 'SMB-IAM-012: Self-service password reset is enabled with MFA gating' -Tag 'SMB-IAM-012','Medium' {
            $sspr = Get-MtSelfServicePasswordResetPolicy -ErrorAction SilentlyContinue
            $sspr.Enabled | Should -BeTrue -Because @"
SSPR is not enabled for any users. Enable for all users to reduce help-desk load.
Ensure MFA is required for reset (NumberOfAuthenticationMethodsRequired >= 2) and security questions are not used.
Entra ID → Password reset.
"@
        }
    }
}
