<#
.SYNOPSIS
    Tier 1 SharePoint Online and OneDrive tests.

.DESCRIPTION
    Covers the SMB-SPO-* control family from BASELINE.md.

    Uses Microsoft Graph beta endpoints for tenant sharing settings
    (Get-MtGraphRequest is a Maester helper that wraps Invoke-MgGraphRequest).
    Requires SharePointTenantSettings.Read.All.
#>

BeforeDiscovery {
    $script:SpoTenant = Get-MtGraphRequest -RelativeUri 'admin/sharepoint/settings' `
                                           -ApiVersion beta -ErrorAction SilentlyContinue
    $script:IntuneAssigned = $null  # lazy-loaded below
}

Describe 'SMB Tier 1 — SharePoint Online and OneDrive' -Tag 'SharePoint','Tier1' {

    BeforeAll {
        if (-not $script:SpoTenant) {
            Write-Warning 'SharePoint tenant settings not retrieved. Verify SharePointTenantSettings.Read.All is granted to the signed-in user or app registration.'
        }
    }

    Context 'External sharing' {

        It 'SMB-SPO-001: External sharing capped at "New and existing guests" or tighter' -Tag 'SMB-SPO-001','High' {
            # sharingCapability: 'disabled' | 'externalUserSharingOnly' | 'externalUserAndGuestSharing' | 'existingExternalUserSharingOnly'
            # Acceptable for Tier 1: anything except 'externalUserAndGuestSharing' (which is "Anyone" / anonymous links allowed)
            $cap = $script:SpoTenant.sharingCapability
            $cap | Should -Not -Be 'externalUserAndGuestSharing' -Because @"
Current setting: '$cap'. "externalUserAndGuestSharing" enables anonymous ("Anyone") links — the single
biggest accidental-exposure vector. SharePoint admin center → Policies → Sharing →
External sharing slider: set to "New and existing guests" or tighter.
Existing Anyone links continue to work until they expire; no new Anyone links can be created.
"@
        }

        It 'SMB-SPO-002: Default sharing link type is "Specific people" or "Organization"' -Tag 'SMB-SPO-002','Medium' {
            # defaultSharingLinkType: 'none' | 'direct' | 'internal' | 'anonymousAccess'
            # 'direct' = Specific people, 'internal' = People in your org, 'anonymousAccess' = Anyone
            $default = $script:SpoTenant.defaultSharingLinkType
            $default | Should -BeIn @('direct','internal','none') -Because @"
Current default: '$default'. The default shapes behavior — if Anyone is the default, users pick that every time.
SharePoint admin center → Policies → Sharing → File and folder links → default link type.
Set to "Specific people" (direct) for Tier 1; "People in your organization" (internal) is also a pass.
"@
        }

        It 'SMB-SPO-003: Anonymous link expiration is enforced at 30 days or less (when Anyone links enabled)' -Tag 'SMB-SPO-003','Medium' {
            if ($script:SpoTenant.sharingCapability -ne 'externalUserAndGuestSharing') {
                Set-ItResult -Skipped -Because 'Anyone links are disabled at the sharing-capability level (SMB-SPO-001); expiration is N/A.'
                return
            }

            # requireAnonymousLinksExpireInDays: 0 means no expiration, otherwise day count
            $days = $script:SpoTenant.requireAnonymousLinksExpireInDays
            $days | Should -BeGreaterThan 0 -Because 'Anyone links have no expiration. Set an expiration policy.'
            $days | Should -BeLessOrEqual 30 -Because "Current expiration: $days days. Tier 1 ceiling is 30 days."
        }

        It 'SMB-SPO-004: External users must accept invitation with the invited email' -Tag 'SMB-SPO-004','Medium' {
            # requireAcceptingAccountMatchInvitedAccount
            $script:SpoTenant.requireAcceptingAccountMatchInvitedAccount | Should -BeTrue -Because @"
Without this, an external user can forward a sharing invitation and a different account can accept it,
turning invitations into an access-transfer mechanism. Enable in SharePoint admin center or via:
Set-SPOTenant -RequireAcceptingAccountMatchInvitedAccount `$true
"@
        }
    }

    Context 'OneDrive sync restrictions' {

        It 'SMB-SPO-005: OneDrive sync blocked from non-compliant devices' -Tag 'SMB-SPO-005','Medium' {
            # Two parts: (a) SPO tenant setting isUnmanagedSyncClientForTenantRestricted should be true,
            # (b) ideally a compliance policy exists (checked separately in Device.Tests.ps1).
            $restricted = $script:SpoTenant.isUnmanagedSyncClientForTenantRestricted

            # If Intune is not in play at all, this is a soft fail — mark but don't block.
            $hasIntune = $false
            try {
                $compliancePolicies = Get-MtGraphRequest -RelativeUri 'deviceManagement/deviceCompliancePolicies' `
                                                        -ErrorAction SilentlyContinue
                $hasIntune = ($compliancePolicies.value.Count -gt 0)
            } catch {}

            if (-not $hasIntune) {
                Set-ItResult -Skipped -Because 'Intune / device management is not configured. Without compliance policies, sync restriction by compliance is not actionable. Consider Intune deployment as a prerequisite.'
                return
            }

            $restricted | Should -BeTrue -Because @"
Sync from non-domain-joined or non-compliant devices is a major exfiltration path post-compromise.
Requires Intune. Enable via SharePoint admin center → Sync → "Allow syncing only on computers
joined to specific domains" or equivalent Graph setting isUnmanagedSyncClientForTenantRestricted.
"@
        }
    }
}
