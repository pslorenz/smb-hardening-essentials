<#
.SYNOPSIS
    Tier 1 Device Compliance tests.

.DESCRIPTION
    Covers the SMB-DEV-* control family from BASELINE.md.

    These controls are meaningful only when Intune (or an equivalent MDM)
    is in use. When Intune is not detected, tests are skipped with a clear
    message rather than failing — "no Intune" is a valid Tier 1 state that
    simply means these controls are N/A.
#>

BeforeDiscovery {
    # Probe for Intune configuration. The presence of device management data
    # in Graph indicates Intune is at least licensed and minimally configured.
    $script:CompliancePolicies = @()
    $script:ConfigPolicies     = @()
    $script:IntuneDetected     = $false

    try {
        $cp = Get-MtGraphRequest -RelativeUri 'deviceManagement/deviceCompliancePolicies' `
                                 -ErrorAction Stop
        $script:CompliancePolicies = $cp.value
        $script:IntuneDetected = $true
    } catch {
        # 403/404 here means Intune is not licensed or the app lacks DeviceManagementConfiguration.Read.All
    }

    $script:CAPolicies = Get-MtConditionalAccessPolicy -ErrorAction SilentlyContinue

    # Fetch group memberships of all compliance policy assignments, resolved for coverage check
    $script:AllUsersGroupId = (Get-MtGraphRequest -RelativeUri "groups?`$filter=displayName eq 'All Users'" `
                                                  -ErrorAction SilentlyContinue).value |
                              Select-Object -ExpandProperty id -First 1
}

Describe 'SMB Tier 1 — Device Compliance' -Tag 'Device','Tier1' {

    BeforeAll {
        if (-not $script:IntuneDetected) {
            Write-Warning "Intune not detected in tenant. Device controls will be marked N/A. If Intune is expected, verify DeviceManagementConfiguration.Read.All is granted."
        }
    }

    Context 'Compliance policy presence' {

        It 'SMB-DEV-001: At least one compliance policy exists and is assigned' -Tag 'SMB-DEV-001','High' {
            if (-not $script:IntuneDetected) {
                Set-ItResult -Skipped -Because 'Intune not configured in tenant. Device compliance controls are N/A.'
                return
            }

            @($script:CompliancePolicies).Count | Should -BeGreaterThan 0 -Because @"
No device compliance policies exist. Create at minimum a Windows compliance policy requiring:
  - BitLocker enabled, Secure Boot enabled, Antivirus on
  - OS build greater than or equal to supported minimum
  - Device not jailbroken/rooted (mobile)
Intune admin center → Devices → Compliance policies → Create policy.
"@

            # Verify at least one policy has assignments (unassigned policies are decorative).
            $assigned = foreach ($p in $script:CompliancePolicies) {
                $assignments = Get-MtGraphRequest `
                    -RelativeUri "deviceManagement/deviceCompliancePolicies/$($p.id)/assignments" `
                    -ErrorAction SilentlyContinue
                if ($assignments.value.Count -gt 0) { $p }
            }

            @($assigned).Count | Should -BeGreaterThan 0 -Because @"
Compliance policies exist but none are assigned to any users or devices. Unassigned policies do nothing.
Each policy → Properties → Assignments → Add group (All Users or a specific group covering >95% of users).
"@
        }
    }

    Context 'Conditional Access enforcement' {

        It 'SMB-DEV-002: A Conditional Access policy requires compliant device for M365 access' -Tag 'SMB-DEV-002','High' {
            if (-not $script:IntuneDetected) {
                Set-ItResult -Skipped -Because 'Intune not configured. Device-based CA is N/A without compliance data.'
                return
            }

            $compliantDevicePolicy = $script:CAPolicies | Where-Object {
                $_.State -eq 'enabled' -and
                (($_.GrantControls.BuiltInControls -contains 'compliantDevice') -or
                 ($_.GrantControls.BuiltInControls -contains 'domainJoinedDevice'))
            }

            @($compliantDevicePolicy).Count | Should -BeGreaterThan 0 -Because @"
No enabled Conditional Access policy requires a compliant or Entra-joined device.
Compliance without CA enforcement is decorative. Create a CA policy:
  - Users: All users (exclude break-glass)
  - Cloud apps: Office 365 (or All cloud apps)
  - Grant: Require device to be marked as compliant (and/or hybrid Entra joined)
Start in report-only mode, validate for 1-2 weeks, then enable.
"@
        }
    }

    Context 'Grace period and rollout' {

        It 'SMB-DEV-003: Non-compliant device grace period is configured between 1 and 7 days' -Tag 'SMB-DEV-003','Medium' {
            if (-not $script:IntuneDetected -or -not $script:CompliancePolicies) {
                Set-ItResult -Skipped -Because 'No compliance policies to evaluate grace period.'
                return
            }

            # Each compliance policy has a scheduledActionsForRule with gracePeriodHours on notification / block
            $problems = foreach ($p in $script:CompliancePolicies) {
                $actions = Get-MtGraphRequest `
                    -RelativeUri "deviceManagement/deviceCompliancePolicies/$($p.id)/scheduledActionsForRule" `
                    -ErrorAction SilentlyContinue
                $blockActions = $actions.value.scheduledActionConfigurations |
                                Where-Object actionType -EQ 'block'

                foreach ($b in $blockActions) {
                    $hours = [int]$b.gracePeriodHours
                    if ($hours -eq 0) {
                        [pscustomobject]@{ Policy = $p.displayName; Issue = 'Immediate block (no grace)' }
                    } elseif ($hours -gt (7*24)) {
                        [pscustomobject]@{ Policy = $p.displayName; Issue = "Grace $hours hours (> 7 days)" }
                    }
                }
            }

            @($problems).Count | Should -Be 0 -Because @"
The following compliance policies have grace periods outside the 1-7 day Tier 1 range:
$($problems | ForEach-Object { "  - $($_.Policy): $($_.Issue)" } | Out-String)
Hard cutoffs cause weekend outages. Excessive grace means non-compliance persists.
Edit each policy → Actions for noncompliance → 'Block' action → set gracePeriod between 24-168 hours.
"@
        }
    }
}
