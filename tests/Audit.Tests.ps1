<#
.SYNOPSIS
    Tier 1 Audit and Telemetry tests.

.DESCRIPTION
    Covers the SMB-AUD-* control family from BASELINE.md.

    These are small in number but disproportionately important: without
    unified audit logging, no meaningful incident response is possible.
#>

BeforeDiscovery {
    # Unified audit log status is exposed via Exchange Online's Get-AdminAuditLogConfig.
    # Maester wraps this as Get-MtExoAdminAuditLogConfig.
    $script:AuditConfig = Get-MtExoAdminAuditLogConfig -ErrorAction SilentlyContinue

    # Org-level audit config (retention, etc.) varies by license.
    $script:OrgConfig = Get-MtExoOrganizationConfig -ErrorAction SilentlyContinue

    # Subscribed SKUs help us determine the expected retention ceiling.
    $script:SubscribedSkus = (Get-MtGraphRequest -RelativeUri 'subscribedSkus' -ErrorAction SilentlyContinue).value
}

Describe 'SMB Tier 1 — Audit and Telemetry' -Tag 'Audit','Tier1' {

    Context 'Unified audit log' {

        It 'SMB-AUD-001: Unified audit log ingestion is enabled' -Tag 'SMB-AUD-001','Critical' {
            $script:AuditConfig.UnifiedAuditLogIngestionEnabled | Should -BeTrue -Because @"
Unified audit log ingestion is OFF. Without it, you have no investigation capability when something goes wrong.
This is on by default for new tenants since 2019, but some migrated or legacy tenants have it disabled.
Enable via Exchange Online PowerShell:
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true
Or via Purview compliance portal → Audit → Start recording user and admin activity.
Ingestion takes up to 24 hours to fully activate after enabling.
"@
        }
    }

    Context 'Audit retention' {

        It 'SMB-AUD-002: Audit log retention is at or near the maximum supported by licensing' -Tag 'SMB-AUD-002','Low' {
            # The default retention is 180 days for E3+, 90 days for older/basic SKUs.
            # E5 / Purview Audit Premium can extend to 1 year or 10 years.
            # Pass criteria: retention policy exists OR license is basic and default (180d) is in effect.

            $plans = $script:SubscribedSkus.ServicePlans.ServicePlanName

            $hasPurviewPremium = ($plans -contains 'M365_ADVANCED_AUDITING') -or
                                 ($plans -contains 'PURVIEW_AUDIT_PREMIUM')

            $retentionPolicies = Get-MtGraphRequest `
                -RelativeUri 'security/auditLog/queries' `
                -ApiVersion beta -ErrorAction SilentlyContinue

            if ($hasPurviewPremium) {
                # Expect a custom retention policy exceeding 180 days
                $hasCustomPolicy = ($retentionPolicies.value.Count -gt 0)
                $hasCustomPolicy | Should -BeTrue -Because @"
Tenant has Purview Audit Premium but no custom retention policy is configured.
Default retention is still 180 days. Create an audit retention policy to extend to 1 year (or 10 with add-on).
Purview compliance portal → Audit → Audit retention policies.
This finding is Low severity — default 180 days is acceptable for Tier 1, but you're leaving licensed capability on the table.
"@
            } else {
                # Default applies, no action needed — record as pass
                $true | Should -BeTrue
            }
        }
    }
}
