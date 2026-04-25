# Maester Mapping
#
# Maps SMB-* control IDs to one or more Maester test IDs from the curated
# upstream test catalog (fetched by Update-MaesterTests). Loaded by
# Invoke-SmbHardeningAssessment.ps1 during the cloud assessment phase.
#
# ----------------------------------------------------------------------
# v0.1.9 mapping authored 2026-04-25 against a verified catalog.csv
# extracted from a real Maester 2.0.0 run on the Proxemedy Research
# tenant (310 tests). Every mapped entry below references a Maester
# test ID that was confirmed present in that catalog.
#
# ----------------------------------------------------------------------
# Entry format
# ----------------------------------------------------------------------
#   'SMB-IAM-XXX' = @{
#       MaesterIds      = @('CIS.M365.1.1.1', 'MT.1234')
#       Aggregate       = 'Or'                # 'Or' (default) or 'And'
#       Severity        = 'Critical'          # optional override
#       Name            = 'Display name'      # optional override
#       LicenseRequired = 'Entra ID P2'       # surface in NotApplicable findings
#       Verified        = $true               # see verification workflow below
#       Notes           = 'free-text'         # design rationale, license caveats
#   }
#
# Aggregation:
#   - Or  : control passes if ANY mapped Maester test passes
#   - And : control passes only if ALL mapped Maester tests pass
#   Use Or unless the control text genuinely requires all conditions.
#
# License gating:
#   When Maester returns Skipped with a reason matching license / SKU
#   patterns (P1, P2, E5, Defender, Premium), the wrapper marks the
#   control NotApplicable and surfaces the LicenseRequired text in the
#   finding. Tag LicenseRequired explicitly when the underlying Maester
#   test depends on a license higher than Entra ID Free / E3.
#
# Unmapped controls:
#   Some SMB-* controls intentionally have no mapping. Two reasons:
#     (a) Process controls (e.g. naming conventions, break-glass account
#         existence) that no automated test can validate.
#     (b) Configuration controls Maester's catalog does not currently
#         cover (e.g. SPO default link type, Teams guest decision).
#   These surface as NotMapped findings in the report — honest signal
#   that manual verification is required, not a hidden gap.
#
# ----------------------------------------------------------------------
# Verification workflow
# ----------------------------------------------------------------------
# Before adding or modifying an entry, verify the Maester test ID exists:
#
#   1. mkdir C:\temp\maester-discover; cd C:\temp\maester-discover
#   2. Update-MaesterTests
#   3. Connect-Maester
#   4. Invoke-Maester -OutputFolder . -OutputFolderFileName discover -DisableTelemetry -NoLogo
#   5. (Get-Content .\discover.json -Raw | ConvertFrom-Json).Tests |
#        Select Id, Title, @{N='Tags';E={$_.Tag -join ','}} |
#        Sort-Object Id |
#        Export-Csv .\catalog.csv -NoTypeInformation
#
# Open catalog.csv. Confirm any test ID you reference here actually
# exists. Do NOT add a mapping based on Maester's docs alone — the
# catalog rotates as upstream adds and removes tests.
#
# ----------------------------------------------------------------------

@{

    # ===================================================================
    # Identity & Access (SMB-IAM-*)
    # ===================================================================

    # MFA enforced for all users. Either Security Defaults (MT.1021) or
    # a CA policy targeting all users (MT.1007) satisfies the control.
    'SMB-IAM-001' = @{
        MaesterIds = @('MT.1007', 'MT.1021')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # MFA enforced for administrative roles. MT.1006 checks for a CA
    # policy specifically requiring MFA on directory roles.
    'SMB-IAM-002' = @{
        MaesterIds = @('MT.1006')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Legacy authentication blocked. Three viable enforcement paths:
    #   - MT.1009: CA blocks "other legacy authentication clients"
    #   - MT.1010: CA blocks Exchange ActiveSync legacy
    #   - MT.1021: Security Defaults (which blocks legacy by default)
    # Any of these closes the gap.
    'SMB-IAM-003' = @{
        MaesterIds = @('MT.1009', 'MT.1010', 'MT.1021')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Reduce Global Administrator count to 2-4. CIS.M365.1.1.3 evaluates
    # the count directly. NOTE: this test typically returns Skipped on
    # tenants where the calling app/user lacks RoleEligibilitySchedule
    # scope. The wrapper classifies that as Skipped-Scope (fixable by
    # reconnecting), not NotApplicable.
    'SMB-IAM-004' = @{
        MaesterIds = @('CIS.M365.1.1.3')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Break-glass account exists and is excluded from CA policies.
    # MT.1005 specifically checks that all CA policies exclude at least
    # one break-glass account/group. Doesn't directly verify the account
    # exists, but operationally equivalent: if it's excluded from CA,
    # someone deliberately created it for that purpose.
    'SMB-IAM-005' = @{
        MaesterIds = @('MT.1005')
        Aggregate  = 'Or'
        Verified   = $true
        Notes      = 'MT.1005 verifies CA exclusions, not account existence. Manual verification of the break-glass procedure is still required for Tier 2 engagements.'
    }

    # Cloud-only admin accounts. Two viable tests:
    #   - CIS.M365.1.1.1: each admin account flagged cloud-only
    #   - CISA.MS.AAD.7.3: privileged users provisioned cloud-only
    'SMB-IAM-006' = @{
        MaesterIds = @('CIS.M365.1.1.1', 'CISA.MS.AAD.7.3')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # SMB-IAM-007 (admin naming convention) is intentionally unmapped.
    # No automated test can validate naming conventions; this is a
    # process/policy control verified manually during the engagement.
    # Surfaces as NotMapped — tech reviewing the report knows to check
    # admin account names against the agreed convention.

    # User consent restrictions. Two layers:
    #   - CISA.MS.AAD.5.2: only administrators may consent
    #   - EIDSCA.AP08: a user consent policy is assigned for applications
    # AND aggregation: both should be in place. If only one passes, the
    # consent boundary is partially porous.
    'SMB-IAM-008' = @{
        MaesterIds = @('CISA.MS.AAD.5.2', 'EIDSCA.AP08')
        Aggregate  = 'And'
        Verified   = $true
    }

    # Guest invite restrictions.
    #   - CISA.MS.AAD.8.2: only users with Guest Inviter role can invite
    #   - EIDSCA.AP04: guest invite restrictions configured
    'SMB-IAM-009' = @{
        MaesterIds = @('CISA.MS.AAD.8.2', 'EIDSCA.AP04')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Sign-in risk policy (Entra ID P2 only). CISA.MS.AAD.2.3 covers
    # high-risk sign-in blocking. The wrapper auto-classifies as
    # NotApplicable on lower SKUs via the SkippedReason regex.
    'SMB-IAM-010' = @{
        MaesterIds      = @('CISA.MS.AAD.2.3')
        Aggregate       = 'Or'
        LicenseRequired = 'Entra ID P2'
        Verified        = $true
    }

    # Microsoft Authenticator hardening. Three settings on the same
    # underlying policy:
    #   - EIDSCA.AM03: require number matching for push
    #   - EIDSCA.AM06: show application name in push
    #   - EIDSCA.AM09: show geographic location in push
    # AND aggregation: all three reduce push-fatigue and AiTM risk
    # together; partial configuration is partial protection.
    'SMB-IAM-011' = @{
        MaesterIds = @('EIDSCA.AM03', 'EIDSCA.AM06', 'EIDSCA.AM09')
        Aggregate  = 'And'
        Verified   = $true
    }

    # SMB-IAM-012 (SSPR for users) is intentionally unmapped.
    # The catalog has EIDSCA.AP01 (admin SSPR) but no test for general
    # user SSPR enablement. v0.2 candidate: contribute upstream to
    # Maester or accept manual verification.

    # ===================================================================
    # Exchange Online (SMB-EXO-*)
    # ===================================================================

    # Preset Security Policies / Safe Attachments-equivalent.
    # CIS.M365.2.1.4 (Safe Attachments) is E5-only. Fall back to
    # CISA.MS.EXO.10.1/10.2 which check malware scanning + quarantine
    # under EOP (E3 baseline).
    'SMB-EXO-001' = @{
        MaesterIds = @('CISA.MS.EXO.10.1', 'CISA.MS.EXO.10.2')
        Aggregate  = 'And'
        Verified   = $true
    }

    # External sender warning (External tag in Outlook).
    'SMB-EXO-002' = @{
        MaesterIds = @('CISA.MS.EXO.7.1')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Block external auto-forwarding.
    'SMB-EXO-003' = @{
        MaesterIds = @('CISA.MS.EXO.1.1')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Mailbox auditing enabled.
    'SMB-EXO-004' = @{
        MaesterIds = @('CISA.MS.EXO.13.1')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # SPF record published.
    'SMB-EXO-005' = @{
        MaesterIds = @('CISA.MS.EXO.2.2')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # DKIM enabled. Three sources cover this:
    #   - CISA.MS.EXO.3.1: DKIM should be enabled for all domains
    #   - CIS.M365.2.1.9: DKIM enabled across EXO domains
    #   - ORCA.108: DKIM signing set up for custom domains
    'SMB-EXO-006' = @{
        MaesterIds = @('CISA.MS.EXO.3.1', 'CIS.M365.2.1.9', 'ORCA.108')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # DMARC published. CISA.MS.EXO.4.1 covers existence of a policy.
    # NOTE: Tier 1 baseline calls for p=quarantine; CISA.MS.EXO.4.2
    # demands p=reject. Mapping to 4.1 only avoids false-failing the
    # control on tenants that follow the documented Tier 1 stance.
    # Revisit in v0.2 when we decide whether to harden Tier 1 to p=reject.
    'SMB-EXO-007' = @{
        MaesterIds = @('CISA.MS.EXO.4.1')
        Aggregate  = 'Or'
        Verified   = $true
        Notes      = 'Maps to existence of DMARC policy. Strictness (quarantine vs reject) is a separate v0.2 decision.'
    }

    # Modern authentication for Exchange Online.
    'SMB-EXO-008' = @{
        MaesterIds = @('MT.1044')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # ===================================================================
    # SharePoint Online (SMB-SPO-*)
    # ===================================================================

    # External sharing restricted.
    'SMB-SPO-001' = @{
        MaesterIds = @('CISA.MS.SHAREPOINT.1.1')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # SMB-SPO-002 through SMB-SPO-005 are intentionally unmapped.
    # The Maester catalog as of v0.1.9 does not include tests for:
    #   - SPO-002: default link type ("Specific people" vs "Anyone")
    #   - SPO-003: Anyone link expiration window
    #   - SPO-004: RequireAcceptingAccountMatchInvitedAccount
    #   - SPO-005: compliant device requirement for SPO (Intune)
    # Surface as NotMapped. Manual verification per RUNBOOK.

    # ===================================================================
    # Teams (SMB-TEAMS-*)
    # ===================================================================

    # External access / unmanaged Teams users.
    'SMB-TEAMS-001' = @{
        MaesterIds = @('CIS.M365.8.2.2')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # SMB-TEAMS-002 (guest access decision) is intentionally unmapped.
    # Either On-with-controls or Off can be correct depending on the
    # client's collaboration model. No automated test can determine
    # which is right for a given tenant. Process control.

    # Anonymous user lobby enforcement. Three angles:
    #   - MT.1046: restrict anonymous from joining
    #   - MT.1047: restrict anonymous from starting
    #   - CIS.M365.8.5.3: only people in org bypass lobby
    'SMB-TEAMS-003' = @{
        MaesterIds = @('MT.1046', 'MT.1047', 'CIS.M365.8.5.3')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # ===================================================================
    # Audit (SMB-AUD-*)
    # ===================================================================

    # Unified audit log enabled.
    'SMB-AUD-001' = @{
        MaesterIds = @('CIS.M365.3.1.1', 'CISA.MS.EXO.17.1')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Audit retention duration. CISA.MS.EXO.17.3 checks duration
    # against OMB M-21-31 (12 months default). Tenants without Audit
    # Premium will skip / fail; treat as license-gated for SMB.
    'SMB-AUD-002' = @{
        MaesterIds      = @('CISA.MS.EXO.17.3')
        Aggregate       = 'Or'
        LicenseRequired = 'Microsoft Purview Audit (Premium)'
        Verified        = $true
        Notes           = 'CISA.MS.EXO.17.2 (Premium logging enabled) is tagged Deprecated in the v0.1.9 catalog. Using 17.3 (retention duration) as primary signal.'
    }

}
