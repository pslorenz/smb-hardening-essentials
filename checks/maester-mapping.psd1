# Maester Mapping
#
# Maps SMB-* control IDs to one or more Maester test IDs from the curated
# upstream test catalog (fetched by Update-MaesterTests). Loaded by
# Invoke-SmbHardeningAssessment.ps1 during the cloud assessment phase.
#
# ----------------------------------------------------------------------
# Why this file exists
# ----------------------------------------------------------------------
# v0.1.0-0.1.7 authored Pester test files in tests/ to evaluate cloud
# controls. That approach failed twice over: BeforeDiscovery blocks
# filtered the tests out at Pester's discovery phase, and Invoke-Maester
# -Path adds to bundled tests rather than replacing them. v0.1.8 dropped
# the authored tests and now curates Maester's curated upstream tests
# (~413 of them) by mapping the subset that satisfies our SMB-* controls.
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
#   }
#
# Aggregation:
#   - Or  : control passes if ANY mapped Maester test passes
#   - And : control passes only if ALL mapped Maester tests pass
#   Use Or unless the control text genuinely requires all conditions.
#
# License gating:
#   When Maester returns Skipped with a reason matching license / SKU
#   patterns, the wrapper marks the control NotApplicable and surfaces
#   the LicenseRequired text (or the skip reason) in the finding.
#
# ----------------------------------------------------------------------
# Verification workflow (READ BEFORE ADDING ENTRIES)
# ----------------------------------------------------------------------
# The verified-encoding rule from CONTRIBUTING.md applies to this file.
# Do NOT add a mapping based on the Maester test name "looking right" —
# verify the ID exists in the current catalog first.
#
# To enumerate available Maester test IDs against a tenant:
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
# Open catalog.csv. For each unmapped SMB-* control, search for keywords
# (e.g. "MFA", "guest invite", "DKIM"), confirm a matching test exists,
# then add the entry below with Verified = $true.
#
# Tentative candidates (commented out below) are mappings carried over
# from earlier session notes that have NOT been confirmed against the
# current catalog. Uncomment them only after running the discovery walk.
#
# ----------------------------------------------------------------------

@{

    # ===================================================================
    # VERIFIED — these test IDs were observed in actual Maester output
    # ===================================================================

    # Reduce Global Administrator count to 2-4 + designate break-glass.
    # CIS.M365.1.1.3 directly checks the count; SMB-IAM-005 (break-glass
    # configuration) is partially co-evaluated but not strictly the same.
    'SMB-IAM-004' = @{
        MaesterIds = @('CIS.M365.1.1.3')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # Cloud-only admin accounts (no on-prem-synced accounts hold roles).
    # CIS.M365.1.1.1 checks each admin account for cloud-only origin.
    'SMB-IAM-006' = @{
        MaesterIds = @('CIS.M365.1.1.1')
        Aggregate  = 'Or'
        Verified   = $true
    }

    # ===================================================================
    # TENTATIVE — uncomment after verifying against your catalog.csv
    # ===================================================================
    # The blocks below are best-guess mappings based on Maester's naming
    # patterns. They have NOT been confirmed against the current
    # Update-MaesterTests catalog. Each is commented out by default.
    # Verify the test ID exists, then uncomment and set Verified = $true.

    # # MFA enforced for all users (Security Defaults OR a CA policy)
    # 'SMB-IAM-001' = @{
    #     MaesterIds = @('MT.1007', 'MT.1021')
    #     Aggregate  = 'Or'
    #     Verified   = $false
    # }

    # # MFA enforced for administrator roles
    # 'SMB-IAM-002' = @{
    #     MaesterIds = @('MT.1006')
    #     Aggregate  = 'Or'
    #     Verified   = $false
    # }

    # # Legacy authentication blocked (CA or Security Defaults)
    # 'SMB-IAM-003' = @{
    #     MaesterIds = @('CISA.MS.AAD.1.1', 'MT.1009', 'MT.1010')
    #     Aggregate  = 'Or'
    #     Verified   = $false
    # }

    # # Sign-in risk policy enforced (P2 only)
    # 'SMB-IAM-010' = @{
    #     MaesterIds      = @('MT.1015')
    #     Aggregate       = 'Or'
    #     LicenseRequired = 'Entra ID P2'
    #     Verified        = $false
    # }

    # ===================================================================
    # UNMAPPED — controls awaiting catalog research
    # ===================================================================
    # The following SMB-* controls have no mapping yet. They will not
    # appear in cloud findings until added. See the verification
    # workflow above.
    #
    #   SMB-IAM-005, SMB-IAM-007, SMB-IAM-008, SMB-IAM-009,
    #   SMB-IAM-011, SMB-IAM-012
    #   SMB-EXO-001 through SMB-EXO-008
    #   SMB-SPO-001 through SMB-SPO-005
    #   SMB-TEAMS-001 through SMB-TEAMS-003
    #   SMB-AUD-001, SMB-AUD-002
    #   SMB-DEV-001, SMB-DEV-002, SMB-DEV-003

}
