<#
.SYNOPSIS
    SMB Hardening Essentials (Tier 1) assessment wrapper.

.DESCRIPTION
    Orchestrates Maester (M365/Entra assessment) and HardeningKitty (Windows
    endpoint assessment) against the Tier 1 baseline, then produces a unified
    HTML report suitable for client delivery.

    This is a v0.1 reference implementation. See RUNBOOK.md for operational
    guidance and BASELINE.md for the control reference.

.PARAMETER TenantId
    Entra ID tenant GUID. Required unless -EndpointOnly.

.PARAMETER ClientName
    Client name as it should appear on the report. Used for output path.

.PARAMETER OutputPath
    Root path for output. A timestamped subdirectory will be created under
    <OutputPath>/<ClientName>/<YYYYMMDD-HHMMSS>/.

.PARAMETER HardeningKittyPath
    Path to the directory containing HardeningKitty.psd1 and HardeningKitty.psm1.
    Optional if HardeningKitty is already installed in a PSModulePath location.
    Required unless -CloudOnly.

.PARAMETER CloudOnly
    Run Maester only; skip endpoint assessment.

.PARAMETER EndpointOnly
    Run HardeningKitty only; skip M365 assessment.

.PARAMETER Categories
    Limit assessment to specific categories. Valid values: Identity,
    ExchangeOnline, SharePoint, Teams, Audit, Device, Defender, ASR,
    Credential, BitLocker, Network, Office, Firewall, UAC, Updates,
    Logging, RemovableMedia. Default: all.

.PARAMETER ClientId
    App registration client ID for non-interactive auth.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for non-interactive auth.

.PARAMETER NonInteractive
    Suppress prompts. Requires -ClientId and -CertificateThumbprint.

.PARAMETER ExceptionsFile
    Path to client-exceptions.json. If present in OutputPath, picked up
    automatically.

.EXAMPLE
    .\Invoke-SmbHardeningAssessment.ps1 -TenantId <guid> -ClientName "Acme Corp" -OutputPath .\reports

.EXAMPLE
    .\Invoke-SmbHardeningAssessment.ps1 -TenantId <guid> -ClientName "Acme" -CloudOnly

.PARAMETER SkipMaesterTestsUpdate
    Skip the Update-MaesterTests fetch. Use only when the Maester test cache
    is already populated (e.g., offline runs or repeat assessments). The
    wrapper will fail fast if the cache is empty when this is set.

.PARAMETER MaesterTestCachePath
    Override the Maester test cache location. Default:
    $env:TEMP\smb-hardening-essentials\maester-tests. Persists across runs.

.NOTES
    Author:  pslorenz
    License: MIT
    Version: 0.1.8
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Interactive')]
    [Parameter(Mandatory, ParameterSetName = 'NonInteractive')]
    [Parameter(ParameterSetName = 'EndpointOnly')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientName,

    [Parameter()]
    [string]$OutputPath = ".\reports",

    [Parameter()]
    [string]$HardeningKittyPath,

    [Parameter(ParameterSetName = 'CloudOnly')]
    [switch]$CloudOnly,

    [Parameter(ParameterSetName = 'EndpointOnly')]
    [switch]$EndpointOnly,

    [Parameter()]
    [ValidateSet('Identity','ExchangeOnline','SharePoint','Teams','Audit','Device',
                 'Defender','ASR','Credential','BitLocker','Network','Office',
                 'Firewall','UAC','Updates','Logging','RemovableMedia')]
    [string[]]$Categories,

    [Parameter(ParameterSetName = 'NonInteractive')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'NonInteractive')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'NonInteractive')]
    [switch]$NonInteractive,

    [Parameter()]
    [string]$ExceptionsFile,

    [Parameter()]
    [switch]$SkipMaesterTestsUpdate,

    [Parameter()]
    [string]$MaesterTestCachePath
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

$script:BaselineVersion = '0.1.9.1'
$script:RunTimestamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:RunId           = [guid]::NewGuid().ToString()
$script:ScriptRoot      = $PSScriptRoot

# Resolve OutputPath to an absolute path BEFORE doing anything else. The
# Maester phase calls Push-Location into the test cache directory, and
# Maester (via Pester) runs many subprocesses that can also change CWD.
# Any relative paths captured before that point will silently rebase
# onto the cache dir and produce ghost output trees there. v0.1.8.1
# fix: anchor every path that the wrapper writes to.
if (-not (Test-Path $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
}
$OutputPath = (Resolve-Path -Path $OutputPath -ErrorAction Stop).ProviderPath

$safeName = $ClientName -replace '[^\w\s-]', '' -replace '\s+', ' '
$runDir = Join-Path $OutputPath "$safeName\$script:RunTimestamp"
$null = New-Item -ItemType Directory -Path $runDir -Force

$script:LogPath = Join-Path $runDir 'run.log'

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $script:LogPath -Value $line
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
}

Write-Log "SMB Hardening Essentials assessment starting"
Write-Log "Client: $ClientName"
Write-Log "Run ID: $script:RunId"
Write-Log "Baseline: v$script:BaselineVersion"
Write-Log "Output:   $runDir"

# ---------------------------------------------------------------------------
# Exception loading
# ---------------------------------------------------------------------------

$script:Exceptions = @{}
if (-not $ExceptionsFile) {
    $candidate = Join-Path (Split-Path $runDir -Parent) 'client-exceptions.json'
    if (Test-Path $candidate) { $ExceptionsFile = $candidate }
}
if ($ExceptionsFile -and (Test-Path $ExceptionsFile)) {
    try {
        $exc = Get-Content $ExceptionsFile -Raw | ConvertFrom-Json
        foreach ($e in $exc.exclusions) { $script:Exceptions[$e.controlId] = $e }
        Write-Log "Loaded $($script:Exceptions.Count) exceptions from $ExceptionsFile" -Level OK
    } catch {
        Write-Log "Failed to parse exceptions file: $_" -Level WARN
    }
}

# ---------------------------------------------------------------------------
# Remediation map + HK input CSV lookup
# ---------------------------------------------------------------------------
# The remediation map is the canonical source of "what to do about a failing
# control." HardeningKitty's output doesn't carry remediation guidance and
# Pester tests carry it only in -Because clauses (which are result-side,
# not findings-side). Centralizing remediation by control ID means one place
# to maintain it across both assessors.
#
# The HK input CSV lookup preserves the ORIGINAL severity and recommended
# value for each control, since HardeningKitty's output reuses the Severity
# column to encode pass/fail state, overwriting the input severity.

$script:RemediationMap = @{}
$remedMapPath = Join-Path $script:ScriptRoot 'checks\remediation-map.psd1'
if (Test-Path $remedMapPath) {
    try {
        $script:RemediationMap = Import-PowerShellDataFile -Path $remedMapPath
        Write-Log "Loaded $($script:RemediationMap.Count) remediation entries" -Level OK
    } catch {
        Write-Log "Failed to load remediation map: $_" -Level WARN
    }
}

$script:HkInputLookup = @{}
$findingListPath = Join-Path $script:ScriptRoot 'checks\tier1-hardeningkitty.csv'
if (Test-Path $findingListPath) {
    try {
        Import-Csv -Path $findingListPath | ForEach-Object {
            if ($_.ID) { $script:HkInputLookup[$_.ID] = $_ }
        }
        Write-Log "Loaded $($script:HkInputLookup.Count) HK control definitions for lookup" -Level OK
    } catch {
        Write-Log "Failed to load HK input CSV for lookup: $_" -Level WARN
    }
}

# Maester mapping: SMB-* control ID -> { MaesterIds, Aggregate, LicenseRequired }.
# Loaded from checks/maester-mapping.psd1. v0.1.8 changed the cloud-side
# strategy from authored Pester tests to curating Maester's bundled tests
# (fetched via Update-MaesterTests). The mapping is the single source of
# truth for which Maester test ID(s) satisfy each SMB-* control.
$script:MaesterMap = @{}
$maesterMapPath = Join-Path $script:ScriptRoot 'checks\maester-mapping.psd1'
if (Test-Path $maesterMapPath) {
    try {
        $script:MaesterMap = Import-PowerShellDataFile -Path $maesterMapPath
        Write-Log "Loaded $($script:MaesterMap.Count) Maester mappings" -Level OK
    } catch {
        Write-Log "Failed to load Maester mapping: $_" -Level WARN
    }
}

function Get-Remediation {
    param([string]$ControlId)
    if ($ControlId -and $script:RemediationMap.ContainsKey($ControlId)) {
        return $script:RemediationMap[$ControlId]
    }
    return "See docs/BASELINE.md for $ControlId remediation guidance."
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

function Test-Prerequisites {
    $issues = @()

    if (-not $EndpointOnly) {
        if (-not (Get-Module -ListAvailable -Name Maester)) {
            $issues += 'Maester module not installed. Run: Install-Module Maester -Scope CurrentUser. If on PowerShell 5.1 and Install-Module silently drops files (Maester 2.x has 700+ files), use PSResourceGet (Install-PSResource Maester) or extract the .nupkg manually. See RUNBOOK.md > Installation prerequisites.'
        } else {
            # Verify the install isn't half-broken: Import-Module + check
            # the three commands the wrapper actually depends on. Counts of
            # files in the module folder are unreliable (Maester 2.x splits
            # tests out into a separate Update-MaesterTests fetch), so we
            # check command availability directly.
            try {
                Import-Module Maester -ErrorAction Stop
                $required = @('Connect-Maester','Invoke-Maester','Update-MaesterTests')
                $missing = $required | Where-Object {
                    -not (Get-Command $_ -Module Maester -ErrorAction SilentlyContinue)
                }
                if ($missing) {
                    $issues += "Maester module imported but is missing commands: $($missing -join ', '). The install is incomplete. Reinstall using PSResourceGet or .nupkg extraction. See RUNBOOK.md."
                }
            } catch {
                $issues += "Failed to import Maester module: $_. The install may be corrupted. See RUNBOOK.md > Installation prerequisites."
            }
        }
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            $issues += 'Microsoft.Graph.Authentication not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        }
    }

    if (-not $CloudOnly) {
        $hkInstalled = Get-Module -Name HardeningKitty -ListAvailable -ErrorAction SilentlyContinue

        if (-not $HardeningKittyPath -and -not $hkInstalled) {
            $issues += '-HardeningKittyPath is required unless HardeningKitty is installed in a PSModulePath location (see https://github.com/scipag/HardeningKitty for installation)'
        } elseif ($HardeningKittyPath) {
            $psd1 = Join-Path $HardeningKittyPath 'HardeningKitty.psd1'
            $psm1 = Join-Path $HardeningKittyPath 'HardeningKitty.psm1'
            if (-not ((Test-Path $psd1) -or (Test-Path $psm1))) {
                $issues += "HardeningKitty module not found at $HardeningKittyPath. Expected HardeningKitty.psd1 or HardeningKitty.psm1."
            }
        }
        $current = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($current)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $issues += 'HardeningKitty requires local admin. Re-run this script from an elevated PowerShell session.'
        }
    }

    if ($issues) {
        foreach ($i in $issues) { Write-Log $i -Level ERROR }
        throw 'Prerequisite check failed. See messages above.'
    }
    Write-Log 'Prerequisites OK' -Level OK
}

Test-Prerequisites

# ---------------------------------------------------------------------------
# M365 / Maester phase
# ---------------------------------------------------------------------------
#
# v0.1.8 changed the strategy here. Earlier versions authored Pester test
# files in tests/ and pointed Invoke-Maester -Path at them. That approach
# failed because:
#
#   1. Our test files used BeforeDiscovery blocks that called Graph cmdlets.
#      Pester runs BeforeDiscovery during the discovery phase, BEFORE
#      Connect-Maester has happened, so the cmdlets returned null and the
#      It blocks were filtered out. Discovery completed cleanly with 0
#      executable tests.
#   2. Invoke-Maester -Path doesn't replace bundled tests, it adds to them.
#      So even if our tests had worked, we'd have been running Maester's
#      ~413 curated tests too.
#
# v0.1.8 leans into option 2: run Maester's curated upstream tests
# (fetched by Update-MaesterTests), then map results back to SMB-* control
# IDs via checks/maester-mapping.psd1.
#
# Notes on directory handling:
#
#   - Update-MaesterTests writes test files (./cis/, ./eidsca/, etc.) into
#     the current working directory. We Set-Location to the cache path
#     before invoking it.
#   - Pester's discovery scans CWD recursively for *.Tests.ps1. If the
#     wrapper is invoked from a directory containing other Pester test
#     files (a common contamination source: the user's Downloads folder
#     after running ScubaGear or similar), those tests run too. The cache
#     path is dedicated to Maester, so this isn't a problem there, but
#     we always Push-Location/Pop-Location around the invocation so the
#     caller's CWD is restored.
#   - OutputFolder and OutputJsonFile are mutually exclusive in Maester:
#     when OutputFolder is set, all other -Output*File parameters are
#     ignored. We use OutputFolder + OutputFolderFileName for predictable
#     output paths.

$maesterFindings = @()

if (-not $EndpointOnly) {
    # Determine cache location for Maester's curated test files.
    if (-not $MaesterTestCachePath) {
        $MaesterTestCachePath = Join-Path $env:TEMP 'smb-hardening-essentials\maester-tests'
    }
    $null = New-Item -ItemType Directory -Path $MaesterTestCachePath -Force

    Write-Log "Maester test cache: $MaesterTestCachePath"

    Push-Location $MaesterTestCachePath
    try {
        Import-Module Maester -ErrorAction Stop

        # Step 1: refresh the curated test catalog (unless skipped).
        if ($SkipMaesterTestsUpdate) {
            $existing = @(Get-ChildItem -Path $MaesterTestCachePath -Recurse -Filter '*.Tests.ps1' -ErrorAction SilentlyContinue)
            if ($existing.Count -lt 50) {
                throw "-SkipMaesterTestsUpdate was specified but the cache contains only $($existing.Count) test files (expected 50+). Re-run without -SkipMaesterTestsUpdate to fetch the catalog."
            }
            Write-Log "Skipped Update-MaesterTests; using cache with $($existing.Count) test files" -Level OK
        } else {
            Write-Log 'Fetching Maester curated tests (Update-MaesterTests)...'
            try {
                Update-MaesterTests -ErrorAction Stop | Out-Null
            } catch {
                throw "Update-MaesterTests failed: $_. Common causes: no internet access, GitHub rate-limit, corporate proxy blocking raw.githubusercontent.com. Re-run with -SkipMaesterTestsUpdate if a recent cache exists at $MaesterTestCachePath."
            }
            $fetched = @(Get-ChildItem -Path $MaesterTestCachePath -Recurse -Filter '*.Tests.ps1' -ErrorAction SilentlyContinue)
            if ($fetched.Count -lt 50) {
                throw "Update-MaesterTests appeared to succeed but produced only $($fetched.Count) test files. Expected 50+. Inspect $MaesterTestCachePath for partial extraction."
            }
            Write-Log "Maester test cache populated: $($fetched.Count) test files" -Level OK
        }

        # Step 2: connect to the tenant.
        # Connect-Maester defaults to Microsoft Graph only. Many of the
        # curated tests we map to live in Exchange Online (CISA.MS.EXO.*,
        # CIS.M365.2.*, CIS.M365.3.*, MT.10[34][0-9]), Teams (CIS.M365.8.*,
        # MT.104[5-8]), or SharePoint (CISA.MS.SHAREPOINT.*). Without
        # connecting to those services, Maester correctly skips the
        # tests with "Not connected to <service>" — which we then
        # classify as Skipped-Other and surface in findings as a
        # configuration question, not a real result.
        #
        # v0.1.9: request all four services Maester supports. This
        # opens additional consent screens on first run for ExchangeOnline
        # and Teams admin permissions; subsequent runs use cached creds.
        # If a service isn't licensed in the tenant, Connect-Maester logs
        # a warning and continues — Maester then skips the affected
        # tests, which is the desired behavior.
        # v0.1.9.1: Maester's -Service ValidateSet is
        #   All, Azure, ExchangeOnline, Graph, SecurityCompliance, Teams
        # No separate SharePoint value — SPO tests run under Graph or
        # one of the other services. Using 'All' to cover everything
        # available in the tenant; Connect-Maester will warn-and-continue
        # for any service not licensed.
        Write-Log 'Connecting Maester to all available services...'
        $connectParams = @{
            TenantId = $TenantId
            Service  = 'All'
        }
        if ($NonInteractive) {
            if (-not ($ClientId -and $CertificateThumbprint)) {
                throw '-NonInteractive requires -ClientId and -CertificateThumbprint'
            }
            $connectParams['ClientId'] = $ClientId
            $connectParams['CertificateThumbprint'] = $CertificateThumbprint
            # NOTE: cert-based auth in non-interactive mode currently
            # only authenticates Graph. EXO/Teams/SharePoint cert-based
            # auth requires per-service app registrations. v0.2 work.
            Write-Log 'NonInteractive cert auth: only Graph is authenticated. EXO/Teams/SPO tests will be Skipped-Other.' -Level WARN
        }
        Connect-Maester @connectParams | Out-Null
        Write-Log 'Connected to tenant' -Level OK

        # Step 3: run Maester's curated tests against the tenant.
        $maesterOutputFile = Join-Path $runDir 'maester-raw.json'

        Write-Log 'Running Maester (curated test catalog)...'
        $maesterParams = @{
            OutputFolder         = $runDir
            OutputFolderFileName = 'maester-raw'
            DisableTelemetry     = $true
            NoLogo               = $true
        }
        Invoke-Maester @maesterParams | Out-Null

        if (-not (Test-Path $maesterOutputFile)) {
            throw "Maester completed but the expected output file was not found at $maesterOutputFile. Inspect $runDir for the actual output path."
        }

        # Step 4: parse, map to SMB-*, aggregate.
        $raw = Get-Content $maesterOutputFile -Raw | ConvertFrom-Json
        $allTests = @($raw.Tests)
        Write-Log "Maester returned $($allTests.Count) test results (Pass=$($raw.PassedCount) Fail=$($raw.FailedCount) Skip=$($raw.SkippedCount) Err=$($raw.ErrorCount))" -Level OK

        # Index by Maester test Id for fast lookup.
        $byId = @{}
        foreach ($t in $allTests) { $byId[$t.Id] = $t }

        # Walk the SMB-* mapping and produce one finding per mapped control.
        foreach ($ctlId in $script:MaesterMap.Keys) {
            $entry = $script:MaesterMap[$ctlId]
            $maesterIds = @($entry.MaesterIds)
            $aggregate  = if ($entry.Aggregate) { $entry.Aggregate } else { 'Or' }
            $licenseReq = $entry.LicenseRequired

            # Resolve each mapped Maester ID to its result row (or null).
            $resolved = foreach ($mid in $maesterIds) {
                if ($byId.ContainsKey($mid)) { $byId[$mid] } else { $null }
            }

            $perTest = @()
            foreach ($i in 0..($maesterIds.Count - 1)) {
                $mt = $resolved[$i]
                if ($null -eq $mt) {
                    $perTest += [pscustomobject]@{
                        Id     = $maesterIds[$i]
                        Result = 'NotFound'
                        Reason = 'Test ID not present in Maester catalog. Mapping may be stale, or the test was removed/renamed upstream.'
                    }
                } else {
                    # Classify Skipped reason: scope-missing vs license vs other.
                    $reason = $null
                    $resultKind = $mt.Result
                    if ($mt.Result -eq 'Skipped') {
                        $sr = $mt.ResultDetail.SkippedReason
                        if ($sr -match 'Missing Scope') {
                            $resultKind = 'Skipped-Scope'
                            $reason = $sr
                        } elseif ($sr -match '(?i)license|requires.*P[12]|requires.*E[35]|requires.*Defender|requires.*Premium') {
                            $resultKind = 'NotApplicable'
                            $reason = $sr
                        } else {
                            $resultKind = 'Skipped-Other'
                            $reason = $sr
                        }
                    } elseif ($mt.Result -eq 'Failed') {
                        $reason = $mt.ResultDetail.TestResult
                    }
                    $perTest += [pscustomobject]@{
                        Id     = $maesterIds[$i]
                        Result = $resultKind
                        Reason = $reason
                    }
                }
            }

            # Aggregate the per-test results into one control-level result.
            # OR: any Passed wins; else any Failed wins; else look at skips.
            # AND: any Failed wins; else any non-Pass wins; else Passed.
            # Wrap with @() to defeat PowerShell's scalar-unwrapping on
            # 0/1-element pipeline output, which would otherwise break .Count.
            $passed    = @($perTest | Where-Object { $_.Result -eq 'Passed' })
            $failed    = @($perTest | Where-Object { $_.Result -eq 'Failed' })
            $skipScope = @($perTest | Where-Object { $_.Result -eq 'Skipped-Scope' })
            $notApp    = @($perTest | Where-Object { $_.Result -eq 'NotApplicable' })
            $notFound  = @($perTest | Where-Object { $_.Result -eq 'NotFound' })

            $aggResult = if ($aggregate -eq 'And') {
                if ($failed.Count -gt 0)                          { 'Failed' }
                elseif ($skipScope.Count -gt 0)                   { 'Skipped' }
                elseif ($notApp.Count -eq $perTest.Count)         { 'NotApplicable' }
                elseif ($notFound.Count -eq $perTest.Count)       { 'NotMapped' }
                elseif ($passed.Count -lt $perTest.Count)         { 'Skipped' }
                else                                              { 'Passed' }
            } else {
                # OR (default)
                if ($passed.Count -gt 0)                          { 'Passed' }
                elseif ($failed.Count -gt 0)                      { 'Failed' }
                elseif ($notApp.Count -eq $perTest.Count)         { 'NotApplicable' }
                elseif ($skipScope.Count -gt 0)                   { 'Skipped' }
                elseif ($notFound.Count -eq $perTest.Count)       { 'NotMapped' }
                else                                              { 'Skipped' }
            }

            # Build the human-readable detail string.
            $details = switch ($aggResult) {
                'Passed' {
                    $names = ($passed | ForEach-Object { $_.Id }) -join ', '
                    "Passed via: $names"
                }
                'Failed' {
                    $first = $failed | Select-Object -First 1
                    if ($first.Reason) { $first.Reason -replace '\s+', ' ' } else { "Failed: $($first.Id)" }
                }
                'NotApplicable' {
                    $req = if ($licenseReq) { $licenseReq } else {
                        ($notApp | Select-Object -First 1).Reason
                    }
                    "Not applicable in this tenant. License/feature required: $req"
                }
                'Skipped' {
                    $first = $perTest | Where-Object Result -in 'Skipped-Scope','Skipped-Other','Skipped' | Select-Object -First 1
                    if ($first.Result -eq 'Skipped-Scope') {
                        "Skipped: $($first.Reason). Reconnect with broader Graph consent: Connect-Maester -Scopes (Get-MtGraphScope)."
                    } elseif ($first.Reason) {
                        "Skipped: $($first.Reason)"
                    } else {
                        "Skipped"
                    }
                }
                'NotMapped' {
                    $ids = ($maesterIds) -join ', '
                    "No matching Maester tests found. Mapped IDs: $ids. Update checks/maester-mapping.psd1."
                }
                default { '' }
            }

            # Severity: prefer the mapping's explicit Severity, else fall
            # back to the underlying test's severity (first non-empty),
            # else 'Medium'.
            $sev = if ($entry.Severity) { $entry.Severity } else {
                $found = $resolved | Where-Object { $_ -and $_.Severity } | Select-Object -First 1
                if ($found) { $found.Severity } else { 'Medium' }
            }

            # Category: keep our SMB-* categorization (parsed from ID prefix).
            $category = switch -Regex ($ctlId) {
                '^SMB-IAM-'   { 'Identity'; break }
                '^SMB-EXO-'   { 'ExchangeOnline'; break }
                '^SMB-SPO-'   { 'SharePoint'; break }
                '^SMB-TEAMS-' { 'Teams'; break }
                '^SMB-AUD-'   { 'Audit'; break }
                '^SMB-DEV-'   { 'Device'; break }
                default       { 'Cloud' }
            }

            $name = if ($entry.Name) { $entry.Name } else {
                $found = $resolved | Where-Object { $_ -and $_.Title } | Select-Object -First 1
                if ($found) { $found.Title } else { $ctlId }
            }

            $maesterFindings += [pscustomobject]@{
                ControlId      = $ctlId
                Category       = $category
                Name           = $name
                Result         = $aggResult
                Severity       = $sev
                Details        = $details
                Remediation    = Get-Remediation -ControlId $ctlId
                Source         = 'Maester'
                MaesterIds     = $maesterIds
                MaesterResults = $perTest
                Aggregate      = $aggregate
            }
        }
        Write-Log "Mapped $($maesterFindings.Count) SMB-* cloud findings from Maester results" -Level OK

        # Surface unmapped controls as a hint, but don't fail the run.
        $unmapped = $maesterFindings | Where-Object Result -eq 'NotMapped'
        if ($unmapped) {
            Write-Log "$($unmapped.Count) control(s) have stale mapping (Maester test ID not found in catalog). Update checks\maester-mapping.psd1." -Level WARN
        }
    } catch {
        Write-Log "Maester phase failed: $_" -Level ERROR
    } finally {
        Pop-Location
        try { Disconnect-Maester -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

# ---------------------------------------------------------------------------
# Endpoint / HardeningKitty phase
# ---------------------------------------------------------------------------

$hkFindings = @()

if (-not $CloudOnly) {
    Write-Log 'Running HardeningKitty...'
    try {
        # Import the HardeningKitty module. Two supported layouts:
        #   1) HardeningKittyPath points at the module root (contains HardeningKitty.psm1)
        #   2) HardeningKitty is already installed in a PSModulePath location
        $hkModule = Get-Module -Name HardeningKitty -ListAvailable | Select-Object -First 1

        if ($HardeningKittyPath) {
            $psm1 = Join-Path $HardeningKittyPath 'HardeningKitty.psm1'
            $psd1 = Join-Path $HardeningKittyPath 'HardeningKitty.psd1'
            if (Test-Path $psd1) {
                Import-Module $psd1 -Force -ErrorAction Stop
            } elseif (Test-Path $psm1) {
                Import-Module $psm1 -Force -ErrorAction Stop
            } else {
                throw "HardeningKitty module files not found at $HardeningKittyPath. Expected HardeningKitty.psd1 or HardeningKitty.psm1."
            }
        } elseif ($hkModule) {
            Import-Module HardeningKitty -Force -ErrorAction Stop
        } else {
            throw 'HardeningKitty not found. Either specify -HardeningKittyPath or install the module: see https://github.com/scipag/HardeningKitty'
        }

        if (-not (Get-Command Invoke-HardeningKitty -ErrorAction SilentlyContinue)) {
            throw 'HardeningKitty module imported but Invoke-HardeningKitty cmdlet is not available. Check module version (0.9.0+).'
        }

        $findingList = Join-Path $script:ScriptRoot 'checks\tier1-hardeningkitty.csv'
        if (-not (Test-Path $findingList)) {
            throw "Finding list not found: $findingList"
        }

        $hkReport = Join-Path $runDir 'hardeningkitty-raw.csv'
        $hkLog    = Join-Path $runDir 'hardeningkitty.log'

        Invoke-HardeningKitty -Mode Audit `
                              -Log -Report `
                              -ReportFile $hkReport `
                              -LogFile $hkLog `
                              -FileFindingList $findingList `
                              -SkipRestorePoint -SkipUserInformation | Out-Null

        if (Test-Path $hkReport) {
            $hkRaw = Import-Csv $hkReport
            foreach ($row in $hkRaw) {
                # HardeningKitty reuses the 'Severity' column in its output to
                # encode the result: "Passed" when a check passes, or the
                # input severity ("Low"/"Medium"/"High") when it fails. Anything
                # else (empty, "None", etc.) means the check couldn't execute.
                $hkResult = "$($row.Severity)".Trim()
                $status = switch ($hkResult) {
                    'Passed'                        { 'Passed'; break }
                    { $_ -in 'Low','Medium','High' }{ 'Failed'; break }
                    default                         { 'NotRun' }
                }

                # Preserve ORIGINAL severity from the input CSV (not HK's
                # result-flavored output). This fixes the bug where every
                # passing control reported Severity=Low regardless of intent.
                $inputDef = $script:HkInputLookup[$row.ID]
                $origSev = if ($inputDef -and $inputDef.Severity) {
                    $inputDef.Severity
                } else {
                    # Best-effort fallback: use the result severity if we
                    # have nothing better (only for Failed cases).
                    if ($hkResult -in 'Low','Medium','High') { $hkResult } else { 'Low' }
                }

                # Expected value from the input CSV. HK's output preserves
                # Result (actual found value) but not RecommendedValue.
                $expected = if ($inputDef) { $inputDef.RecommendedValue } else { '' }
                $found = "$($row.Result)".Trim()

                $details = if ($status -eq 'NotRun') {
                    "Check did not execute. HK reported severity '$hkResult'. Verify the check definition in checks/tier1-hardeningkitty.csv is valid for this host."
                } else {
                    "Expected '$expected', found '$found'."
                }

                $hkFindings += [pscustomobject]@{
                    ControlId    = $row.ID
                    Category     = $row.Category
                    Name         = $row.Name
                    Result       = $status
                    Severity     = $origSev
                    Details      = $details
                    Remediation  = Get-Remediation -ControlId $row.ID
                    Source       = 'HardeningKitty'
                }
            }
            Write-Log "Collected $($hkFindings.Count) HardeningKitty findings" -Level OK
        } else {
            Write-Log 'HardeningKitty produced no report' -Level WARN
        }
    } catch {
        Write-Log "HardeningKitty phase failed: $_" -Level ERROR
    }
}

# ---------------------------------------------------------------------------
# Normalize, apply exceptions, write findings.json
# ---------------------------------------------------------------------------

$allFindings = @($maesterFindings) + @($hkFindings)

foreach ($f in $allFindings) {
    if ($script:Exceptions.ContainsKey($f.ControlId)) {
        $exc = $script:Exceptions[$f.ControlId]
        $f | Add-Member -NotePropertyName 'Exception' -NotePropertyValue $exc -Force
        $f.Result = 'Excepted'
    }
}

$summary = [pscustomobject]@{
    Client           = $ClientName
    RunId            = $script:RunId
    Timestamp        = (Get-Date).ToString('o')
    BaselineVersion  = $script:BaselineVersion
    TotalControls    = $allFindings.Count
    # @(...) forces array semantics. Without it, Where-Object returning
    # a single match unwraps to a scalar PSCustomObject in PS5.1 strict-
    # ish contexts and (.Count) returns $null instead of 1. Symptom: the
    # exact counters that match exactly one finding render as blank in
    # the summary while zero/multi counters work fine.
    Passed           = @($allFindings | Where-Object Result -EQ 'Passed').Count
    Failed           = @($allFindings | Where-Object Result -EQ 'Failed').Count
    NotRun           = @($allFindings | Where-Object Result -EQ 'NotRun').Count
    Skipped          = @($allFindings | Where-Object Result -EQ 'Skipped').Count
    NotApplicable    = @($allFindings | Where-Object Result -EQ 'NotApplicable').Count
    NotMapped        = @($allFindings | Where-Object Result -EQ 'NotMapped').Count
    Excepted         = @($allFindings | Where-Object Result -EQ 'Excepted').Count
    CriticalFailures = @($allFindings | Where-Object { $_.Result -eq 'Failed' -and $_.Severity -eq 'Critical' }).Count
    HighFailures     = @($allFindings | Where-Object { $_.Result -eq 'Failed' -and $_.Severity -eq 'High' }).Count
}

$output = [pscustomobject]@{
    Summary  = $summary
    Findings = $allFindings
}

$findingsJson = Join-Path $runDir 'findings.json'
$output | ConvertTo-Json -Depth 10 | Set-Content -Path $findingsJson -Encoding UTF8
Write-Log "Wrote $findingsJson" -Level OK

# ---------------------------------------------------------------------------
# Generate the HTML report
# ---------------------------------------------------------------------------

function New-HtmlReport {
    param($Summary, $Findings, $OutPath)

    $templatePath = Join-Path $script:ScriptRoot 'templates\report.html.template'
    if (-not (Test-Path $templatePath)) {
        throw "Report template not found: $templatePath"
    }
    $template = Get-Content $templatePath -Raw

    # Score is computed against assessable controls only. NotApplicable
    # (license/feature absent), Skipped (Maester scope issue), NotMapped
    # (catalog drift), NotRun (HK execution issue), and Excepted (acknowledged
    # by client) all sit OUTSIDE the denominator. The score reflects
    # configuration of controls we could actually evaluate.
    $assessable = $Summary.Passed + $Summary.Failed
    $scorePct = if ($assessable -gt 0) {
        [math]::Round(($Summary.Passed / $assessable) * 100, 0)
    } else { 0 }

    $grade = switch ($scorePct) {
        { $_ -ge 90 } { 'A' }
        { $_ -ge 80 } { 'B' }
        { $_ -ge 70 } { 'C' }
        { $_ -ge 60 } { 'D' }
        default       { 'F' }
    }

    $failed = $Findings | Where-Object Result -EQ 'Failed' | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} default {4} }
    }}, Category, ControlId

    $findingsHtml = ($failed | ForEach-Object {
        $sevClass = $_.Severity.ToLower()
        @"
<div class="finding sev-$sevClass">
  <div class="finding-head">
    <span class="sev-badge sev-$sevClass">$($_.Severity)</span>
    <span class="ctrl-id">$($_.ControlId)</span>
    <span class="ctrl-cat">$($_.Category)</span>
  </div>
  <h3 class="finding-title">$([System.Web.HttpUtility]::HtmlEncode($_.Name))</h3>
  <p class="finding-details">$([System.Web.HttpUtility]::HtmlEncode($_.Details))</p>
  <details class="finding-rem">
    <summary>Remediation</summary>
    <p>$([System.Web.HttpUtility]::HtmlEncode($_.Remediation))</p>
  </details>
</div>
"@
    }) -join "`n"

    if (-not $findingsHtml) {
        $findingsHtml = '<div class="no-findings"><p>No failures. Every Tier 1 control passed or was excepted. Verify exceptions in the appendix are current.</p></div>'
    }

    $excepted = $Findings | Where-Object Result -EQ 'Excepted'
    $exceptedHtml = if ($excepted) {
        ($excepted | ForEach-Object {
            @"
<tr>
  <td class="mono">$($_.ControlId)</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($_.Name))</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($_.Exception.reason))</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($_.Exception.approvedBy))</td>
  <td>$($_.Exception.expiresOn)</td>
</tr>
"@
        }) -join "`n"
    } else {
        '<tr><td colspan="5" class="empty">No acknowledged exceptions.</td></tr>'
    }

    Add-Type -AssemblyName System.Web

    $replacements = @{
        '{{CLIENT_NAME}}'       = [System.Web.HttpUtility]::HtmlEncode($Summary.Client)
        '{{RUN_DATE}}'          = (Get-Date).ToString('MMMM d, yyyy')
        '{{BASELINE_VERSION}}'  = $Summary.BaselineVersion
        '{{RUN_ID}}'            = $Summary.RunId
        '{{SCORE_PCT}}'         = $scorePct
        '{{GRADE}}'             = $grade
        # Use assessable count for the headline figure. Non-assessable
        # controls (NotApplicable, NotMapped, Skipped, NotRun, Excepted)
        # are excluded from the user-visible "X of Y" so the report
        # doesn't read as "1 of 33 passed" when 31 controls were skipped
        # for license/mapping reasons. The full breakdown is in
        # findings.json and summary.txt.
        '{{TOTAL}}'             = $assessable
        '{{PASSED}}'            = $Summary.Passed
        '{{FAILED}}'            = $Summary.Failed
        '{{EXCEPTED}}'          = $Summary.Excepted
        '{{NOT_RUN}}'           = $Summary.NotRun
        '{{CRITICAL_FAILURES}}' = $Summary.CriticalFailures
        '{{HIGH_FAILURES}}'     = $Summary.HighFailures
        '{{FINDINGS_HTML}}'     = $findingsHtml
        '{{EXCEPTIONS_HTML}}'   = $exceptedHtml
    }
    foreach ($k in $replacements.Keys) {
        $template = $template.Replace($k, [string]$replacements[$k])
    }
    Set-Content -Path $OutPath -Value $template -Encoding UTF8
}

$reportPath = Join-Path $runDir 'report.html'
try {
    New-HtmlReport -Summary $summary -Findings $allFindings -OutPath $reportPath
    Write-Log "Generated $reportPath" -Level OK
} catch {
    Write-Log "Report generation failed: $_" -Level ERROR
}

# ---------------------------------------------------------------------------
# Executive summary (plain text)
# ---------------------------------------------------------------------------

$summaryPath = Join-Path $runDir 'summary.txt'
@"
SMB Hardening Essentials — Assessment Summary
==============================================
Client:     $($summary.Client)
Date:       $((Get-Date).ToString('yyyy-MM-dd HH:mm'))
Baseline:   v$($summary.BaselineVersion)
Run ID:     $($summary.RunId)

Score:               $($summary.Passed) of $($summary.Passed + $summary.Failed) assessable controls passed
Critical failures:   $($summary.CriticalFailures)
High failures:       $($summary.HighFailures)
Acknowledged excpt:  $($summary.Excepted)
Not applicable:      $($summary.NotApplicable)
Skipped (scope):     $($summary.Skipped)
Not mapped:          $($summary.NotMapped)
Not run (endpoint):  $($summary.NotRun)

Top failing controls (by severity):
"@ | Set-Content -Path $summaryPath -Encoding UTF8

$allFindings | Where-Object Result -EQ 'Failed' |
    Sort-Object @{Expression={ switch ($_.Severity) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} } }} |
    Select-Object -First 10 |
    ForEach-Object { "  [{0,-8}] {1}  {2}" -f $_.Severity, $_.ControlId, $_.Name } |
    Add-Content -Path $summaryPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

Write-Log 'Assessment complete.' -Level OK
Write-Log "Report:  $reportPath"
Write-Log "Summary: $summaryPath"

if (-not $NonInteractive) {
    try { Invoke-Item $runDir } catch {}
}

# Return the summary object so callers can script against it
$summary
