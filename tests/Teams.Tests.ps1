<#
.SYNOPSIS
    Tier 1 Microsoft Teams tests.

.DESCRIPTION
    Covers the SMB-TEAMS-* control family from BASELINE.md.

    Teams configuration is split across Graph (policy objects) and the
    MicrosoftTeams PowerShell module (tenant federation). Where possible
    we prefer Graph for consistency with the rest of the test suite.
#>

BeforeDiscovery {
    # Tenant federation configuration controls external access (B2B chat federation).
    # Exposed via Graph as /teamwork/teamsAppSettings and /policies/externalIdentitiesPolicy,
    # but the authoritative source for federated domains is the CsTenantFederationConfiguration
    # from the MicrosoftTeams module. We attempt Graph first and fall back.
    $script:TeamsFederation = Get-MtGraphRequest -RelativeUri 'admin/teams/settings' `
                                                 -ApiVersion beta -ErrorAction SilentlyContinue

    # Meeting policy (global, which governs anonymous join)
    $script:MeetingPolicy = Get-MtGraphRequest `
        -RelativeUri "teamwork/teamsPolicyAssignments" `
        -ApiVersion beta -ErrorAction SilentlyContinue

    # Guest access settings via Authorization policy
    $script:AuthzPolicy = Get-MtAuthorizationPolicy -ErrorAction SilentlyContinue
}

Describe 'SMB Tier 1 — Microsoft Teams' -Tag 'Teams','Tier1' {

    Context 'External access (federation)' {

        It 'SMB-TEAMS-001: External access is scoped to an allowlist or disabled' -Tag 'SMB-TEAMS-001','Medium' {
            # Federation mode can be:
            #   - Blocked (disabled for all external domains) → pass
            #   - AllowSpecificDomains (allowlist) → pass
            #   - BlockSpecificDomains (blocklist, open federation) → fail
            #   - AllowAllExternalDomains → fail
            #
            # The safest approach for SMB is allowlist or disabled. Open federation plus
            # chat with external users = phishing vector.

            if (-not $script:TeamsFederation) {
                Set-ItResult -Skipped -Because 'Teams federation settings not retrievable via Graph. Verify with Get-CsTenantFederationConfiguration from the MicrosoftTeams module.'
                return
            }

            $mode = $script:TeamsFederation.externalAccessMode
            $mode | Should -BeIn @('disabled','allowedDomains','blocked') -Because @"
Current mode: '$mode'. SMB Tier 1 requires either:
  - External access disabled, OR
  - External access limited to an explicit allowlist of partner domains.
Open federation with blocklist is Tier 2 (acceptable but requires ongoing monitoring).
Configure via: Teams admin center → Users → External access.
"@
        }
    }

    Context 'Guest access' {

        It 'SMB-TEAMS-002: Guest access is configured deliberately (not left at default)' -Tag 'SMB-TEAMS-002','Low' {
            # "Deliberately configured" is hard to detect automatically. Our heuristic:
            # either guest access is explicitly disabled at the Teams level, OR
            # at least one Teams-scoped guest-access policy exists (indicating someone touched it).

            if (-not $script:TeamsFederation) {
                Set-ItResult -Skipped -Because 'Teams admin settings not retrievable via Graph.'
                return
            }

            $guestAccessExplicit = ($script:TeamsFederation.PSObject.Properties.Name -contains 'allowGuestUser') -and
                                   ($null -ne $script:TeamsFederation.allowGuestUser)

            $guestAccessExplicit | Should -BeTrue -Because @"
Guest access in Teams has not been explicitly configured — it is still at tenant default.
Guest access is not inherently bad, but it should be a decision, not an oversight.
Either disable it (Teams admin center → Users → Guest access → off) or configure
restricted guest settings (calling, meetings, messaging). Document the decision in the runbook.
"@
        }
    }

    Context 'Meetings' {

        It 'SMB-TEAMS-003: Anonymous users either cannot join meetings or must wait in lobby' -Tag 'SMB-TEAMS-003','Medium' {
            # The Global meeting policy controls the default. Anonymous join being on with
            # AutoAdmit = EveryoneInCompanyIncludingGuests (or similar) is the unsafe combination.
            # Safe combinations:
            #   - AllowAnonymousUsersToJoinMeeting = $false  → pass
            #   - AllowAnonymousUsersToJoinMeeting = $true AND AutoAdmittedUsers = 'EveryoneInCompany' or stricter → pass

            $meetingPolicy = Get-MtGraphRequest -RelativeUri "admin/teams/meetingPolicies('Global')" `
                                                -ApiVersion beta -ErrorAction SilentlyContinue

            if (-not $meetingPolicy) {
                Set-ItResult -Skipped -Because 'Global meeting policy not retrievable. Verify with Get-CsTeamsMeetingPolicy -Identity Global from the MicrosoftTeams module.'
                return
            }

            $anonJoinOff = ($meetingPolicy.allowAnonymousUsersToJoinMeeting -eq $false)
            $safeAdmit = $meetingPolicy.autoAdmittedUsers -in @(
                'EveryoneInCompany',
                'EveryoneInCompanyExcludingGuests',
                'EveryoneInSameAndFederatedCompany',
                'OrganizerOnly',
                'InvitedUsers'
            )

            ($anonJoinOff -or $safeAdmit) | Should -BeTrue -Because @"
Current state: AllowAnonymousUsersToJoinMeeting=$($meetingPolicy.allowAnonymousUsersToJoinMeeting),
AutoAdmittedUsers=$($meetingPolicy.autoAdmittedUsers).
Anonymous joiners landing directly in meetings enables eavesdropping. Either:
  - Disable anonymous join (Teams admin center → Meetings → Meeting policies → Global → Anonymous users can join), OR
  - Require lobby for anonymous (set auto-admit to "Everyone in your organization" or stricter).
"@
        }
    }
}
