<#
.SYNOPSIS
    Tier 1 Exchange Online tests.

.DESCRIPTION
    Covers the SMB-EXO-* control family from BASELINE.md.
#>

BeforeDiscovery {
    $script:OrgConfig       = Get-MtExoOrganizationConfig -ErrorAction SilentlyContinue
    $script:OutboundSpam    = Get-MtExoOutboundSpamPolicy -ErrorAction SilentlyContinue
    $script:PresetPolicies  = Get-MtExoPresetSecurityPolicy -ErrorAction SilentlyContinue
    $script:ExternalTagging = Get-MtExoExternalInOutlook -ErrorAction SilentlyContinue
    $script:AcceptedDomains = Get-MtExoAcceptedDomain -ErrorAction SilentlyContinue
    $script:DkimConfig      = Get-MtExoDkimSigningConfig -ErrorAction SilentlyContinue
}

Describe 'SMB Tier 1 — Exchange Online' -Tag 'ExchangeOnline','Tier1' {

    Context 'Protection policies' {

        It 'SMB-EXO-001: Preset Security Policies are applied at Standard level' -Tag 'SMB-EXO-001','High' {
            $standard = $script:PresetPolicies | Where-Object Name -EQ 'Standard Preset Security Policy'
            $standard.State | Should -Be 'Enabled' -Because @"
Standard Preset Security Policies enable Microsoft-recommended anti-phishing, Safe Links, Safe Attachments,
and anti-spam configurations in a single step. This replaces 20+ individual settings.
Microsoft 365 Defender → Email & collaboration → Policies & rules → Threat policies → Preset Security Policies.
"@
        }

        It 'SMB-EXO-002: External sender tagging is enabled' -Tag 'SMB-EXO-002','Medium' {
            $script:ExternalTagging.Enabled | Should -BeTrue -Because @"
External sender tagging shows users when a message came from outside the organization, reducing
BEC and spoofing success rates. Enable via: Set-ExternalInOutlook -Enabled `$true
"@
        }

        It 'SMB-EXO-003: Automatic forwarding to external domains is blocked' -Tag 'SMB-EXO-003','High' {
            $default = $script:OutboundSpam | Where-Object IsDefault -EQ $true
            $default.AutoForwardingMode | Should -Be 'Off' -Because @"
Current value: $($default.AutoForwardingMode). Automatic external forwarding is a classic post-compromise
exfiltration path. Set the default outbound spam filter's AutoForwardingMode to 'Off'.
Exchange Online → Protection → outbound spam policy (default) → Forwarding rules.
"@
        }
    }

    Context 'Audit and auth' {

        It 'SMB-EXO-004: Mailbox auditing is enabled by default' -Tag 'SMB-EXO-004','High' {
            $script:OrgConfig.AuditDisabled | Should -BeFalse -Because @"
Mailbox audit logging is disabled tenant-wide. Enable with:
Set-OrganizationConfig -AuditDisabled `$false
Required for incident response — without this, compromise cannot be scoped.
"@
        }

        It 'SMB-EXO-008: Modern authentication is required' -Tag 'SMB-EXO-008','Critical' {
            $script:OrgConfig.OAuth2ClientProfileEnabled | Should -BeTrue -Because @"
Modern authentication (OAuth 2.0) is not enabled at the Exchange Online org level.
Set-OrganizationConfig -OAuth2ClientProfileEnabled `$true
Without this, some clients can still use legacy auth even if CA blocks it.
"@
        }
    }

    Context 'Email authentication (SPF/DKIM/DMARC)' {

        It 'SMB-EXO-005: All accepted domains have an SPF record ending in -all' -Tag 'SMB-EXO-005','High' {
            $results = foreach ($domain in $script:AcceptedDomains) {
                $spf = Resolve-DnsName -Type TXT -Name $domain.DomainName -ErrorAction SilentlyContinue |
                       Where-Object Strings -Match '^v=spf1'
                [pscustomobject]@{
                    Domain = $domain.DomainName
                    Spf    = $spf.Strings -join ''
                    OK     = $spf.Strings -match ' -all( |$)'
                }
            }
            $failing = $results | Where-Object { -not $_.OK }
            @($failing).Count | Should -Be 0 -Because @"
Domains without a hard-fail SPF record: $($failing.Domain -join ', ')
Publish a TXT record: v=spf1 include:spf.protection.outlook.com -all
Soft-fail (~all) is insufficient; unauthorized senders will still be accepted by some receivers.
"@
        }

        It 'SMB-EXO-006: DKIM signing is enabled on all accepted domains' -Tag 'SMB-EXO-006','Medium' {
            $failing = foreach ($domain in $script:AcceptedDomains | Where-Object DomainType -EQ 'Authoritative') {
                $dkim = $script:DkimConfig | Where-Object Domain -EQ $domain.DomainName
                if (-not $dkim.Enabled) { $domain.DomainName }
            }
            @($failing).Count | Should -Be 0 -Because @"
DKIM not enabled on: $($failing -join ', ')
Publish both CNAME records per domain, then: Set-DkimSigningConfig -Identity <domain> -Enabled `$true
"@
        }

        It 'SMB-EXO-007: DMARC policy is at least p=quarantine with reporting' -Tag 'SMB-EXO-007','High' {
            $failing = foreach ($domain in $script:AcceptedDomains | Where-Object DomainType -EQ 'Authoritative') {
                $dmarc = Resolve-DnsName -Type TXT -Name "_dmarc.$($domain.DomainName)" -ErrorAction SilentlyContinue |
                         Where-Object Strings -Match '^v=DMARC1'
                $record = $dmarc.Strings -join ''
                $hasPolicy = $record -match 'p=(quarantine|reject)'
                $hasRua = $record -match 'rua=mailto:'
                if (-not ($hasPolicy -and $hasRua)) { $domain.DomainName }
            }
            @($failing).Count | Should -Be 0 -Because @"
Domains missing or weak DMARC: $($failing -join ', ')
Publish TXT at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>; fo=1
Start with p=quarantine + reporting; graduate to p=reject once reports are clean.
"@
        }
    }
}
