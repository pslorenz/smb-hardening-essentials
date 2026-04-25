# Remediation Map
#
# Canonical remediation guidance keyed by control ID. Loaded by
# Invoke-SmbHardeningAssessment.ps1 and merged into every finding.
#
# Keep entries short, actionable, and include either the admin portal path
# or the exact cmdlet. Mention significant gotchas (what it breaks, what
# needs to be tested first). Do NOT duplicate the full rationale from
# docs/BASELINE.md — that lives there; this is the "what to do" column.
#
# When adding a new control to the baseline, add its remediation here.
# CI validates every control ID in the baseline has a matching entry.

@{

    # -------------------------------------------------------------------
    # Identity and Access Management (Maester)
    # -------------------------------------------------------------------

    'SMB-IAM-001' = 'Enable Security Defaults (Entra ID > Properties > Manage Security Defaults) OR create a Conditional Access policy targeting All users requiring MFA. Security Defaults is free and correct for most small tenants; CA policy is required when any targeted exclusion is needed.'

    'SMB-IAM-002' = 'Create a Conditional Access policy targeting directory roles (Global Admin, Privileged Role Admin, Security Admin, Exchange Admin, SharePoint Admin, User Admin) with MFA required. Exclude only the documented break-glass account.'

    'SMB-IAM-003' = 'Block legacy authentication via Security Defaults OR a Conditional Access policy targeting client app types "Exchange ActiveSync clients" and "Other clients" with Block access. Before enabling: inventory any service accounts or scanners that authenticate against Exchange and migrate them to modern auth first.'

    'SMB-IAM-004' = 'Reduce Global Administrator count to 2-4. Reassign role-specific duties to lower-privileged roles (Exchange Administrator, User Administrator, Security Administrator, Authentication Administrator). Retain one designated break-glass account (documented in SMB-IAM-005).'

    'SMB-IAM-005' = 'Create a cloud-only Global Administrator account (break-glass@<tenant>.onmicrosoft.com), assign a long passphrase, store printed credentials in a physical safe, exclude the account from all Conditional Access policies, and configure sign-in alerts via Entra ID > Monitoring > Alerts. Docs: https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'

    'SMB-IAM-006' = 'Create cloud-only accounts for every admin role holder. Remove directory role assignments from any on-prem-synced account. On-prem AD compromise flows into cloud within minutes when admin roles are held by synced accounts.'

    'SMB-IAM-007' = 'Adopt a naming convention for admin accounts (adm-<name>@tenant, or similar) that makes them visually distinct from daily-driver mailboxes. Assign minimum licensing (often admin accounts need no mailbox at all). Daily work, including email, happens on the standard user account.'

    'SMB-IAM-008' = 'Restrict user consent to third-party apps: Entra ID > Enterprise applications > Consent and permissions > User consent settings > "Allow user consent for apps from verified publishers, for selected permissions." Configure an admin consent request workflow so users can request apps that fall outside the allowed scope.'

    'SMB-IAM-009' = 'Restrict guest invitations: Entra ID > External Identities > External collaboration settings > Guest invite settings > "Only users assigned to specific admin roles can invite guest users." Delegate to a defined role (e.g., Guest Inviter) for users who legitimately need the capability.'

    'SMB-IAM-010' = 'Requires Entra ID P2. Entra ID > Protection > Conditional Access > New policy. Conditions > Sign-in risk > Medium and above. Grant > Require MFA. Start in Report-only mode, review sign-in logs for 30-60 days, tune exclusions, then enable Enforce. User risk policies follow the same pattern with password change as the control.'

    'SMB-IAM-011' = 'Entra ID > Security > Authentication methods > Policies > Microsoft Authenticator > Configure > Require number matching for push notifications: Enabled, Target: All users. Default for new tenants since 2023; older tenants may still need manual configuration.'

    'SMB-IAM-012' = 'Entra ID > Password reset > Properties > Self service password reset enabled > All. Registration > Require users to register when signing in > Yes. Authentication methods > set Number of methods required to reset to 2; remove Security questions from allowed methods.'

    # -------------------------------------------------------------------
    # Exchange Online (Maester)
    # -------------------------------------------------------------------

    'SMB-EXO-001' = 'Microsoft Defender portal > Email & collaboration > Policies & rules > Threat policies > Preset Security Policies > Standard protection > Edit > target All recipients. Standard is the Tier 1 target; Strict is Tier 2 and requires user education on the stricter quarantine experience.'

    'SMB-EXO-002' = 'PowerShell: Set-ExternalInOutlook -Enabled $true. Rolls out to Outlook clients within ~48 hours. Users see a clear "External" tag on messages from outside the org. No licensing required; available on all tenants.'

    'SMB-EXO-003' = 'Exchange admin center > Mail flow > Anti-spam > Outbound policy (default) > Edit > Forwarding rules > Automatic forwarding rules: Off. Before enabling: audit existing auto-forward rules (Get-InboxRule -Mailbox * or the Compliance portal) and migrate legitimate forwarding to mail-enabled distribution groups or Power Automate flows.'

    'SMB-EXO-004' = 'PowerShell: Set-OrganizationConfig -AuditDisabled $false. Verify with Get-OrganizationConfig | Select-Object AuditDisabled. Required for incident response; without mailbox auditing, compromise of a specific mailbox cannot be scoped.'

    'SMB-EXO-005' = 'Publish a TXT record at the apex of each accepted domain: "v=spf1 include:spf.protection.outlook.com -all" (replace "-all" with your policy; -all is the hard-fail target for Tier 1). Validate with an SPF checker before committing to catch include-chain issues.'

    'SMB-EXO-006' = 'Microsoft Defender portal > Email & collaboration > Policies & rules > Threat policies > Email authentication settings > DKIM. For each accepted domain, publish both CNAME records at selector1._domainkey and selector2._domainkey, then click Enable. Verify signing with Get-DkimSigningConfig.'

    'SMB-EXO-007' = 'Publish a TXT record at _dmarc.<domain>: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@<domain>; fo=1". Monitor aggregate reports weekly (or use a DMARC service like dmarcian, Valimail, URIports) for 30-60 days to verify legitimate senders are aligned, then consider graduating to p=reject.'

    'SMB-EXO-008' = 'PowerShell: Set-OrganizationConfig -OAuth2ClientProfileEnabled $true. Belt-and-suspenders to SMB-IAM-003; some Exchange protocols can still use legacy auth if this tenant-level toggle is off even when CA blocks legacy at the front door.'

    # -------------------------------------------------------------------
    # SharePoint / OneDrive (Maester)
    # -------------------------------------------------------------------

    'SMB-SPO-001' = 'SharePoint admin center > Policies > Sharing > External sharing: set to "New and existing guests" (or stricter). Existing "Anyone" links continue to function until they expire; no new Anyone links can be created. OneDrive slider should match or be stricter than SharePoint.'

    'SMB-SPO-002' = 'SharePoint admin center > Policies > Sharing > File and folder links > Default link type: "Specific people" (Tier 1) or "People in your organization" (also acceptable). The default shapes user behavior — most users accept the default and rarely change it.'

    'SMB-SPO-003' = 'SharePoint admin center > Policies > Sharing > Choose expiration and permissions options for Anyone links > These links must expire within this many days: 30. Default permissions: View (not Edit) for files, View (not Edit) for folders.'

    'SMB-SPO-004' = 'PowerShell: Set-SPOTenant -RequireAcceptingAccountMatchInvitedAccount $true. Or: SharePoint admin center > Policies > Sharing > External sharing > More external sharing settings > Guests must sign in using the same account to which sharing invitations are sent.'

    'SMB-SPO-005' = 'Requires Intune. Create a Conditional Access policy targeting Office 365 SharePoint Online with Grant > Require device to be marked as compliant. Without Intune, compensate via Session controls requiring MFA for each sign-in on unmanaged devices.'

    # -------------------------------------------------------------------
    # Teams (Maester)
    # -------------------------------------------------------------------

    'SMB-TEAMS-001' = 'Teams admin center > Users > External access. Set "Teams and Skype for Business users in external organizations" to either Off, or "Allow only specific external domains" with an explicit allowlist of partner domains.'

    'SMB-TEAMS-002' = 'Teams admin center > Users > Guest access. Decide explicitly: either turn guest access Off (strictest), or leave On and configure the sub-settings (calling, meetings, messaging, identity) per organizational need. Document the decision in the engagement runbook.'

    'SMB-TEAMS-003' = 'Teams admin center > Meetings > Meeting policies > Global (Org-wide default). Set "Anonymous users can join a meeting" to Off, OR keep On and set "Who can bypass the lobby" to "People in my organization" or stricter.'

    # -------------------------------------------------------------------
    # Audit (Maester)
    # -------------------------------------------------------------------

    'SMB-AUD-001' = 'PowerShell: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. Or: Microsoft Purview compliance portal > Audit > Start recording user and admin activity. Ingestion takes up to 24 hours to fully activate. Without this, no meaningful incident response is possible.'

    'SMB-AUD-002' = 'With Purview Audit Premium: Microsoft Purview compliance portal > Audit > Audit retention policies > create a policy at tenant maximum (1 year or 10 years with add-on). Without Premium, default retention (90 days Basic, 180 days E3/E5) applies — still log-in and verify it reflects expectations.'

    # -------------------------------------------------------------------
    # Device Compliance (Maester)
    # -------------------------------------------------------------------

    'SMB-DEV-001' = 'Intune admin center > Devices > Compliance policies > Create policy (Windows, iOS, macOS, Android as needed). Require: BitLocker on, Secure Boot on, Antivirus on, minimum OS build. Assign to All users (or a group covering >95% of the workforce). Unassigned policies are decorative.'

    'SMB-DEV-002' = 'Entra ID > Protection > Conditional Access > New policy. Users: All users (exclude break-glass). Cloud apps: Office 365 (or All cloud apps). Grant: Require device to be marked as compliant and/or Require hybrid Entra joined device. Start in Report-only for 2 weeks, tune, then Enable.'

    'SMB-DEV-003' = 'In each compliance policy: Actions for noncompliance > Block > set Grace period to 24-168 hours (1-7 days). Immediate block causes weekend outages; excessive grace means noncompliance persists. 48-72 hours is a common Tier 1 setting.'

    # -------------------------------------------------------------------
    # Defender (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-DEF-001' = 'Intune: Endpoint security > Antivirus > create a Windows profile with Real-Time Protection = Yes. PowerShell: Set-MpPreference -DisableRealtimeMonitoring $false. If this control is off, a legacy AV installer may have disabled Defender; remove the legacy agent before re-enabling.'

    'SMB-DEF-002' = 'Intune: Endpoint security > Antivirus > Cloud-delivered protection level: High. PowerShell: Set-MpPreference -MAPSReporting Advanced; Set-MpPreference -CloudBlockLevel High. High is the Tier 1 target; "High+" is Tier 2 (more false positives).'

    'SMB-DEF-003' = 'Intune: Endpoint security > Antivirus > Submit samples consent: Send safe samples automatically. PowerShell: Set-MpPreference -SubmitSamplesConsent SendSafeSamples. Feeds the cloud protection this client benefits from; low privacy concern.'

    'SMB-DEF-004' = 'Microsoft Defender portal > Settings > Endpoints > Advanced features > Tamper protection: On. Or enroll devices via Intune and enable tamper protection in the Antivirus profile. Cannot be set purely via local registry; requires cloud management.'

    'SMB-DEF-005' = 'Intune: Endpoint security > Antivirus > Potentially unwanted app protection: Block. PowerShell: Set-MpPreference -PUAProtection Enabled. Catches bundled adware and potentially-unwanted installers; very low false-positive rate.'

    'SMB-DEF-006' = 'Intune: Endpoint security > Attack surface reduction > Web protection > Enable network protection: Enabled (block mode). PowerShell: Set-MpPreference -EnableNetworkProtection Enabled. Blocks known-bad C2 domains at the OS level regardless of browser.'

    'SMB-DEF-007' = 'Intune: Configuration profiles > Edge baseline > SmartScreen settings > SmartScreenEnabled: Enabled; SmartScreenPuaEnabled: Enabled. Or GPO: Computer Configuration > Administrative Templates > Microsoft Edge > SmartScreen settings.'

    'SMB-DEF-008' = 'Intune: Endpoint security > Attack surface reduction > App and browser isolation > SmartScreen for Microsoft Edge: Yes; Block malicious site access: Yes; Block unverified file download: Yes. Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen = 1.'

    # -------------------------------------------------------------------
    # Attack Surface Reduction (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-ASR-001' = 'Intune: Endpoint security > Attack surface reduction > Attack surface reduction rules > Block credential stealing from the Windows local security authority subsystem: Block. PowerShell: Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled.'

    'SMB-ASR-002' = 'Intune ASR rule: "Block Office applications from creating executable content" = Block. GUID: 3b576869-a4ec-4529-8536-b80a7769e899. Enable via Set-MpPreference or Add-MpPreference.'

    'SMB-ASR-003' = 'Intune ASR rule: "Block Office applications from injecting code into other processes" = Block. GUID: 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84.'

    'SMB-ASR-004' = 'Intune ASR rule: "Block Win32 API calls from Office macros" = Block. GUID: 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b. Part of the Office macro-hardening set; minimal business impact.'

    'SMB-ASR-005' = 'Intune ASR rule: "Block executable content from email client and webmail" = Block. GUID: be9ba2d9-53ea-4cdc-84e5-9b1eeee46550. Closes the phishing > attachment > payload chain.'

    'SMB-ASR-006' = 'Intune ASR rule: "Block JavaScript or VBScript from launching downloaded executable content" = Block. GUID: d3e037e1-3eb8-44c8-a917-57927947596d. Drive-by download defense.'

    'SMB-ASR-007' = 'Intune ASR rule: "Block Adobe Reader from creating child processes" = Block. GUID: 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c. Adobe Reader should never spawn processes.'

    'SMB-ASR-008' = 'Intune ASR rule: "Block persistence through WMI event subscription" = Block. GUID: e6db77e5-3df2-4cf1-b95a-636979351e5b. Fileless persistence technique used by multiple threat actors.'

    'SMB-ASR-009' = 'Intune ASR rule: "Use advanced protection against ransomware" = Block. GUID: c1db55ab-c21a-4637-bb3f-a12568109d35. Behavioral detection; occasional false positives on backup utilities — test before broad rollout.'

    'SMB-ASR-010' = 'Intune ASR rule: "Block untrusted and unsigned processes that run from USB" = Block. GUID: b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4. Covers the dropped-USB attack vector.'

    # -------------------------------------------------------------------
    # Credential Protection (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-CRED-001' = 'Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1. Deploy via Intune Administrative Templates or GPO. Some legacy security agents (older AV, older DLP) may conflict — validate with your endpoint vendor first. Requires reboot.'

    'SMB-CRED-002' = 'Registry: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0. Default in Windows 10+ but legacy images may have it on. Deploy via GPO preference or Intune config.'

    'SMB-CRED-003' = 'Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1. Default in modern Windows. Deploy via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change: Enabled.'

    'SMB-CRED-004' = 'Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5. GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level: "Send NTLMv2 response only. Refuse LM & NTLM." Requires verification that no legacy auth dependencies exist (older NAS, legacy scanners).'

    'SMB-CRED-005' = 'Deploy Windows LAPS (built into Windows 11 22H2+ and backport-available for earlier). Intune: Endpoint security > Account protection > Local admin password solution policy. Configure: directory = Entra (cloud-only) or AD (hybrid), password complexity = Large letters + small letters + numbers + special, length = 20+, age = 30 days. The check verifies the policy registry key BackupDirectory is set; this confirms a LAPS policy is deployed but does not verify successful password rotation — that requires Get-LapsAADPassword or the Intune reporting view.'

    # Note: SMB-CRED-006 (Built-in Administrator disabled) and SMB-CRED-007
    # (Guest account disabled) are deferred from the v0.1.3 baseline. The
    # local-account-status check requires a HardeningKitty method that we
    # could not verify against the upstream finding lists. Plan to add back
    # in v0.1.4 once the correct method is identified, or as a Maester-style
    # PowerShell test using Get-LocalUser.

    # -------------------------------------------------------------------
    # BitLocker (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-BL-001' = 'Enable BitLocker on the OS drive: manage-bde -on C: -UsedSpaceOnly (or via Intune Disk encryption policy). Ensure TPM 2.0 is present and Secure Boot is enabled. Recovery key must escrow to Entra (SMB-BL-003) before enabling.'

    'SMB-BL-002' = 'Configure BitLocker to use XTS-AES 256: Intune Disk encryption > Encryption method for OS drives: XTS-AES 256-bit. GPO: Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Choose drive encryption method and cipher strength > XTS-AES 256-bit. Applies to newly encrypted drives; existing volumes stay on their original cipher.'

    # -------------------------------------------------------------------
    # Network protocols (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-NET-001' = 'Disable SMBv1 client: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. Or via Intune device configuration. Restart required.'

    'SMB-NET-002' = 'Disable SMBv1 server: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force. Broken in the EternalBlue-class vulnerabilities; no modern reason to leave it on. Before enforcing: verify no legacy scanners, copiers, or NAS devices require it.'

    'SMB-NET-003' = 'Require SMB signing on the server side: Set-SmbServerConfiguration -RequireSecuritySignature $true. Prevents SMB relay attacks. Minimal compatibility impact on modern clients.'

    'SMB-NET-004' = 'Disable LLMNR: GPO > Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution: Enabled. Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0. Closes the Responder-class poisoning attack.'

    'SMB-NET-005' = 'Disable NetBIOS over TCP/IP via DHCP option 001 or per-adapter in network settings. Alternative: registry on each NIC under HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_* > NetbiosOptions = 2. CAUTION: some legacy printers, scanners, and MFP discovery protocols still require NetBIOS; test on a pilot group first.'

    'SMB-NET-006' = 'Disable TLS 1.0 client: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client > Enabled = 0, DisabledByDefault = 1. Also disable server-side if this is a server. Before enforcing: verify no legacy LOB apps require TLS 1.0.'

    'SMB-NET-007' = 'Disable TLS 1.1 client and server: same registry path as SMB-NET-006 under "TLS 1.1". Most modern software negotiates to 1.2+ automatically; legacy app compatibility is the gating concern.'

    # -------------------------------------------------------------------
    # Office (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-OFF-001' = 'Block macros from the internet in Word, Excel, PowerPoint. Intune: Microsoft Office > Security > Block macros in files from the Internet = Enabled (per app). Or GPO: User Configuration > Administrative Templates > Microsoft Word > Word Options > Security > Trust Center > Block macros from running in Office files from the Internet = Enabled. Single highest-ROI Office setting.'

    'SMB-OFF-001a' = 'Block macros from the internet in Excel. Same setting as SMB-OFF-001 but checked per-app because each Office application has its own registry key under HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\<app>\security. Apply via Intune Office Cloud Policy or GPO.'

    'SMB-OFF-001b' = 'Block macros from the internet in PowerPoint. Same setting as SMB-OFF-001 but checked per-app. Apply via Intune Office Cloud Policy or GPO.'

    'SMB-OFF-002' = 'Enable Protected View for files from the internet. Word/Excel/PowerPoint > Options > Trust Center > Trust Center Settings > Protected View > Enable Protected View for files originating from the Internet = On. Deploy via GPO or Intune Admin Templates.'

    'SMB-OFF-003' = 'Enable Protected View for Outlook attachments. Same Trust Center path as SMB-OFF-002, setting: Enable Protected View for Outlook attachments = On.'

    'SMB-OFF-004' = 'Enable Protected View for files from unsafe locations (downloads, temp directories). Trust Center > Protected View > Enable Protected View for files located in potentially unsafe locations = On.'

    'SMB-OFF-005' = 'Disable Dynamic Data Exchange in all Office apps. For Word: Options > Trust Center > Trust Center Settings > External Content > Security settings for Dynamic Data Exchange > Disable all Dynamic Data Exchange server lookup / launch. Deploy via Administrative Templates. Legacy Office feature, exploited in phishing campaigns.'

    # -------------------------------------------------------------------
    # Firewall (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-FW-001' = 'Enable Windows Defender Firewall for all three profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True. Verify with Get-NetFirewallProfile.'

    'SMB-FW-001a' = 'Enable Private profile firewall: Set-NetFirewallProfile -Profile Private -Enabled True. Off on imaged machines occasionally; rare but checked separately so the per-profile state is visible in the report.'

    'SMB-FW-001b' = 'Enable Public profile firewall: Set-NetFirewallProfile -Profile Public -Enabled True. Most critical of the three profiles — covers untrusted networks where attack surface is highest.'

    'SMB-FW-002' = 'Block inbound by default on Public profile: Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block. Also reasonable to apply to Private and Domain, but Public is the Tier 1 minimum.'

    # -------------------------------------------------------------------
    # UAC (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-UAC-001' = 'Enable UAC: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA = 1. GPO: User Account Control: Run all administrators in Admin Approval Mode = Enabled. Default in modern Windows; legacy images or misconfigured systems may have it off.'

    'SMB-UAC-002' = 'Enable Admin Approval Mode: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken = 1. Forces the UAC prompt even for members of the Administrators group.'

    'SMB-UAC-003' = 'Require secure desktop for elevation prompts: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop = 1. Prevents UI spoofing of the elevation prompt by malicious processes.'

    # -------------------------------------------------------------------
    # Updates (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-WU-001' = 'Configure automatic updates via Intune Windows Update for Business or GPO. At minimum: Automatic Updates enabled, download and install automatically, deferral per policy (quality 0-7 days, feature 60-180 days). Deferral beyond these ranges leaves the system exposed to known exploited CVEs.'

    # -------------------------------------------------------------------
    # Logging (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-LOG-001' = 'Enable PowerShell script block logging: HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1. GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled. Near-zero cost; invaluable in incident response.'

    'SMB-LOG-002' = 'Enable PowerShell module logging: HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging = 1, then add module names under ModuleNames subkey (* for all). GPO: same path as SMB-LOG-001 > Turn on Module Logging = Enabled.'

    'SMB-LOG-003' = 'Enable command-line process auditing: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1. Also enable Audit Process Creation subcategory via Auditpol or GPO: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking > Audit Process Creation = Success.'

    # -------------------------------------------------------------------
    # Removable Media (HardeningKitty)
    # -------------------------------------------------------------------

    'SMB-RM-001' = 'Disable AutoRun for all drive types: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 255. GPO: Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off Autoplay = Enabled, on all drives.'
}
