# Tier 1 Baseline Control Reference

This document is the canonical description of every control in the Tier 1 baseline, plus the explicit exclusions (controls that look like they should be here but aren't, with rationale).

Every control has a stable ID (`SMB-<CATEGORY>-<NNN>`) used by the wrapper script and report. IDs never change once published; deprecated controls are marked but kept.

**Design principles for Tier 1 inclusion:**

1. Closes a real attack path seen in the field, not a theoretical one.
2. Deploys without user-visible friction in an org without help-desk capacity.
3. Meaningful to a non-technical business owner when shown as a finding.
4. Does not require ongoing tuning, exception management, or specialist attention.

A control that fails any of these is a Tier 2 control.

---

## Part 1: Microsoft 365 / Entra ID (Maester)

### Identity and Access Management

| ID | Control | Why it matters | Implementation note |
|---|---|---|---|
| SMB-IAM-001 | MFA required for all users | The single highest-ROI control in M365. Blocks ~99% of credential-stuffing and password-spray attacks. | Security Defaults satisfies this for tenants without Entra P1. P1+ tenants should use a Conditional Access policy. |
| SMB-IAM-002 | MFA required for all admin roles | Admins are the highest-value targets and often excluded from user-level policies. | Separate CA policy scoped to admin roles, no exclusions except break-glass. |
| SMB-IAM-003 | Legacy authentication blocked tenant-wide | Legacy auth bypasses MFA. If not blocked, MFA is theatre. | CA policy blocking "Other clients." Some orgs still have legacy services, verify no critical apps depend on it before enabling. |
| SMB-IAM-004 | Global Admin count between 2 and 4 | Too few and you lock yourself out. Too many and every compromise is catastrophic. | Count excludes the one break-glass account (itself an SMB-IAM-005 requirement). |
| SMB-IAM-005 | Emergency access (break-glass) account configured | When MFA breaks or a provider has an outage, you need a way in. | Cloud-only account, long passphrase stored in physical safe, excluded from CA policies, monitored for any sign-in. |
| SMB-IAM-006 | Admin roles held by cloud-only accounts | Synced admin accounts inherit AD compromise. On-prem compromise → cloud compromise in minutes. | `onPremisesSyncEnabled` must be false for all directory role members. |
| SMB-IAM-007 | Admin accounts separate from daily-driver mailboxes | If your admin account gets phished via Outlook, it's game over. | Admin accounts have no licenses or mailbox-free licenses. |
| SMB-IAM-008 | User consent to third-party apps restricted | OAuth consent phishing is a rising vector. Users consenting to malicious apps bypasses MFA entirely. | Set to "Allow user consent for verified publishers, for selected permissions" at minimum. |
| SMB-IAM-009 | Guest invitation restricted | Unrestricted guest invites let employees create external sharing paths with no oversight. | Restrict to admins, or at minimum to users in specific roles. |
| SMB-IAM-010 | Sign-in risk and user risk policies configured (report-only acceptable) | Detects anomalous sign-ins and leaked credentials. | Requires Entra P2. If not licensed, mark as N/A rather than fail. Report-only is sufficient for Tier 1, enforce is Tier 2. |
| SMB-IAM-011 | Number-matching MFA enforced | Defeats MFA fatigue attacks. | Default for all new tenants since 2023, but verify as some tenants have legacy policies overriding this. |
| SMB-IAM-012 | Self-service password reset enabled with MFA gating | Reduces help-desk load. MFA gating prevents SSPR from being an attack vector. | All users enabled, MFA required for reset, security questions disabled. |

### Exchange Online

| ID | Control | Why it matters | Implementation note |
|---|---|---|---|
| SMB-EXO-001 | Preset Security Policies applied at Standard | Single setting enables safe-attachments, safe-links, anti-phishing, anti-spam at Microsoft-recommended thresholds. Replaces 20+ individual settings. | Standard is the Tier 1 target. Strict is Tier 2 (more false positives, requires tuning). |
| SMB-EXO-002 | External sender tagging enabled | Users can see when a message came from outside the org. Reduces BEC and spoofing success. | `Set-ExternalInOutlook -Enabled $true`. Deployed everywhere in Outlook clients within ~48 hours. |
| SMB-EXO-003 | Automatic forwarding to external domains blocked | Classic exfiltration path after mailbox compromise. | Outbound spam policy with `AutoForwardingMode = Off`. |
| SMB-EXO-004 | Mailbox auditing on by default | Required for incident response. On by default since 2019 but verify, especially in tenants migrated from legacy configurations. | `Get-OrganizationConfig` → `AuditDisabled = False`. |
| SMB-EXO-005 | SPF record present and hard-fail | Email spoofing defense, layer 1. | TXT record ends in `-all`, not `~all`, for production domains. |
| SMB-EXO-006 | DKIM enabled on all accepted domains | Email spoofing defense, layer 2. | Both CNAME records published, signing enabled per domain. |
| SMB-EXO-007 | DMARC at p=quarantine minimum with reporting | Email spoofing defense, layer 3 — and the one that ties SPF/DKIM together. | `p=quarantine` minimum, `rua=` tag pointing to a monitored mailbox or DMARC service. |
| SMB-EXO-008 | Modern authentication only | Belt-and-suspenders to SMB-IAM-003; some Exchange settings bypass tenant-level legacy auth blocking. | `Get-OrganizationConfig` → `OAuth2ClientProfileEnabled = $true`. |

### SharePoint Online and OneDrive

| ID | Control | Why it matters | Implementation note |
|---|---|---|---|
| SMB-SPO-001 | External sharing capped at "New and existing guests" | "Anyone" enables anonymous links, the single biggest accidental-exposure vector. | Tenant setting, not per-site. Individual sites can be more restrictive. |
| SMB-SPO-002 | Default sharing link type set to "Specific people" | The default shapes behavior. If default is "Anyone," users pick that every time. | "Specific people" is Tier 1. "People in your organization" is also acceptable if external sharing is rare. |
| SMB-SPO-003 | Anonymous link expiration enforced | If anonymous links are enabled at all, they should expire. 30 days is the Tier 1 ceiling. | Can be set to 7/14/30. Tier 1 allows up to 30. |
| SMB-SPO-004 | External users must accept invitation with same email | Prevents invitation forwarding from becoming an access-transfer mechanism. | Single tenant setting. |
| SMB-SPO-005 | Sync blocked from non-domain-joined or non-compliant devices | OneDrive sync from personal machines is a major exfiltration path post-compromise. | Requires Intune compliance policies to function fully. If no Intune, mark as partial. |

### Teams

| ID | Control | Why it matters | Implementation note |
|---|---|---|---|
| SMB-TEAMS-001 | External access scoped to allowlist or disabled | Default is open federation with all domains. External chat is a phishing vector. | Allowlist is best for Tier 1. Disabled is acceptable. Open federation fails. |
| SMB-TEAMS-002 | Guest access configured deliberately | Default-on guest access isn't inherently bad, but it should be a choice, not a default. | Pass if either enabled-with-deliberate-config or disabled. Fail if default-never-reviewed. |
| SMB-TEAMS-003 | Anonymous meeting join disabled or lobby required | Anonymous joiners landing directly in meetings enables eavesdropping. | Lobby required for anonymous is Tier 1 target. Disabled is also a pass. |

### Audit and Telemetry

| ID | Control | Why it matters | Implementation note |
|---|---|---|---|
| SMB-AUD-001 | Unified audit log enabled | Required for any incident response. Off by default in some legacy tenants. | `Get-AdminAuditLogConfig` → `UnifiedAuditLogIngestionEnabled = $true`. |
| SMB-AUD-002 | Audit log retention at tenant maximum | 90 days (E3) or 180+ (E5) is the default. Longer retention requires Microsoft Purview Audit (Premium). Set to the maximum the license supports. | Doesn't cost extra within the licensed tier. No reason not to maximize. |

### Device Compliance (if Intune in play)

| ID | Control | Why it matters | Implementation note |
|---|---|---|---|
| SMB-DEV-001 | Compliance policy exists and is assigned | Unassigned policies are decorative. | Must target all users or a group covering >95% of user base. |
| SMB-DEV-002 | CA requires compliant device for M365 access | Compliance without CA enforcement is decorative. | Exclusions acceptable for break-glass account and mobile-only roles. |
| SMB-DEV-003 | Non-compliant device grace period configured | Hard cutoffs cause outages. Grace period prevents compliance-drift outages on weekends. | 24-72 hours is the Tier 1 range. |

---

## Part 2: Windows Endpoint (HardeningKitty)

### Defender Configuration

| ID | Control | Registry/Policy | Rationale |
|---|---|---|---|
| SMB-DEF-001 | Real-time protection on | `DisableRealtimeMonitoring = 0` | Obvious but measured. Frequently disabled by legacy LOB installers. |
| SMB-DEF-002 | Cloud-delivered protection at High | `MpCloudBlockLevel = 2` | High is the Tier 1 target. "High+" is Tier 2 (more FPs). |
| SMB-DEF-003 | Automatic sample submission on | `SubmitSamplesConsent = 1` | Feeds the cloud protection this client is benefiting from. Low privacy concern for SMB. |
| SMB-DEF-004 | Tamper protection on | Configured via Security Center or Intune | Prevents attackers (and misguided users) from disabling Defender. |
| SMB-DEF-005 | PUA protection on block | `PUAProtection = 1` | Catches bundled adware, legitimately unwanted apps. Low FP rate. |
| SMB-DEF-006 | Network protection on block | `EnableNetworkProtection = 1` | Blocks known-bad C2 domains at the OS level. Not audit as the FP rate is low enough to enforce in Tier 1. |
| SMB-DEF-007 | SmartScreen for Edge on block | `SmartScreenEnabled = Block` | Browser-layer phishing and malware filter. |
| SMB-DEF-008 | SmartScreen for Windows on block | `EnableSmartScreen = 1`, `ShellSmartScreenLevel = Block` | OS-layer protection for downloads from any browser. |

### Attack Surface Reduction (block mode)

The following ASR rules are **block mode** in Tier 1:

| ID | Rule GUID | Description | Why block (not audit) |
|---|---|---|---|
| SMB-ASR-001 | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Block credential stealing from LSASS | Near-zero FP rate. Pure win. |
| SMB-ASR-002 | 3b576869-a4ec-4529-8536-b80a7769e899 | Block Office apps creating executable content | Office dropping EXEs is always suspicious. |
| SMB-ASR-003 | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 | Block Office from injecting into other processes | Same. |
| SMB-ASR-004 | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b | Block Win32 API calls from Office macros | Same. |
| SMB-ASR-005 | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Block executable content from email client and webmail | Closes the "open the attachment" attack loop. |
| SMB-ASR-006 | d3e037e1-3eb8-44c8-a917-57927947596d | Block JavaScript/VBScript from launching downloaded executables | Drive-by download vector. |
| SMB-ASR-007 | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c | Block Adobe Reader from creating child processes | Reader should never spawn processes. |
| SMB-ASR-008 | e6db77e5-3df2-4cf1-b95a-636979351e5b | Block persistence through WMI event subscription | Fileless persistence technique. |
| SMB-ASR-009 | c1db55ab-c21a-4637-bb3f-a12568109d35 | Use advanced ransomware protection | Behavioral ransomware detection. |
| SMB-ASR-010 | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 | Block untrusted/unsigned processes from USB | Covers the dropped-USB attack. |

The following ASR rules are deliberately **audit mode** in Tier 1 (graduate to block in Tier 2):

| Rule GUID | Description | Why audit-only in Tier 1 |
|---|---|---|
| d1e49aac-8f56-4280-b9ba-993a6d77406c | Block process creations from PSExec and WMI | Breaks many RMM agents. Requires exception management. |
| 01443614-cd74-433a-b99e-2ecdc07bfc25 | Block executable files unless they meet prevalence/age criteria | Breaks niche LOB software. Requires tuning. |

### Credential Protection

| ID | Control | Rationale |
|---|---|---|
| SMB-CRED-001 | LSA protection (RunAsPPL) enabled | Blocks LSASS memory access by non-PPL tools. |
| SMB-CRED-002 | WDigest authentication disabled | Prevents cleartext credential caching in LSASS. |
| SMB-CRED-003 | LM hash storage disabled | LM hashes are trivially crackable. |
| SMB-CRED-004 | NTLMv1 disabled | NTLMv1 is broken cryptography. |
| SMB-CRED-005 | LAPS deployed with Entra or AD escrow | Unique, rotating local admin passwords. Eliminates lateral movement via shared local admin. |
| SMB-CRED-006 | Built-in Administrator disabled or managed by LAPS | The default Administrator account is the attacker's first target. |
| SMB-CRED-007 | Guest account disabled | Should be disabled by default but verify. |

### BitLocker

| ID | Control | Rationale |
|---|---|---|
| SMB-BL-001 | BitLocker on for all fixed OS drives | Lost laptops are routine. Full disk encryption is the single control that makes loss a non-event. |
| SMB-BL-002 | XTS-AES 256 encryption | Strongest standard algorithm. Default for Windows 10+, but verify. |
| SMB-BL-003 | Recovery key escrowed to Entra (or AD for hybrid) | Without escrow, a TPM failure means data loss. |
| SMB-BL-004 | Pre-boot authentication via TPM minimum | TPM-only is the Tier 1 target. PIN is Tier 2 (help-desk burden on PIN resets). |
| SMB-BL-005 | Fixed data drives encrypted | Prevents removal and reading of secondary drives. |

### Network Protocols

| ID | Control | Rationale |
|---|---|---|
| SMB-NET-001 | SMBv1 client disabled | SMBv1 is broken. EternalBlue-class vulnerabilities. |
| SMB-NET-002 | SMBv1 server disabled | Same. |
| SMB-NET-003 | SMB signing required | Prevents relay attacks. |
| SMB-NET-004 | LLMNR disabled | Classic poisoning vector (Responder-class tools). |
| SMB-NET-005 | NetBIOS over TCP/IP disabled | Same. **Flag:** some legacy printers/scanners still need it. Test before enforcing. |
| SMB-NET-006 | TLS 1.0 disabled | Cryptographic failures. |
| SMB-NET-007 | TLS 1.1 disabled | Same. |

### Office

| ID | Control | Rationale |
|---|---|---|
| SMB-OFF-001 | Block macros from internet (Mark of the Web) | The single highest-ROI Office setting. Covers the phishing → macro → payload chain. |
| SMB-OFF-002 | Protected view enabled for internet files | Sandboxes opened-from-internet files. |
| SMB-OFF-003 | Protected view enabled for attachments | Same for email attachments. |
| SMB-OFF-004 | Protected view enabled for unsafe locations | Same for downloads folder, temp, etc. |
| SMB-OFF-005 | Dynamic Data Exchange disabled in all Office apps | Legacy feature, exploited via phishing docs. |

### Windows Firewall

| ID | Control | Rationale |
|---|---|---|
| SMB-FW-001 | Firewall on for all three profiles (Domain, Private, Public) | Still off on some imaged machines. |
| SMB-FW-002 | Inbound blocked by default | Outbound is permitted in Tier 1; outbound lockdown is Tier 2. |
| SMB-FW-003 | Notifications on | Users see blocks and can report them. |

### UAC

| ID | Control | Rationale |
|---|---|---|
| SMB-UAC-001 | UAC enabled | Obvious but measurable. |
| SMB-UAC-002 | Admin approval mode on | Forces consent for elevation. |
| SMB-UAC-003 | Secure desktop for elevation prompts | Prevents UI spoofing of the prompt. |

**Deliberately NOT in Tier 1:** "Always Notify" level of UAC. It generates measurable help-desk volume. Default notify-on-change is the Tier 1 target.

### Windows Update

| ID | Control | Rationale |
|---|---|---|
| SMB-WU-001 | Automatic updates configured | Set to install automatically. Deferral acceptable; disabled is not. |
| SMB-WU-002 | Quality update deferral 0-7 days | Too long = exposure to known exploited CVEs. |
| SMB-WU-003 | Feature update deferral 60-180 days | Too short = compatibility breakage. Too long = unsupported OS. |

### Logging

| ID | Control | Rationale |
|---|---|---|
| SMB-LOG-001 | PowerShell script block logging on | Near-zero cost, invaluable in incident response. |
| SMB-LOG-002 | PowerShell module logging on for core modules | Same. |
| SMB-LOG-003 | Command-line process auditing on | Captures the command line of spawned processes. |

**Deliberately NOT in Tier 1:** PowerShell transcription. Generates significant disk I/O and potential privacy concerns. Tier 2.

### Removable Media

| ID | Control | Rationale |
|---|---|---|
| SMB-RM-001 | AutoRun/AutoPlay disabled for removable media and network drives | Dropped-USB attack. Cheap, safe. |

---

## Explicit Exclusions (and why)

The following are commonly included in enterprise baselines and **deliberately excluded from Tier 1**. Each is a valid Tier 2 candidate.

| Control | Why excluded from Tier 1 |
|---|---|
| AppLocker / WDAC (any mode) | Significant ongoing exception-management burden. Requires a trained operator. Tier 2. |
| PowerShell Constrained Language Mode | Breaks RMM agents, admin tooling, and most non-signed automation. Tier 2 with careful rollout. |
| Credential Guard | Hardware-dependent, breaks some VPN clients and legacy auth tooling. Tier 2 after compatibility validation. |
| BitLocker with PIN at pre-boot | Generates help-desk volume. TPM-only is the Tier 1 position. |
| Account lockout at aggressive thresholds | Help-desk generator. Smart Lockout in Entra covers the cloud side; on-prem aggressive lockout causes more problems than it solves in SMB. |
| Removable media write-block (device control) | Breaks legitimate workflows (presentations, file transfers at client sites). Tier 2 after policy definition. |
| Exploit Protection custom XML profiles | Maintenance burden. Default Windows Exploit Protection is enabled; custom profiles are Tier 2. |
| Disabling signed Office macros globally | Breaks finance/operations workflows (QuickBooks, Excel models, RFP templates). MOTW block (SMB-OFF-001) covers the main attack surface; full disable is Tier 2 after macro inventory. |
| PIM for admin roles | Requires Entra P2. Configuration burden. High value but Tier 2. |
| Privileged Access Workstations | Operational model change. Tier 2. |
| Identity Protection risk policies in enforce mode | False positive rate requires tuning. Report-only is Tier 1 (SMB-IAM-010); enforce is Tier 2. |
| Preset Security Policies at Strict | Higher FP rate, requires user education on the quarantine experience. Standard is the Tier 1 target; Strict is Tier 2. |
| Outbound firewall lockdown | Significant exception management. Tier 2. |
| PowerShell transcription | Disk I/O and privacy concerns. Tier 2. |
| 802.1X network access control | Infrastructure-dependent. Tier 2+ and often outside this scope entirely. |

---

## Framework Mappings

Tier 1 controls map directionally to the following frameworks. These mappings are not audit-grade and are provided for context, not attestation.

- **CIS Controls v8 IG1:** Primary alignment. Most Tier 1 controls correspond to IG1 safeguards.
- **CIS Microsoft 365 Foundations Benchmark v4:** Cloud-side controls align to Level 1 with some Level 2 picked up opportunistically.
- **CIS Microsoft Windows 11 Benchmark:** Endpoint controls align to Level 1.
- **NIST CSF 2.0:** Covers Identify, Protect, and some Detect subcategories.

Audit-grade framework mapping (including HIPAA, SOC 2, CMMC Level 2) is an eventual deliverable.
