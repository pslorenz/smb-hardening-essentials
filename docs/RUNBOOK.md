# Runbook: Operating the Tier 1 Assessment

This document is the operational guide. The README covers what the project is; BASELINE covers what it tests; this covers how to run it, what to do with the output, and how to communicate findings.

**Audience:** the person running the assessment; you, a technician, or an MSP partner. Assumes PowerShell literacy and basic M365 admin knowledge.

---

## Pre-engagement checklist

Before you schedule the assessment with a client, confirm:

- [ ] An admin account exists with at least Global Reader, Security Reader, SharePoint Administrator, Exchange Administrator
- [ ] MFA on that account is working and the method is available to you during the scan
- [ ] Client has been told what to expect: read-only, no changes, ~30 minutes runtime
- [ ] If running endpoint checks, you have the target machine(s) identified and either local access or RMM scripted-deployment capability
- [ ] HardeningKitty is installed as a PowerShell module (either in a PSModulePath location via `Import-Module`, or clone path known for `-HardeningKittyPath`) and `Import-Module HardeningKitty; Get-Command Invoke-HardeningKitty` succeeds on the run machine
- [ ] Maester is installed and `Connect-Maester` has been tested against *your own* tenant
- [ ] Output path exists and is somewhere the final report won't get swept up in client-facing folders by accident

---

## Running the assessment

### Standard run (cloud + endpoint, interactive auth)

```powershell
.\Invoke-SmbHardeningAssessment.ps1 `
    -TenantId "11111111-2222-3333-4444-555555555555" `
    -ClientName "Acme Corp" `
    -OutputPath "C:\SMBHardening\reports" `
    -HardeningKittyPath "C:\Tools\HardeningKitty"
```

Expect:

1. Browser window opens for M365 auth. Sign in with the admin account.
2. Maester runs (~5-10 minutes depending on tenant size).
3. HardeningKitty runs locally (~3-5 minutes).
4. Report is generated and the output path is opened in Explorer.

### Cloud-only (useful for sales calls and initial assessments)

```powershell
.\Invoke-SmbHardeningAssessment.ps1 `
    -TenantId <guid> -ClientName "Acme" -CloudOnly
```

This is the ~10-minute demo you can run on a prospect call with their admin watching.

### Unattended (scheduled/RMM)

Requires an app registration with certificate auth. See README for required Graph permissions.

```powershell
.\Invoke-SmbHardeningAssessment.ps1 `
    -TenantId <guid> `
    -ClientId <app-id> `
    -CertificateThumbprint <thumbprint> `
    -ClientName "Acme" `
    -OutputPath "\\fileserver\SMBHardening\Acme" `
    -NonInteractive
```

---

## What the output looks like

```
reports/
└── Acme Corp/
    └── 20261015-143022/
        ├── report.html           ← give this to the client
        ├── summary.txt           ← one-pager for the engagement manager
        ├── findings.json         ← machine-readable, for drift tracking
        ├── maester-raw.json      ← full Maester output (archive, not client-facing)
        ├── hardeningkitty-raw.csv ← same for HardeningKitty
        └── run.log               ← for troubleshooting
```

**The client sees `report.html`.** Everything else is for you.

---

## Interpreting findings

Each finding in the report has a severity: **Critical**, **High**, **Medium**, or **Low**.

- **Critical** active attack path or compliance failure with no compensating control. Example: MFA not enforced, legacy auth allowed.
- **High** significant risk reduction available with low effort. Example: automatic forwarding to external domains not blocked.
- **Medium** meaningful improvement; context-dependent severity. Example: external sharing set to "Anyone" when the business has no anonymous-sharing use case.
- **Low** hygiene. Example: audit log retention at default instead of maximum.

**Acknowledged exceptions** appear in their own section with the reason, approver, and expiration date. They are not failures but they are not passes either — they're risk acceptances.

**N/A findings** (control doesn't apply e.g., a P2-licensed control in a P1 tenant) appear grouped at the end for transparency.

---

## The client conversation

The report is the artifact. The conversation is the product.

**Do not email the report without a conversation.** A non-technical business owner opening a PDF with 12 Critical findings will panic, call their lawyer, or fire their MSP. None of those outcomes serve them.

Structure the readout:

1. **Lead with what's working.** Something is always working, MFA is partially deployed, BitLocker is on, whatever. Name it first. Five sentences.
2. **The three things that matter.** Pick the three highest-impact findings. Explain each in business terms, not security terms:
   - Not "Legacy authentication is not blocked tenant-wide."
   - But "Right now, there's a way to sign into email that skips the extra verification step on your phone. Attackers know about this and use it. We need to turn it off."
3. **What we recommend, what it costs, what it risks.** For each of the three, say what the fix is, roughly what the effort is, and whether anything might break. Be specific.
4. **The rest of the report.** Briefly acknowledge it exists, offer to walk through any specific finding, but do not go line-by-line unless asked.
5. **Next steps.** Either "we'll fix these as part of your current engagement," "here's a proposal for a hardening engagement," or "your MSP should address these — here's what to ask for."

The whole conversation is 20-30 minutes. If it's longer, you lost them.

---

## Common field issues

### Maester fails to connect

- **Check:** Is the account licensed for Entra ID? Unlicensed accounts can't read some settings.
- **Check:** Are you on the latest Maester module? `Update-Module Maester`.
- **Check:** Is Conditional Access blocking PowerShell sign-ins? Some hardened tenants require CA exceptions for admin tooling.

### HardeningKitty reports a setting as "Not defined" when you know it's set

- **Check:** Are you running as admin? Many registry checks require elevation.
- **Check:** Is the machine domain-joined or Entra-joined? Some settings only exist when policy is applied.
- **Check:** Is the finding list the right Windows version? The Tier 1 list targets Windows 10 1809+ and Windows 11. Older systems will have false negatives.

### Report generation fails

- Check `run.log` in the output directory.
- The most common cause is a template variable missing so if you customized the template, verify all expected fields are present.

### A control legitimately doesn't apply

Use `client-exceptions.json` (see README). Document the reason with enough detail that a future reader (or auditor) can evaluate the decision. "Doesn't apply" is not a valid reason; "Requires NetBIOS for legacy Epson label printer on accounting floor, VLAN-isolated" is.

---

## After the engagement

### If remediation is in scope

Re-run the assessment after remediation. The delta between the two reports is the evidence of value delivered, archive it.

### If remediation is ongoing (retainer/co-managed)

Schedule the assessment to run monthly or quarterly. Commit the `findings.json` to a client-specific private repo. Drift becomes visible as git diff.

### If the engagement is one-and-done

Archive the entire output folder. Include a short cover memo with the engagement details and any verbal findings that aren't in the report. This becomes the baseline if the client comes back in a year.

---

## Updating the baseline

The Tier 1 baseline will change. Microsoft defaults shift, attack techniques evolve, field experience reveals FPs.

**Before updating baseline in production:**

1. Test the new control on your own tenant.
2. Run against at least two client-like environments (a test tenant and a low-risk friendly client).
3. Update `BASELINE.md` with the rationale.
4. Bump the baseline version in `Invoke-SmbHardeningAssessment.ps1`.
5. Note the change in `CHANGELOG.md`.

**Never silently change the meaning of an existing control ID.** If a control's check changes substantively, deprecate the old ID and introduce a new one. Reports from six months ago should still be readable.


