# Security

## Reporting a vulnerability

If you believe you've found a security vulnerability in this project, i.e something that would let this tool mis-report results, exfiltrate data from a scanned tenant, escalate privilege on a scanned endpoint, or otherwise compromise an environment it's run against please report it.

- A description of the vulnerability
- Steps to reproduce
- Your assessment of impact
- Any mitigations you're aware of

We'll acknowledge within as soon as possible, provide a disposition (accepted/declined with reasoning) within 10 business days, and coordinate a fix timeline for accepted reports.

## Scope

In scope:

- The assessment wrapper script and its handling of credentials, output, and network requests
- The Maester test pack and HardeningKitty finding list specifically, any case where they produce misleading results that could cause a practitioner to miss a real issue
- The report template and any XSS/injection concerns in generated reports
- The CI pipeline and any supply chain concerns

Out of scope (report upstream instead):

- Vulnerabilities in Maester itself report to [maester-dev/maester](https://github.com/maester-dev/maester)
- Vulnerabilities in HardeningKitty report to [scipag/HardeningKitty](https://github.com/scipag/HardeningKitty)
- Vulnerabilities in Microsoft Graph, Entra ID, Exchange Online, or any Microsoft service — report to [Microsoft Security Response Center](https://msrc.microsoft.com/)
- Findings in a scanned tenant itself (that's what the tool is for. Enable the tool, remediate the findings)

## Operational security when running this tool

A few cautions worth naming, since this tool reads privileged data from tenants:

- **Output directories contain sensitive information.** `findings.json` and the raw JSON/CSV outputs include tenant configuration that could help an attacker. Protect the output path accordingly.
- **Run IDs are UUIDs** and should be treated as moderately sensitive in client-facing reports as they're not secrets, but they correlate with internal records.
- **Credential handling.** The script supports interactive auth and certificate-based app auth. It does not support client-secret auth and will not accept one, because SharePoint requires certificate auth. If you've configured the app reg with a secret, remove it and use a certificate.
- **Least-privilege app registrations.** The minimum required Graph permissions are listed in the README. Do not over-grant. `.Read.All` is sufficient for every check in this project; `.ReadWrite.All` is never required.

## Supply chain

Dependencies:

- Maester (via PowerShell Gallery) signed by the Maester maintainers
- Microsoft.Graph.Authentication (via PowerShell Gallery) signed by Microsoft
- HardeningKitty (PowerShell module distributed via GitHub releases, not PowerShell Gallery as of this writing) always verify the source is `github.com/scipag/HardeningKitty` and pin to a tagged release; verify the `.psd1` author (`Michael Schneider`) and GUID (`b3223371-0f7e-4b56-8b76-67da6027921e`) match the expected upstream

Keep these updated. The CI pipeline does not currently pin dependency versions; PRs welcome.
