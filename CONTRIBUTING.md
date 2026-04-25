# Contributing

Field feedback is the whole point of this project. If you run Tier 1 against a real environment and something breaks, surprises you, or produces noise, please tell us.

## What's most useful

In descending order of value:

1. **Field-broken controls.** A control that fails in your environment because of a specific LOB app, legacy printer, line-of-business workflow, or imaging oddity. These produce the exclusion annotations that make the baseline genuinely usable.
2. **False positives in the assessment logic.** A Maester test or HardeningKitty check that reports non-compliance when the environment is actually compliant (different valid setting, different configuration path, etc.).
3. **Remediation guidance improvements.** Specific feedback on where the remediation text led someone wrong or omitted a crucial step.
4. **Missing controls that pass the Tier 1 inclusion test.** See below.

## Tier 1 inclusion test

A control belongs in Tier 1 only if **all four** of these are true:

1. Closes a real attack path seen in the field (not theoretical).
2. Deploys without user-visible friction in an org without help-desk capacity.
3. Meaningful to a non-technical business owner when shown as a finding.
4. Does not require ongoing tuning, exception management, or specialist attention.

If any of these fails, the control belongs in Tier 2 (`smb-hardening-enhanced`), not here. PRs adding Tier 2-flavored controls to Tier 1 will be redirected.

## Reporting broken or noisy controls

Open an issue using the **Field Finding** template. Please include:

- Control ID (`SMB-<CATEGORY>-<NNN>`)
- Environment profile: seat count, M365 SKU, hybrid AD yes/no, primary LOB applications
- What the control reported
- What you expected
- What broke (if anything) when you tried to remediate

Detail matters. "It doesn't work" is not actionable; "SMB-NET-005 breaks our Epson TM-L90 label printers on the accounting VLAN" is a one-line doc update that helps every future user.

## Pull requests

Small PRs welcome, especially:

- Documentation fixes (typos, stale links, clarification)
- Remediation link updates as Microsoft renames admin centers
- Exclusion annotations in `docs/BASELINE.md` based on field experience
- New entries in the "common exception patterns" appendix

Larger changes like new controls, baseline additions, tooling features, please open an issue first so we can align on scope before you invest effort.

## What's out of scope

- Controls that require Entra P2, Defender for Endpoint P2, or Purview Premium licensing. Those belong in Tier 2.
- Controls requiring AppLocker, WDAC, Constrained Language Mode, or other capabilities with significant operational overhead. Tier 2.
- Anything that requires a SIEM or SOC to operationalize. Tier 2.
- Features that turn this into a general-purpose security assessment tool. The opinion — specifically sized for SMB without IT — is the product.

## Code style

PowerShell:

- Target PowerShell 7.2+ syntax.
- `Set-StrictMode -Version Latest` is the desired state, but we're not there yet across the codebase.
- Pass `Invoke-ScriptAnalyzer` at Warning severity (run by CI).

Pester tests:

- Tag every `It` block with its stable control ID (`SMB-<CATEGORY>-<NNN>`) and severity (`Critical`/`High`/`Medium`/`Low`).
- Use `-Because` on every assertion with actionable remediation text.
- Cache tenant-wide reads in `BeforeDiscovery`, not `BeforeAll`.

HardeningKitty CSV:

- IDs must be unique and must start with `SMB-`.
- Severity must be `Critical`, `High`, `Medium`, or `Low`.
- CI validates schema on every PR.

## License

By contributing, you agree your contributions are licensed under the MIT license covering this repository.
