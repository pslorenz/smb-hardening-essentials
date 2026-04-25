# Endpoint Checks (HardeningKitty finding lists)

This directory contains HardeningKitty finding lists used by the Tier 1 endpoint assessment.

## Files

- `tier1-hardeningkitty.csv` — the Tier 1 baseline. ~50 controls covering Defender, ASR, credential protection, BitLocker, network protocols, Office, firewall, UAC, updates, logging, and removable media.

## CSV format

HardeningKitty expects a specific column set. The ones we use:

| Column | Purpose |
|---|---|
| `ID` | Our stable control ID (`SMB-<CATEGORY>-<NNN>`). Must be unique. |
| `Category` | Logical grouping matching the `-Categories` parameter values in `Invoke-SmbHardeningAssessment.ps1`. |
| `Name` | Human-readable description. Appears in the report. |
| `Method` | `Registry`, `Cmdlet`, `Account`, `accesscheck`, etc. How to retrieve the current value. |
| `MethodArgument` | Argument to the method (e.g., `-MountPoint C:` for `Get-BitLockerVolume`). |
| `RegistryPath`, `RegistryItem` | For `Method=Registry`. |
| `Property` | For `Method=Cmdlet`, the property of the returned object to check. |
| `DefaultValue` | Value Windows ships with. Informational. |
| `RecommendedValue` | Expected value for a pass. |
| `Operator` | `=`, `>=`, `<=`, `Contains`. |
| `Severity` | `Critical`, `High`, `Medium`, or `Low`. Maps to the report severity. |

The full HardeningKitty format supports additional columns (`Task`, `FindingID`, etc.) that we don't use.

## Adding a control

1. Pick the next available ID in the relevant category (e.g., `SMB-NET-008`).
2. Add a row to `tier1-hardeningkitty.csv`.
3. Add a corresponding entry to `../docs/BASELINE.md` with rationale.
4. If the control belongs in Tier 2 instead, add it to the `smb-hardening-enhanced` repo rather than here.

**Before merging a new control, verify it passes all four Tier 1 inclusion tests:**

1. Closes a real attack path seen in the field.
2. Deploys without user-visible friction.
3. Meaningful to a non-technical business owner.
4. Does not require ongoing tuning or exception management.

If any of these fail, the control belongs in Tier 2.

## Modifying an existing control

Never change the meaning of a published ID. If a control's check substantively changes:

1. Mark the old ID as deprecated in `../docs/BASELINE.md` (keep the row).
2. Add a new row with a new ID.
3. Document in `CHANGELOG.md`.

This preserves report comparability across time since a client's Q1 and Q3 reports should reference the same IDs for the same checks.

## Testing changes locally

```powershell
# Run HardeningKitty directly with this list
Import-Module HardeningKitty   # or: Import-Module C:\Tools\HardeningKitty\HardeningKitty.psd1
Invoke-HardeningKitty -Mode Audit -FileFindingList .\tier1-hardeningkitty.csv -Report

# Run the full assessment (cloud + endpoint) against your own tenant
..\Invoke-SmbHardeningAssessment.ps1 -TenantId <guid> -ClientName "Test" `
    -HardeningKittyPath C:\Tools\HardeningKitty
```
