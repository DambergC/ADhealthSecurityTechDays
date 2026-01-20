# ADSecurityMonitor – Active Directory Security Risk Checks

This module provides a large set of PowerShell checks (80+ individual tests) to assess on‑prem Active Directory security posture, roughly aligned to the kinds of findings you see in a PingCastle report:

- Categorized as **HIGH**, **MEDIUM**, and **LOW**.
- Each function returns a `PSCustomObject` with:
  - `CheckName`
  - `Severity`
  - `Status` (`PASS`, `FAIL`, `WARN`, `INFO`, `ERROR`)
  - Plus details and recommendations.

> This is not a replacement for PingCastle, but gives you scriptable checks you can run on a schedule and compare with PingCastle output.

---

## 1. Installation

1. Save the module file:

   ```powershell
   # On an admin workstation or management server
   $modulePath = "C:\Program Files\WindowsPowerShell\Modules\ADSecurityMonitor"
   New-Item -ItemType Directory -Path $modulePath -Force | Out-Null
   Copy-Item .\ADSecurityMonitor.psm1 $modulePath\
   ```

2. Ensure the **ActiveDirectory** and (optionally) **GroupPolicy** modules are available on the machine you run it from.

3. Import the module:

   ```powershell
   Import-Module ADSecurityMonitor
   ```

---

## 2. Running Audits

### 2.1 Full audit

```powershell
# Run all High, Medium and Low checks
$results = Invoke-ADSecurityAudit -Severity All
$results | Format-Table Severity, CheckName, Status
```

### 2.2 By severity

```powershell
# High only
Invoke-ADSecurityAudit -Severity High

# Medium only
Invoke-ADSecurityAudit -Severity Medium

# Low only
Invoke-ADSecurityAudit -Severity Low
```

### 2.3 Export to CSV for comparison with PingCastle

```powershell
$csv = "C:\Reports\ADSecurity-$(Get-Date -Format yyyyMMdd-HHmm).csv"
Invoke-ADSecurityAudit -Severity All -ExportPath $csv
```

You can then:

- Map `CheckName` / `Severity` / `Status` to PingCastle categories.
- Use Excel/Power BI to compare trends over time.

---

## 3. Security Score and HTML Report

### 3.1 Overall score

```powershell
$score = Get-ADSecurityScore
$score
```

Example output:

```text
TotalChecks     : 82
Passed          : 60
Failed          : 10
Warnings        : 12
MaxScore        : 540
EarnedScore     : 410
ScorePercentage : 75.93
Rating          : Good
```

### 3.2 HTML Report

```powershell
$htmlPath = "C:\Reports\ADSecurityReport-$(Get-Date -Format yyyyMMdd-HHmm).html"
Export-ADSecurityReport -OutputPath $htmlPath
Start-Process $htmlPath
```

The HTML report shows:

- Overall score and rating.
- A table with all checks, colored by:
  - Severity (High/Medium/Low)
  - Status (PASS/FAIL/WARN)

---

## 4. Example: Run on a schedule

Basic scheduled task approach:

```powershell
$script = 'Import-Module ADSecurityMonitor; ' +
          '$csv = "C:\Reports\ADSecurity-$(Get-Date -Format yyyyMMdd-HHmm).csv"; ' +
          'Invoke-ADSecurityAudit -Severity All -ExportPath $csv; ' +
          '$html = "C:\Reports\ADSecurityReport-$(Get-Date -Format yyyyMMdd-HHmm).html"; ' +
          'Export-ADSecurityReport -OutputPath $html;'

$taskPath = "C:\Scripts\Run-ADSecurityAudit.ps1"
$script | Out-File -FilePath $taskPath -Encoding UTF8

# Then create a scheduled task that runs:
# powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Run-ADSecurityAudit.ps1"
```

---

## 5. Mapping to PingCastle

This module is **inspired by** PingCastle findings, for example:

- **High risks**: KRBTGT age, AdminSDHolder ACLs, unconstrained delegation, SMBv1, LAPS, RODC PRP, DC patching, DC firewall, etc.
- **Medium risks**: password policy, account lockout, stale accounts, SIDHistory, DES, pre‑auth disabled, dangerous GPO rights, group nesting, operator groups, etc.
- **Low risks**: Recycle Bin, DNS scavenging, functional level, backup age, event log size, empty OUs, duplicate SPNs.

You can extend the module with your own `Test-*` functions that return the same shape of object; `Invoke-ADSecurityAudit` can be updated to include them.

---

## 6. Notes / Requirements

- Must be run with **Domain Admin** or equivalent rights for many checks.
- Some checks use remote registry, WMI/CIM, and require:
  - RPC/firewall allowed between the management host and DCs.
  - Appropriate permissions.
- Some commands (e.g. `Get-DhcpServerInDC`, `Get-DfsrBacklog`, `Get-DnsServerScavenging`) must be available on the machine (RSAT / AD DS / DNS / DHCP tools installed).

---

If you want, I can next:

- Trim/extend to exactly 100 checks and provide a small mapping table to PingCastle categories, or
- Help you build a comparison script that ingests a PingCastle XML/CSV and lines it up with this module’s results.
