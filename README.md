# ADSecurityMonitor – Active Directory Security Risk Checks

This module provides a PowerShell-based assessment of on‑prem Active Directory security posture, inspired by the types of findings you see in PingCastle.

- Implemented as a single module file: `ADSecurityMonitor.psm1`
- Contains many `Test-*` checks (aiming at ~100 individual tests over time)
- Categorized as **HIGH**, **MEDIUM**, and **LOW** severity
- Each check focuses on a concrete, actionable risk (configuration, hardening, operational hygiene)
- Includes optional **remediation helper functions** to assist in fixing certain findings (see [4. Remediation Helpers](#4-remediation-helpers))

Every test function returns a `PSCustomObject` with a common shape, typically including:

- `CheckName`
- `Severity` (HIGH, MEDIUM, LOW)
- `Status` (`PASS`, `FAIL`, `WARN`, `INFO`, `ERROR`)
- One or more detail properties (e.g. `Details`, `AffectedComputers`, `DaysOld`, etc.)
- `Recommendation`
- `Risk`

> This module is not a replacement for PingCastle. It is a scriptable, extensible way to monitor many of the same risk areas on a schedule, export results, and integrate with your own reporting/alerting.

---

## 1. Installation

1. Copy the module to a standard PowerShell module path on an admin workstation or management server (with RSAT / AD tools installed):

   ```powershell
   $moduleRoot = "C:\Program Files\WindowsPowerShell\Modules\ADSecurityMonitor"
   New-Item -ItemType Directory -Path $moduleRoot -Force | Out-Null
   Copy-Item .\ADSecurityMonitor.psm1 $moduleRoot\
   ```

2. Ensure required modules are present on the machine where you run it:

   - **Required**: `ActiveDirectory`
   - **Recommended / used by some checks**: Group Policy, DNS / DHCP RSAT tools, BitLocker / storage cmdlets, etc.

3. Import the module:

   ```powershell
   Import-Module ADSecurityMonitor
   ```

You can verify that the module is loaded and discover available checks with:

```powershell
Get-Command -Module ADSecurityMonitor
```

---

## 2. Running Security Checks

The module exposes individual `Test-*` functions per risk area. Each function:

- Runs one logical check (e.g. “KRBTGT password age”, “Unconstrained delegation”, “SMBv1 enabled on DCs”)
- Returns a single `PSCustomObject` summarizing status and key details

You can either:

- Call specific checks manually, or
- Use a wrapper function (if present in your version of the module, e.g. `Invoke-ADSecurityAudit`) to orchestrate multiple checks.

### 2.1 Running individual checks (examples)

Below are examples taken from the **HIGH severity** section of the module. All of them return a single object with `Status`, `Recommendation`, and `Risk` for easy reporting.

```powershell
# KRBTGT password age
Test-KrbtgtPasswordAge -MaxDaysOld 180

# AdminSDHolder ACL modifications
Test-AdminSDHolder

# Unconstrained delegation on computer accounts
Test-UnconstrainedDelegation

# AutoLogon registry settings on DCs
Test-DCRegistryAutoLogon

# NTLM authentication / LMCompatibilityLevel on DCs
Test-NTLMAuthentication

# Pre-Windows 2000 Compatible Access group members
Test-PreWindows2000CompatibleAccess

# Print Spooler running on DCs
Test-DCPrintSpooler

# Protected Users group membership for privileged accounts
Test-ProtectedUsersGroup

# Unauthorized software on DCs (customizable list)
Test-DCUnauthorizedSoftware -UnauthorizedSoftware @("*Chrome*", "*Firefox*", "*Skype*", "*Teams*")

# Anonymous / unsigned LDAP behaviour on DCs
Test-DCAnonymousAccess

# Privileged accounts with SPNs (Kerberoasting risk)
Test-PrivilegedAccountsWithSPN

# SYSVOL share permissions
Test-DCSysvolPermissions

# RODC password replication policy
Test-RODCPasswordReplicationPolicy

# Local Administrators group contents on DCs
Test-DCLocalAdminGroup

# Remote access / remote administration services on DCs
Test-DCRemoteAccessServices

# SMBv1 protocol usage on DCs
Test-SMBv1Protocol

# Windows Firewall profiles enabled on DCs
Test-DCFirewallStatus

# BitLocker enabled on DC OS volumes
Test-BitLockerOnDCs

# Null session access / anonymous enumeration settings
Test-NullSessionAccess

# LLMNR / NetBIOS‑NS disabled on DCs
Test-LLMNRAndNBTNS

# Privileged group nesting (Domain Admins / Enterprise Admins / Schema Admins)
Test-PrivilegedGroupsNesting

# DC patch level (days since last installed hotfix)
Test-DCPatchLevel -DaysSinceLastUpdate 30

# Domain machine account quota (ms-DS-MachineAccountQuota)
Test-DomainObjectQuota

# GPO backup age and presence
Test-GPOBackups -BackupPath "\\$( (Get-ADDomain).PDCEmulator )\GPOBackups" -MaxDaysOld 30

# Admin account isolation (separate admin vs. user accounts)
Test-AdminAccountIsolation

# Service accounts with weak password policy (never expires / very old)
Test-ServiceAccountPasswords

# AD Certificate Services presence (CA discovery / inventory)
Test-CertificateServices

# Exchange schema version (for Exchange‑enabled forests)
Test-ExchangeSchemaVersion

# LAPS deployment (schema and configuration checks – defined later in the module)
Test-LAPSDeployment
```

Each call produces a single record. For example:

```powershell
Test-KrbtgtPasswordAge

CheckName        : KRBTGT Password Age
Severity         : HIGH
Status           : FAIL
PasswordLastSet  : 01/01/2022 10:00:00
DaysOld          : 380
MaxAllowed       : 180
Recommendation   : Reset KRBTGT password immediately if older than 180 days
Risk             : Golden Ticket attacks possible with compromised old KRBTGT password
```

You can pipe the combined output from multiple tests into any reporting / export mechanism that fits your environment.

### 2.2 (Optional) Aggregated audit entry point

If your version of `ADSecurityMonitor.psm1` contains a wrapper such as `Invoke-ADSecurityAudit`, you can run a broader audit like:

```powershell
# All checks
$results = Invoke-ADSecurityAudit -Severity All
$results | Format-Table Severity, CheckName, Status

# Only HIGH checks
Invoke-ADSecurityAudit -Severity High

# Export combined results to CSV
Invoke-ADSecurityAudit -Severity All |
    Export-Csv "C:\Reports\ADSecurity-$(Get-Date -Format yyyyMMdd-HHmm).csv" -NoTypeInformation
```

If there is no wrapper function in your current commit, you can build one easily by:

1. Listing the `Test-*` functions you want to include.
2. Invoking each in turn.
3. Collecting and outputting all returned objects.

---

## 3. Example: Build Your Own Summary / Score

Since every test returns a similar object, you can:

- Build a simple “scorecard” (count of PASS/FAIL/WARN per severity).
- Generate custom HTML / email reports.
- Push results into a SIEM or monitoring platform.

Example (manual composition of checks):

```powershell
$checks = @()
$checks += Test-KrbtgtPasswordAge
$checks += Test-AdminSDHolder
$checks += Test-UnconstrainedDelegation
$checks += Test-DCRegistryAutoLogon
$checks += Test-NTLMAuthentication
# ... add any additional Test-* functions you want

$summary = $checks | Group-Object Severity, Status | Select-Object Name, Count
$summary | Format-Table
```

You can extend this pattern to calculate a custom “score” or to tag results for dashboards.

---

## 4. Remediation Helpers

In addition to the `Test-*` functions, the module can expose **remediation helper** functions (`Repair-*`, `Invoke-*Remediation`, or similar) designed to assist in fixing specific high‑impact findings in a **scriptable and repeatable** way.

> **Important:**  
> All remediation helpers are designed for **experienced AD administrators**. Always:
> - Review the implementation.
> - Test in a lab / non‑production environment.
> - Take appropriate backups (GPO, system state, etc.).
> - Obtain change approvals according to your change management process.

### 4.1 Concept and workflow

The typical workflow is:

1. **Detect** issues using `Test-*` functions.
2. **Review** the `Recommendation` and `Risk`.
3. **Plan remediation** and validate impact.
4. **Optionally call a remediation helper** to automate all or part of the change.

High‑level pattern:

```powershell
# 1. Run a check
$result = Test-KrbtgtPasswordAge -MaxDaysOld 180

if ($result.Status -eq 'FAIL') {
    # 2. Review details
    $result | Format-List *

    # 3. Run remediation helper (example name)
    #    Make sure you understand the implications of resetting KRBTGT!
    Invoke-RepairKrbtgtPassword -WhatIf
}
```

Most remediation functions should support:

- `-WhatIf` / `-Confirm` (if they perform changes).
- Clear logging / verbose output.
- Parameters to scope which objects are affected (e.g. specific DCs, GPOs, or OUs).

### 4.2 Typical remediation areas

Depending on which helpers you implement in `ADSecurityMonitor.psm1`, you might cover:

- **Account / password risks**
  - Resetting the **KRBTGT** account in a controlled, phased manner.
  - Rotating **service account passwords** and moving to **gMSA**.
  - Enforcing **password expiration** for old or never‑expiring accounts.

- **Group and ACL hardening**
  - Cleaning **AdminSDHolder** ACLs (only approved admin groups).
  - Removing **unexpected members** from **DC local Administrators** group.
  - Tidying **privileged group nesting** (Domain Admins, Enterprise Admins, Schema Admins).

- **Domain policy & configuration**
  - Reducing **MachineAccountQuota** to 0.
  - Hardening **null session** configuration.
  - Disabling **LLMNR** and **NetBIOS‑NS** via GPO.
  - Ensuring **LAPS** is deployed and linked to the right OUs.

- **DC hardening**
  - Disabling **SMBv1**, **Print Spooler** on DCs.
  - Enabling and configuring **Windows Firewall** profiles.
  - Enabling **BitLocker** on DC OS volumes.
  - Removing **unauthorized software** from DCs.
  - Disabling unnecessary remote access services (RemoteRegistry, etc.).

Each remediation helper should clearly document:

- Input parameters.
- What it changes.
- Preconditions and required rights.
- Rollback/mitigation guidance, if applicable.

### 4.3 Enumerating remediation helpers

You can list all remediation-related commands with:

```powershell
# All commands in the module
Get-Command -Module ADSecurityMonitor

# Filter common naming patterns
Get-Command -Module ADSecurityMonitor -Name 'Repair-*','Fix-*','Invoke-*Remediation*'
```

Once you know the helper’s name, use standard PowerShell help to review usage:

```powershell
Get-Help Invoke-RepairKrbtgtPassword -Full
Get-Help Repair-DCLocalAdmins -Examples
```

---

## 5. Mapping to PingCastle / Common Risk Areas

The module is **inspired by** PingCastle’s risk model. The implemented `Test-*` functions cover, among others:

- **High risks**
  - KRBTGT account age, unconstrained delegation
  - AdminSDHolder ACL manipulation
  - SMBv1 protocol, unsigned / anonymous LDAP, null sessions
  - DC patch level, firewall status, BitLocker encryption
  - RODC password replication policy
  - Privileged accounts with SPNs, privileged group nesting
  - LAPS deployment, AD CS presence / configuration, Exchange integration
  - Unauthorized software and dangerous remote services on DCs
  - Domain object creation quota

- **Medium / Low risks**
  - Additional configuration and hygiene checks (password policy, stale objects, functional levels, backup age, etc.) defined in later parts of the module.

You can:

- Add your own `Test-*` functions that return the same object layout.
- Adjust severities (`Severity = "HIGH" | "MEDIUM" | "LOW"`) to mirror your internal risk model.
- Compare the output with PingCastle reports by matching risk names or categories.

---

## 6. Scheduling and Automation

To run the checks regularly, you can schedule a script that imports the module, runs the desired tests, and exports to CSV / HTML / your monitoring system.

Example scheduled-task script:

```powershell
Import-Module ADSecurityMonitor

$timestamp = Get-Date -Format yyyyMMdd-HHmm
$outDir    = "C:\Reports"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# Example using a wrapper – adjust if you run tests manually
$csvPath  = Join-Path $outDir "ADSecurity-$timestamp.csv"
$results  = Invoke-ADSecurityAudit -Severity All
$results  | Export-Csv $csvPath -NoTypeInformation

# Optionally: custom HTML or other export
# Export-ADSecurityReport -OutputPath (Join-Path $outDir "ADSecurityReport-$timestamp.html")
```

Then configure a scheduled task to run:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\Run-ADSecurityAudit.ps1
```

---

## 7. Requirements / Notes

- Run from a host with:
  - RSAT / AD DS tools (`ActiveDirectory` module) installed.
  - Appropriate admin rights (Domain Admin or equivalent is often required).
- Some checks rely on:
  - Remote registry access
  - WMI / CIM (e.g. `Get-WmiObject`, `Get-BitLockerVolume`, `Get-SmbServerConfiguration`)
  - Network/firewall access from the management host to all domain controllers
- Optional / environment-specific dependencies:
  - DNS / DHCP / DFSR / Exchange / AD CS tools for specialized checks.

---

## 8. Extending the Module

To add new checks:

1. Create a `Test-*` function in `ADSecurityMonitor.psm1`.
2. Return a single `PSCustomObject` with at least:

   ```powershell
   [PSCustomObject]@{
       CheckName      = "Your Check Name"
       Severity       = "HIGH"  # or MEDIUM / LOW
       Status         = "PASS"  # or FAIL / WARN / INFO / ERROR
       Recommendation = "What to do if this fails"
       Risk           = "Why this matters"
       # Any other details helpful for triage
   }
   ```

3. Optionally add your new function into any wrapper/orchestrator function (e.g. `Invoke-ADSecurityAudit`) so that it runs as part of the normal audit.

To add remediation helpers:

1. Implement a `Repair-*` / `Invoke-*Remediation` function alongside the relevant `Test-*`.
2. Ensure it is:
   - Idempotent where possible.
   - Safe to run with `-WhatIf` / `-Confirm`.
   - Well-documented via `Get-Help`.
3. Reference it from the related `Test-*` function’s `Recommendation` text so operators know a helper exists.

This approach keeps the module easy to maintain while allowing you to tailor it to your environment’s specific risks and to automate both **detection** and **remediation** in a controlled way.