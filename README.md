# ADSecurityHealth Toolkit

A PowerShell toolkit to monitor Active Directory security and health, inspired by PingCastle checks. Includes 20 functions covering privileged membership, stale accounts, password policy, delegation, replication, DNS/SYSVOL health, trusts, GPOs, SPNs, audit policies, and event log configuration.

## Features

- **Comprehensive Comment-Based Help**: All functions include detailed synopsis, description, parameters, and examples
- **Robust Error Handling**: Try-catch blocks throughout with graceful degradation
- **Detailed Logging**: Verbose logging using Write-ADSHVerbose for troubleshooting
- **Parameter Validation**: ValidateSet, ValidateRange, and ValidateNotNullOrEmpty attributes
- **Unit Tests**: Pester tests included for validation of core functionality

## Prerequisites

- Windows PowerShell 5.1 (or PowerShell 7 with Windows remoting)
- RSAT components:
  - ActiveDirectory module
  - GroupPolicy module
- Permissions:
  - Read access across the domain
  - Remote access to domain controllers for service, log, and file queries

## Installation

1. Copy `ADSecurityHealth.psm1` and `adsh-config.json` to a folder.
2. Import the module:

```powershell
Import-Module .\ADSecurityHealth.psm1
```

3. Optional: Adjust thresholds in `adsh-config.json`.

## Testing

Run the included Pester tests to validate functionality:

```powershell
# Install Pester if needed
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run tests
Invoke-Pester -Path .\AdSecurityHealth.Tests.ps1
```

Tests cover:
- Helper function validation
- Parameter validation ranges
- Error handling scenarios
- Module structure and documentation
- Integration testing with mocked AD cmdlets

## Usage

Run all checks and create reports:

```powershell
.\Run-ADSecurityHealth.ps1
```

Or invoke specific checks:

```powershell
Get-PrivilegedGroupMembership -Groups 'Domain Admins','Enterprise Admins'
Get-StaleAccounts -StaleDays 60
Get-DNSHealth -TimeoutSeconds 120
Invoke-ADSecurityHealthCheck -IncludeRawEvidence
```

## Implementation Tips

- Modular design: Each check is a function returning a standardized finding object.
- Configurable thresholds: Edit `adsh-config.json` for stale days, log sizes, etc.
- Scheduling: Use Task Scheduler to run `Run-ADSecurityHealth.ps1` daily/weekly.
- Least privileges: For DC remote queries, run as an account with necessary rights.
- Error handling: Functions use try/catch and continue; evidence includes failures.
- Reporting:
  - JSON: easy to ingest into dashboards/SIEM.
  - HTML: quick human-readable summary.
- Alerting: Integrate email or Teams/Slack notifications by scanning for `Severity -in 'High','Critical'`.
- Performance:
  - Scope queries with `-Server` or site-based targeting if needed.
  - Prefer `LDAPFilter` for efficient AD queries.
- Remediation guidance: Each finding includes a remediation hint; extend per your standards.
- Source control: Store the module and config in Git; use CI to run linting/tests.
- Security:
  - Use JEA (Just Enough Administration) to limit function execution contexts.
  - Log script usage to a central repository.

## Notes

Some checks (e.g., reversible encryption policy) depend on FGPP and may vary by environment. GPO analysis leverages XML reports for portability. Adjust remote paths (e.g., `C:\Windows\NTDS\ntds.dit`) if your DCs use custom locations.

Contributions welcome.