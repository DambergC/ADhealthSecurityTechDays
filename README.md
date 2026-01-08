# ADSecurityHealth Toolkit - Complete Edition

A comprehensive PowerShell toolkit for Active Directory security and health monitoring, inspired by PingCastle.  **Version 2.0** includes **60+ security functions** covering threat detection, configuration auditing, health monitoring, and compliance checks.

## 🎯 Overview

ADSecurityHealth provides enterprise-grade Active Directory monitoring with: 
- **60+ security and health check functions**
- **Automated threat detection** (SID history, AS-REP roasting, weak encryption)
- **Configuration drift detection**
- **Compliance reporting** (password policies, audit settings, encryption standards)
- **HTML/JSON/CSV reporting** with severity-based prioritization
- **Scheduled execution** support via Task Scheduler

## 📊 Function Categories

### 🔒 Security Functions (20)

| # | Function | Description | Severity |
|---|----------|-------------|----------|
| 1 | `Get-PrivilegedGroupMembership` | Audit Domain Admins, Enterprise Admins, etc. | High |
| 2 | `Get-StaleAccounts` | Identify inactive enabled user accounts | Medium-High |
| 3 | `Get-PasswordPolicyAudit` | Review domain and FGPP password policies | Medium |
| 4 | `Get-AccountsPasswordNeverExpires` | Find accounts with non-expiring passwords | High |
| 5 | `Get-AccountsReversibleEncryption` | Detect reversible encryption in policies | High |
| 6 | `Get-KerberosDelegationIssues` | Unconstrained/constrained delegation risks | High |
| 7 | `Get-AdminSDHolderProtectedAccounts` | AdminCount=1 accounts (persistence risk) | Medium |
| 8 | `Get-ExcessivePermissionsDelegations` | Risky ACLs (GenericAll, WriteOwner, WriteDacl) | High |
| 9 | `Get-PreWin2000AccessRisks` | Pre-Windows 2000 Compatible Access members | Medium |
| 10 | `Get-SPNAudit` | Duplicate SPNs and Kerberoasting targets | Medium |

### 🏥 Health & Operations (10)

| # | Function | Description | Severity |
|---|----------|-------------|----------|
| 11 | `Get-DCReplicationStatus` | Domain controller replication health | High |
| 12 | `Get-DNSHealth` | DNS configuration via dcdiag | High |
| 13 | `Get-SYSVOLReplicationStatus` | DFSR vs FRS status | High |
| 14 | `Get-FSMORoleHolders` | Current FSMO role holders | Info |
| 15 | `Get-DCServiceStatus` | Critical service status (NTDS, KDC, DNS) | High |
| 16 | `Get-ADDatabaseStats` | NTDS. dit size and growth tracking | Info |
| 17 | `Get-TrustRelationships` | Domain and forest trust audit | Medium |
| 18 | `Get-GPOReview` | Orphaned and misconfigured GPOs | Medium |
| 19 | `Get-AuditPolicyVerification` | Audit policy coverage on DCs | Medium |
| 20 | `Get-SecurityEventLogConfig` | Security log size and retention | Medium |

### 🎯 Advanced Threat Detection (20)

| # | Function | Description | Severity |
|---|----------|-------------|----------|
| 21 | `Get-SuspiciousSIDHistory` | SID History privilege escalation | High |
| 22 | `Get-PrivilegedAccountPasswordAge` | Old passwords on admin accounts | High |
| 23 | `Get-WeakEncryptionTypes` | DES/RC4 Kerberos downgrade risks | High |
| 24 | `Get-LAPSCoverage` | Local admin password solution coverage | High |
| 25 | `Get-ProtectedUsersGroupMembership` | Protected Users group audit | Medium |
| 26 | `Get-KrbtgtPasswordAge` | Krbtgt password age (Golden Ticket) | Critical |
| 27 | `Get-CertificateTemplatePermissions` | ADCS ESC vulnerabilities | Critical |
| 28 | `Get-NTLMAuthenticationUsage` | Legacy NTLM authentication tracking | Medium |
| 29 | `Get-AnonymousLDAPBind` | Anonymous LDAP enumeration vectors | High |
| 30 | `Get-DCPatchLevel` | Domain controller patch currency | High |
| 31 | `Get-TombstoneLifetime` | Tombstone configuration (backup safety) | High |
| 32 | `Get-InactiveComputerAccounts` | Stale computer accounts | Medium |
| 33 | `Get-SMBSigningDC` | SMB signing relay protection | High |
| 34 | `Get-PrivilegedLogonToWorkstations` | Tiering violations (SIEM required) | Medium |
| 35 | `Get-PrintSpoolerOnDCs` | PrintNightmare mitigation | High |
| 36 | `Get-AccountLockoutPolicy` | Brute-force protection | Medium |
| 37 | `Get-ASREPRoastableAccounts` | Accounts without Kerberos pre-auth | High |
| 38 | `Get-DnsAdminsGroupMembership` | DnsAdmins privilege escalation vector | High |
| 39 | `Get-RODCPasswordReplicationPolicy` | RODC credential exposure | Medium |
| 40 | `Get-ADRecycleBinStatus` | AD Recycle Bin enabled status | Medium |

### 🔍 Critical Security Checks (10)

| # | Function | Description | Severity |
|---|----------|-------------|----------|
| 41 | `Get-DCOMPermissions` | DCOM attack surface audit | High |
| 42 | `Get-GPOOwnershipAudit` | Hijacked GPO detection | High |
| 43 | `Get-DNSZoneTransferSettings` | DNS zone security | High |
| 44 | `Get-DHCPAuthorization` | Rogue DHCP detection | Medium |
| 45 | `Get-DomainTrustSIDFiltering` | Trust SID filtering bypass risks | High |
| 46 | `Get-AdminShareExposure` | C$/ADMIN$ enumeration risks | Medium |
| 47 | `Get-LDAPSigningEnforcement` | LDAP channel binding | High |
| 48 | `Get-NetBIOSConfiguration` | Legacy protocol exposure | Medium |
| 49 | `Get-AccountOperatorsPrivileges` | Account Operators audit | High |
| 50 | `Get-BackupOperatorsAudit` | Backup Operators privilege abuse | High |

### ☁️ Cloud Hybrid Monitoring (10)

| # | Function | Description | Severity |
|---|----------|-------------|----------|
| 51 | `Get-AADConnectHealth` | Azure AD Connect sync status | High |
| 52 | `Get-AADConnectConfiguration` | Sync configuration security audit | Medium |
| 53 | `Get-AADConnectPermissions` | Connector account permissions | High |
| 54 | `Get-EntraIDPasswordHashSync` | PHS configuration and status | Medium |
| 55 | `Get-EntraIDPassThroughAuth` | PTA agent health | Medium |
| 56 | `Get-ADFSFarmHealth` | ADFS server and certificate status | High |
| 57 | `Get-CloudOnlyAccounts` | Cloud-only vs synced users | Info |
| 58 | `Get-HybridJoinStatus` | Azure AD hybrid join health | Medium |
| 59 | `Get-ConditionalAccessGaps` | Unprotected accounts | High |
| 60 | `Get-EntraIDPrivilegedRoles` | Map to on-prem privileged accounts | High |

## 🚀 Quick Start

### Prerequisites

```powershell
# Windows PowerShell 5.1 or PowerShell 7+
# Required modules (install via RSAT)
Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-DNS-Server, RSAT-ADCS

# Or on Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management. Tools~~~~0.0.1.0
```

### Installation

```powershell
# Clone or download repository
git clone https://github.com/DambergC/ADhealthSecurityTechDays.git
cd ADhealthSecurityTechDays

# Import module
Import-Module .\ADSecurityHealth-Complete. psm1 -Force
```

### Basic Usage

```powershell
# Run all 60+ checks
.\Run-ADSecurityHealth-AllChecks.ps1

# Run specific function
Get-PrivilegedGroupMembership -Groups 'Domain Admins', 'Enterprise Admins'

# Run with verbose logging
Get-StaleAccounts -StaleDays 60 -Verbose

# Run baseline checks only (1-20)
Invoke-ADSecurityHealthCheck

# Run advanced checks (21-40)
Invoke-ADSecurityHealthCheckAdvanced

# Run all checks programmatically
$findings = Invoke-ADSecurityHealthCheckComplete -IncludeRawEvidence
```

## 📈 Reporting

### Generated Reports

The runner script creates multiple report formats:

#### 1. **HTML Dashboard** (`adsh-report.html`)
- Color-coded severity indicators
- Sortable/filterable findings
- Executive summary with statistics
- Remediation guidance links

#### 2. **JSON Export** (`adsh-findings.json`)
- Complete findings with evidence
- SIEM/automation integration ready
- Timestamped entries

#### 3. **CSV Summary** (`adsh-summary.csv`)
- Spreadsheet-compatible format
- Easy filtering and pivoting
- Suitable for tracking over time

#### 4. **Executive Summary** (`adsh-executive-summary.txt`)
- High-level overview
- Critical/High findings count
- Top 10 risks

### Report Structure

```json
{
  "Timestamp": "2026-01-08T10:30:00Z",
  "Category": "Security",
  "Id": "KRBTGT-AGE",
  "Severity":  "Critical",
  "Title": "Krbtgt password age exceeds 180 days",
  "Description": "Krbtgt password is 547 days old.. .",
  "Evidence": { ... },
  "Remediation": "Reset krbtgt password using Microsoft script..."
}
```

## 🔧 Configuration

Edit `adsh-config.json` to customize thresholds:

```json
{
  "StaleDays": 90,
  "ComputerStaleDays": 90,
  "KrbtgtMaxPasswordAgeDays": 180,
  "PrivilegedAccountMaxPasswordAgeDays": 90,
  "DCPatchMaxAgeDays": 60,
  "TombstoneMinDays": 180,
  "LAPSMinCoveragePercent": 90,
  "EventLogMinSizeMB": 2048,
  "SensitiveGroups": [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins"
  ],
  "CriticalServices": [
    "NTDS",
    "KDC",
    "DNS",
    "Netlogon",
    "LanmanServer",
    "DFSR"
  ],
  "AlertEmail": "soc@company.com"
}
```

## 📅 Scheduled Execution

### Task Scheduler Setup

```powershell
# Create scheduled task (daily at 2 AM)
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ADSecurityHealth\Run-ADSecurityHealth-AllChecks.ps1"'

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\ADHealthSvc" -LogonType Password -RunLevel Highest

Register-ScheduledTask -TaskName "AD Security Health Check" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Daily AD security and health monitoring"
```

### Email Alerts

```powershell
# Configure email alerts for Critical/High findings
$findings = Invoke-ADSecurityHealthCheckComplete
$critical = $findings | Where-Object { $_.Severity -in @('Critical','High') }

if ($critical) {
    $body = $critical | ConvertTo-Html -Fragment | Out-String
    Send-MailMessage -From 'adhealthcheck@domain.com' `
        -To 'soc@domain.com' `
        -Subject "[$($critical.Count)] Critical AD Security Findings" `
        -Body $body -BodyAsHtml `
        -SmtpServer 'smtp.domain.com'
}
```

## 🎨 Sample Output

```
================================================================
AD SECURITY HEALTH CHECK - COMPLETE SCAN
================================================================
Scan Started: 2026-01-08 10:30:15
Domain:  CONTOSO.COM
DCs Found: 4

[✓] Baseline Checks (1-20)............ 20/20 complete
[✓] Advanced Checks (21-40)........... 20/20 complete
[✓] Critical Checks (41-50)........... 10/10 complete
[✓] Cloud Hybrid Checks (51-60)....... 10/10 complete

================================================================
FINDINGS SUMMARY
================================================================
Total Findings:     156
Critical:           3   [!!! ]
High:              12  [!! ]
Medium:            34  [! ]
Low:               7
Info:              100

================================================================
TOP CRITICAL FINDINGS
================================================================
[CRITICAL] KRBTGT-AGE:  Krbtgt password is 547 days old
[CRITICAL] CERT-TMPL:  Certificate template vulnerable to ESC1
[CRITICAL] SIDHIST: 5 accounts with suspicious SID History

================================================================
Reports Generated
================================================================
HTML:     C:\ADSecurityHealth\reports\adsh-report-20260108.html
JSON:    C:\ADSecurityHealth\reports\adsh-findings-20260108.json
CSV:      C:\ADSecurityHealth\reports\adsh-summary-20260108.csv
Executive: C:\ADSecurityHealth\reports\adsh-executive-20260108.txt

Scan completed in 8m 34s
================================================================
```

## 🔐 Security Considerations

### Permissions Required

- **Domain Users**: Basic read access (limited functionality)
- **Recommended**: Domain Admins or equivalent for full checks
- **Minimum**: Account with read access to: 
  - AD objects and attributes
  - GPO read permissions
  - Remote access to DCs (for service/log checks)
  - PKI configuration (for certificate checks)

### Data Sensitivity

Reports contain sensitive security information:
- ✅ Store reports in secured location
- ✅ Encrypt reports at rest
- ✅ Limit access to SOC/security team
- ✅ Implement retention policies
- ❌ Do not email unencrypted reports
- ❌ Do not store in public repositories

## 📊 Performance

| Environment Size | Execution Time | Memory Usage |
|-----------------|----------------|--------------|
| Small (1 DC, <1K users) | 2-5 minutes | ~200 MB |
| Medium (3 DCs, 5K users) | 5-10 minutes | ~400 MB |
| Large (10 DCs, 50K users) | 10-20 minutes | ~800 MB |
| Enterprise (50+ DCs, 200K users) | 20-45 minutes | ~1.5 GB |

### Optimization Tips

```powershell
# Target specific DC for queries
Get-PrivilegedGroupMembership -Server 'DC01.domain.com'

# Run checks in parallel (PowerShell 7+)
$baseline = Start-Job { Invoke-ADSecurityHealthCheck }
$advanced = Start-Job { Invoke-ADSecurityHealthCheckAdvanced }
$results = Receive-Job $baseline,$advanced -Wait

# Exclude slow checks
# Edit Run-ADSecurityHealth-AllChecks.ps1 and comment out: 
# - Get-DNSHealth (uses dcdiag, slow on large domains)
# - Get-GPOReview (slow with 1000+ GPOs)
```

## 🐛 Troubleshooting

### Common Issues

**Error: "Module ActiveDirectory not found"**
```powershell
# Install RSAT Active Directory module
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory. DS-LDS.Tools~~~~0.0.1.0
```

**Error: "Access Denied" on DC queries**
```powershell
# Ensure executing account has: 
# - Domain admin rights OR
# - WinRM/PowerShell remoting enabled + admin on DCs
Test-WSMan -ComputerName DC01
```

**Error: "Invoke-Command :  The WinRM client cannot process the request"**
```powershell
# Enable CredSSP or run directly on DC
Enable-WSManCredSSP -Role Client -DelegateComputer "*. domain.com" -Force
```

**Slow execution (>30 minutes)**
```powershell
# Run with -Verbose to identify bottleneck
Invoke-ADSecurityHealthCheckComplete -Verbose

# Common slow checks:
# - Get-DNSHealth (dcdiag timeout)
# - Get-GPOReview (many GPOs)
# - Get-DCReplicationStatus (many DCs)
```

## 📚 Advanced Usage

### Custom Checks

```powershell
# Create custom check function
function Get-CustomSecurityCheck {
    [CmdletBinding()]
    param()
    
    $evidence = Get-ADUser -Filter 'Department -eq "IT"' -Properties Department
    
    New-ADSHFinding -Category 'Custom' -Id 'CUSTOM-001' -Severity 'Medium' `
        -Title "Custom IT department audit" `
        -Description "Review IT department user accounts" `
        -Evidence $evidence `
        -Remediation "Validate IT user access levels"
}

# Run custom check
$findings = Invoke-ADSecurityHealthCheckComplete
$findings += Get-CustomSecurityCheck
```

### Integration with SIEM

```powershell
# Export findings to JSON for SIEM ingestion
$findings = Invoke-ADSecurityHealthCheckComplete
$findings | ConvertTo-Json -Depth 10 | Out-File siem-export.json

# Splunk HTTP Event Collector (HEC)
$splunkUrl = "https://splunk.domain.com:8088/services/collector"
$splunkToken = "your-hec-token"
$findings | ForEach-Object {
    $body = @{
        event = $_
        sourcetype = "ad: security: health"
    } | ConvertTo-Json
    Invoke-RestMethod -Uri $splunkUrl -Method Post -Headers @{Authorization="Splunk $splunkToken"} -Body $body
}

# Azure Sentinel / Log Analytics
$workspaceId = "your-workspace-id"
$sharedKey = "your-shared-key"
# Use Azure Monitor Data Collector API
```

### Filtering and Analysis

```powershell
# Get only Critical/High severity findings
$critical = $findings | Where-Object { $_.Severity -in @('Critical','High') }

# Group by category
$findings | Group-Object Category | Select-Object Name, Count

# Find specific issues
$findings | Where-Object { $_.Id -like 'KRBTGT*' }

# Export specific category to CSV
$findings | Where-Object { $_.Category -eq 'ThreatDetection' } | 
    Export-Csv -Path threat-findings.csv -NoTypeInformation
```

## 🔄 Version History

### Version 2.0.0 (2026-01-08)
- ✨ Added 40 new advanced security functions (21-60)
- ✨ Cloud hybrid monitoring (Azure AD Connect, ADFS)
- ✨ Critical security checks (DCOM, DNS zones, trusts)
- ✨ Enhanced reporting (HTML dashboard, executive summary)
- ✨ Improved configuration management
- 🐛 Fixed replication metadata errors on read-only DCs
- 📚 Complete documentation overhaul

### Version 1.0.0 (2025-12-15)
- Initial release with 20 baseline functions
- JSON/HTML reporting
- Configuration file support
- Pester tests

## 🤝 Contributing

Contributions welcome! Areas for enhancement:

1. **Additional Checks**:  Suggest new security/health functions
2. **Performance**:  Optimize slow queries for large environments
3. **Reporting**: Enhanced visualizations, dashboards
4. **Integrations**:  SIEM connectors, ticketing systems
5. **Remediation**: Safe automation for common fixes

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by [PingCastle](https://www.pingcastle.com/) by Vincent LE TOUX
- Microsoft Active Directory security best practices
- ANSSI AD security recommendations
- MITRE ATT&CK framework

## 📞 Support

- **Issues**: https://github.com/DambergC/ADhealthSecurityTechDays/issues
- **Discussions**: https://github.com/DambergC/ADhealthSecurityTechDays/discussions
- **Email**: support@yourdomain.com

## 🔗 Related Resources

- [Microsoft AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices)
- [MITRE ATT&CK - Active Directory](https://attack.mitre.org/matrices/enterprise/)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD relationship mapping
- [Purple Knight](https://www.purple-knight.com/) - AD security assessment

---

**Made with ❤️ for Active Directory security professionals**

*Last updated: 2026-01-08*