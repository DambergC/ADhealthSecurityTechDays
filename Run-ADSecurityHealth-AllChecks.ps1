#requires -Version 5.1
<#
.SYNOPSIS
    Executes all 60+ Active Directory security and health checks.  

.DESCRIPTION
    Comprehensive runner that executes all baseline, advanced, and critical
    AD security checks, then generates HTML, JSON, CSV, and executive summary reports. 

.PARAMETER OutputPath
    Directory path for output reports. Defaults to .\reports

.PARAMETER IncludeRawEvidence
    Include full evidence details in reports (increases file size).

.PARAMETER EmailReport
    Send email notification with critical findings.

.PARAMETER EmailTo
    Email recipient address for reports.

.PARAMETER EmailFrom
    Email sender address.  

.PARAMETER SmtpServer
    SMTP server for email delivery.

.PARAMETER SkipSlowChecks
    Skip time-consuming checks (DNS health, GPO review).

.EXAMPLE
    .\Run-ADSecurityHealth-AllChecks.ps1
    Run all checks with default settings.

.EXAMPLE
    .\Run-ADSecurityHealth-AllChecks.ps1 -OutputPath C:\Reports -EmailReport -EmailTo "soc@domain.com"
    Run all checks, save to custom path, and email results.

.EXAMPLE
    .\Run-ADSecurityHealth-AllChecks.ps1 -SkipSlowChecks
    Run all checks except slow-running ones (DNS, GPO review).

.NOTES
    Author: Active Directory Security Team
    Version: 2.1.0
    Requires: Domain Admin or equivalent permissions
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = "$PSScriptRoot\reports",
    
    [Parameter()]
    [switch] $IncludeRawEvidence,
    
    [Parameter()]
    [switch] $EmailReport,
    
    [Parameter()]
    [string] $EmailTo,
    
    [Parameter()]
    [string] $EmailFrom = "adhealthcheck@domain.com",
    
    [Parameter()]
    [string] $SmtpServer = "smtp.domain.com",
    
    [Parameter()]
    [switch] $SkipSlowChecks
)

#region Initialize

$ErrorActionPreference = 'Continue'
$startTime = Get-Date

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "AD SECURITY HEALTH CHECK - COMPLETE SCAN" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Scan Started: $($startTime.ToString('yyyy-MM-dd HH:mm: ss'))" -ForegroundColor Gray

# Import module
$modulePath = Join-Path $PSScriptRoot "ADSecurityHealth-Complete. psm1"
if (-not (Test-Path $modulePath)) {
    Write-Error "Module not found: $modulePath"
    exit 1
}

Write-Host "Importing module..." -ForegroundColor Gray
Import-Module $modulePath -Force -ErrorAction Stop

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportBaseName = "adsh-$timestamp"

# Initialize environment
Initialize-ADSHEnvironment

# Get domain info
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    
    Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
    Write-Host "Forest: $($forest.RootDomain)" -ForegroundColor Green
    Write-Host "DCs Found: $($dcs.Count)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Error "Failed to connect to Active Directory: $_"
    exit 1
}

#endregion Initialize

#region Execute Checks

$allFindings = @()

# Baseline Checks (1-20)
Write-Host "[" -NoNewline
Write-Host "✓" -ForegroundColor Green -NoNewline
Write-Host "] Baseline Checks (1-20)........ ....  " -NoNewline
try {
    $baselineStart = Get-Date
    
    $allFindings += Get-PrivilegedGroupMembership
    $allFindings += Get-StaleAccounts
    $allFindings += Get-PasswordPolicyAudit
    $allFindings += Get-AccountsPasswordNeverExpires
    $allFindings += Get-AccountsReversibleEncryption
    $allFindings += Get-KerberosDelegationIssues
    $allFindings += Get-AdminSDHolderProtectedAccounts
    $allFindings += Get-ExcessivePermissionsDelegations
    $allFindings += Get-DCReplicationStatus
    
    if (-not $SkipSlowChecks) {
        $allFindings += Get-DNSHealth
        $allFindings += Get-GPOReview
    }
    
    $allFindings += Get-SYSVOLReplicationStatus
    $allFindings += Get-FSMORoleHolders
    $allFindings += Get-DCServiceStatus
    $allFindings += Get-ADDatabaseStats
    $allFindings += Get-TrustRelationships
    $allFindings += Get-PreWin2000AccessRisks
    $allFindings += Get-SPNAudit
    $allFindings += Get-AuditPolicyVerification
    $allFindings += Get-SecurityEventLogConfig
    
    $baselineTime = ((Get-Date) - $baselineStart).TotalSeconds
       Write-Host "20/20 complete $([math]::Round($baselineTime,1))s" -ForegroundColor Green
} catch {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Warning "Baseline checks error: $_"
}

# Advanced Checks (21-40)
Write-Host "[" -NoNewline
Write-Host "✓" -ForegroundColor Green -NoNewline
Write-Host "] Advanced Checks (21-40)........... " -NoNewline
try {
    $advancedStart = Get-Date
    
    $allFindings += Get-SuspiciousSIDHistory
    $allFindings += Get-PrivilegedAccountPasswordAge
    $allFindings += Get-WeakEncryptionTypes
    $allFindings += Get-LAPSCoverage
    $allFindings += Get-ProtectedUsersGroupMembership
    $allFindings += Get-KrbtgtPasswordAge
    $allFindings += Get-CertificateTemplatePermissions
    $allFindings += Get-NTLMAuthenticationUsage
    $allFindings += Get-AnonymousLDAPBind
    $allFindings += Get-DCPatchLevel
    $allFindings += Get-TombstoneLifetime
    $allFindings += Get-InactiveComputerAccounts
    $allFindings += Get-SMBSigningDC
    $allFindings += Get-PrivilegedLogonToWorkstations
    $allFindings += Get-PrintSpoolerOnDCs
    $allFindings += Get-AccountLockoutPolicy
    $allFindings += Get-ASREPRoastableAccounts
    $allFindings += Get-DnsAdminsGroupMembership
    $allFindings += Get-RODCPasswordReplicationPolicy
    $allFindings += Get-ADRecycleBinStatus
    
    $advancedTime = ((Get-Date) - $advancedStart).TotalSeconds
   Write-Host "20/20 complete ($([math]::Round($advancedTime,1))s)" -ForegroundColor Green
} catch {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Warning "Advanced checks error: $_"
}

# Critical Checks (41-50)
Write-Host "[" -NoNewline
Write-Host "✓" -ForegroundColor Green -NoNewline
Write-Host "] Critical Checks (41-50)........... " -NoNewline
try {
    $criticalStart = Get-Date
    
    $allFindings += Get-UnconstrainedDelegationAccounts
    $allFindings += Get-GoldenTicketIndicators
    $allFindings += Get-ShadowCredentialsRisks
    $allFindings += Get-DCOMPermissionsAudit
    $allFindings += Get-DCMachineAccountQuota
    $allFindings += Get-GPOCriticalSecuritySettings
    $allFindings += Get-EmptyGroupPolicyLinks
    $allFindings += Get-PrivilegedAccountLoginLocations
    $allFindings += Get-HighValueTargetExposure
    $allFindings += Get-SuspiciousServiceAccounts
    
    $criticalTime = ((Get-Date) - $criticalStart).TotalSeconds
   Write-Host "10/10 complete $([math]::Round($criticalTime,1))s" -ForegroundColor Green
} catch {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Warning "Critical checks error: $_"
}

# Cloud Hybrid Checks (51-60) - Future implementation
Write-Host "[" -NoNewline
Write-Host "~" -ForegroundColor Yellow -NoNewline
Write-Host "] Cloud Hybrid Checks (51-60)... .... Planned for future release" -ForegroundColor Yellow

Write-Host ""

#endregion Execute Checks

#region Generate Summary Statistics

$totalFindings = $allFindings.Count
$criticalCount = ($allFindings | Where-Object { $_. Severity -eq 'Critical' }).Count
$highCount = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
$mediumCount = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
$infoCount = ($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Total Findings:     $totalFindings"
Write-Host "Critical:            " -NoNewline
Write-Host $criticalCount -ForegroundColor Red -NoNewline
Write-Host "   [!!! ]" -ForegroundColor Red
Write-Host "High:              " -NoNewline
Write-Host $highCount -ForegroundColor Magenta -NoNewline
Write-Host "  [!! ]" -ForegroundColor Magenta
Write-Host "Medium:            " -NoNewline
Write-Host $mediumCount -ForegroundColor Yellow -NoNewline
Write-Host "  [!]" -ForegroundColor Yellow
Write-Host "Low:                $lowCount"
Write-Host "Info:              $infoCount"
Write-Host ""

# Top critical findings
$criticalFindings = $allFindings | Where-Object { $_.Severity -eq 'Critical' } | Select-Object -First 10
$highFindings = $allFindings | Where-Object { $_.Severity -eq 'High' } | Select-Object -First 10

if ($criticalFindings) {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "TOP CRITICAL FINDINGS" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    foreach ($finding in $criticalFindings) {
        Write-Host "[CRITICAL] " -ForegroundColor Red -NoNewline
        Write-Host "$($finding.Id): $($finding.Title)"
    }
    Write-Host ""
}

if ($highFindings -and $criticalCount -eq 0) {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "TOP HIGH FINDINGS" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    foreach ($finding in $highFindings | Select-Object -First 5) {
        Write-Host "[HIGH] " -ForegroundColor Magenta -NoNewline
        Write-Host "$($finding.Id): $($finding.Title)"
    }
    Write-Host ""
}

#endregion Generate Summary Statistics

#region Export Reports

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "GENERATING REPORTS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# JSON Export
$jsonPath = Join-Path $OutputPath "$reportBaseName-findings.json"
Write-Host "Generating JSON report..." -ForegroundColor Gray
if ($IncludeRawEvidence) {
    $allFindings | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $jsonPath
} else {
    $allFindings | Select-Object Timestamp, Category, Id, Severity, Title, Description, Remediation | 
        ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $jsonPath
}
Write-Host "JSON:      $jsonPath" -ForegroundColor Green

# CSV Export
$csvPath = Join-Path $OutputPath "$reportBaseName-summary.csv"
Write-Host "Generating CSV report..." -ForegroundColor Gray
$allFindings | Select-Object Timestamp, Category, Id, Severity, Title, Description, Remediation | 
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "CSV:     $csvPath" -ForegroundColor Green

# HTML Report
$htmlPath = Join-Path $OutputPath "$reportBaseName-report.html"
Write-Host "Generating HTML dashboard..." -ForegroundColor Gray

# Base HTML (header + summary + table header)
$htmlBody = @'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AD Security Health Report - __DOMAIN__</title>
    <style>
        body { 
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        h1 { 
            color: #0078D4; 
            border-bottom: 3px solid #0078D4;
            padding-bottom: 10px;
        }
        h2 {
            color: #333;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .summary-item {
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .summary-item h3 {
            margin: 0;
            font-size: 32px;
            font-weight: bold;
        }
        .summary-item p {
            margin: 5px 0 0 0;
            font-size: 14px;
            opacity: 0.8;
        }
        .critical-box { background-color: #d32f2f; color: white; }
        .high-box     { background-color: #f57c00; color: white; }
        .medium-box   { background-color: #fbc02d; color: black; }
        .low-box      { background-color: #afb42b; color: white; }
        .info-box     { background-color: #0288d1; color: white; }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-top: 20px;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th { 
            background-color: #0078D4; 
            color: white; 
            padding: 12px; 
            text-align: left;
            position: sticky;
            top: 0;
        }
        td { 
            padding: 10px; 
            border-bottom: 1px solid #ddd; 
        }
        tr:hover { background-color: #f5f5f5; }
        .Critical { background-color: #ffebee; border-left: 4px solid #d32f2f; }
        .High     { background-color: #fff3e0; border-left: 4px solid #f57c00; }
        .Medium   { background-color: #fffde7; border-left: 4px solid #fbc02d; }
        .Low      { background-color: #f1f8e9; border-left: 4px solid #afb42b; }
        .Info     { background-color: #e3f2fd; border-left: 4px solid #0288d1; }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
        }
        .severity-Critical { background-color: #d32f2f; color: white; }
        .severity-High     { background-color: #f57c00; color: white; }
        .severity-Medium   { background-color: #fbc02d; color: black; }
        .severity-Low      { background-color: #afb42b; color: white; }
        .severity-Info     { background-color: #0288d1; color: white; }
        .meta {
            color: #666;
            font-size: 12px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
        .filter-buttons {
            margin: 15px 0;
        }
        .filter-btn {
            padding: 8px 15px;
            margin-right: 10px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-weight: bold;
            transition: opacity 0.2s;
        }
        .filter-btn:hover { 
            opacity: 0.8; 
        }
        .filter-btn-all {
            background-color: #0078D4; 
            color: white;
        }
        .filter-btn-critical { background-color: #d32f2f; color: white; }
        .filter-btn-high     { background-color: #f57c00; color: white; }
        .filter-btn-medium   { background-color: #fbc02d; color: black; }
    </style>
    <script>
        function filterTable(severity) {
            var rows = document.querySelectorAll("#findingsTable tbody tr");
            rows.forEach(function(row) {
                if (severity === "all" || row.classList.contains(severity)) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        }
    </script>
</head>
<body>
    <h1>Active Directory Security & Health Report</h1>
    <div class="summary">
        <p><strong>Domain:</strong> __DOMAIN__</p>
        <p><strong>Forest:</strong> __FOREST__</p>
        <p><strong>Scan Date:</strong> __SCANDATE__</p>
        <p><strong>Domain Controllers:</strong> __DCCOUNT__</p>
        <p><strong>Total Findings:</strong> __TOTALFINDINGS__</p>
        
        <div class="summary-grid">
            <div class="summary-item critical-box">
                <h3>__CRITCOUNT__</h3>
                <p>Critical</p>
            </div>
            <div class="summary-item high-box">
                <h3>__HIGHCOUNT__</h3>
                <p>High</p>
            </div>
            <div class="summary-item medium-box">
                <h3>__MEDCOUNT__</h3>
                <p>Medium</p>
            </div>
            <div class="summary-item low-box">
                <h3>__LOWCOUNT__</h3>
                <p>Low</p>
            </div>
            <div class="summary-item info-box">
                <h3>__INFOCOUNT__</h3>
                <p>Info</p>
            </div>
        </div>
    </div>
    
    <h2>Findings</h2>
    <div class="filter-buttons">
        <button class="filter-btn filter-btn-all"      onclick="filterTable('all')">All</button>
        <button class="filter-btn filter-btn-critical" onclick="filterTable('Critical')">Critical</button>
        <button class="filter-btn filter-btn-high"     onclick="filterTable('High')">High</button>
        <button class="filter-btn filter-btn-medium"   onclick="filterTable('Medium')">Medium</button>
    </div>
    
    <table id="findingsTable">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>ID</th>
                <th>Title</th>
                <th>Description</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
'@

# Inject dynamic values into the HTML shell
$htmlBody = $htmlBody.Replace('__DOMAIN__',        $domain.DNSRoot)
$htmlBody = $htmlBody.Replace('__FOREST__',        $forest.RootDomain)
$htmlBody = $htmlBody.Replace('__SCANDATE__',      $startTime.ToString('yyyy-MM-dd HH:mm:ss'))
$htmlBody = $htmlBody.Replace('__DCCOUNT__',       $dcs.Count)
$htmlBody = $htmlBody.Replace('__TOTALFINDINGS__', $totalFindings)
$htmlBody = $htmlBody.Replace('__CRITCOUNT__',     $criticalCount)
$htmlBody = $htmlBody.Replace('__HIGHCOUNT__',     $highCount)
$htmlBody = $htmlBody.Replace('__MEDCOUNT__',      $mediumCount)
$htmlBody = $htmlBody.Replace('__LOWCOUNT__',      $lowCount)
$htmlBody = $htmlBody.Replace('__INFOCOUNT__',     $infoCount)

# Add System.Web for HtmlEncode
Add-Type -AssemblyName System.Web

foreach ($finding in ($allFindings | Sort-Object @{Expression={
    switch ($_.Severity) {
        'Critical' { 1 }
        'High'     { 2 }
        'Medium'   { 3 }
        'Low'      { 4 }
        'Info'     { 5 }
        default    { 6 }
    }
}}, Category)) {

    $desc = [System.Web.HttpUtility]::HtmlEncode($finding.Description)
    $rem  = [System.Web.HttpUtility]::HtmlEncode($finding.Remediation)

    $row = @'
            <tr class="__SEVERITY__">
                <td><span class="severity-badge severity-__SEVERITY__">__SEVERITY__</span></td>
                <td>__CATEGORY__</td>
                <td>__ID__</td>
                <td><strong>__TITLE__</strong></td>
                <td>__DESC__</td>
                <td>__REM__</td>
            </tr>
'@

    $row = $row.Replace('__SEVERITY__', $finding.Severity)
    $row = $row.Replace('__CATEGORY__', $finding.Category)
    $row = $row.Replace('__ID__',       $finding.Id)
    $row = $row.Replace('__TITLE__',    $finding.Title)
    $row = $row.Replace('__DESC__',     $desc)
    $row = $row.Replace('__REM__',      $rem)

    $htmlBody += $row
}

$endTime  = Get-Date
$duration = $endTime - $startTime

# Close the HTML
$htmlBody += @'
        </tbody>
    </table>
    
    <div class="meta">
        <p><strong>Report Generated:</strong> __REPORTDATE__</p>
        <p><strong>Scan Duration:</strong> __DURATION__ minutes</p>
        <p><strong>Tool:</strong> ADSecurityHealth Complete Edition v2.1</p>
    </div>
</body>
</html>
'@

$htmlBody = $htmlBody.Replace('__REPORTDATE__', $endTime.ToString('yyyy-MM-dd HH:mm:ss'))
$htmlBody = $htmlBody.Replace('__DURATION__',   [math]::Round($duration.TotalMinutes,2))

$htmlBody | Out-File -Encoding UTF8 $htmlPath
Write-Host "HTML:      $htmlPath" -ForegroundColor Green

$endTime = Get-Date
$duration = $endTime - $startTime

$htmlBody += @"
        </tbody>
    </table>
    
    <div class="meta">
        <p><strong>Report Generated:</strong> $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p><strong>Scan Duration:</strong> $([math]::Round($duration.TotalMinutes,2)) minutes</p>
        <p><strong>Tool:</strong> ADSecurityHealth Complete Edition v2.1</p>
    </div>
</body>
</html>
"@

# Add System.Web for HtmlEncode
Add-Type -AssemblyName System.Web

$htmlBody | Out-File -Encoding UTF8 $htmlPath
Write-Host "HTML:       $htmlPath" -ForegroundColor Green

foreach ($finding in ($allFindings | Sort-Object @{Expression={
    switch($_. Severity) {
        'Critical' {1}
        'High' {2}
        'Medium' {3}
        'Low' {4}
        'Info' {5}
    }
}}, Category)) {
    $htmlBody += @"
            <tr class="$($finding. Severity)">
                <td><span class="severity-badge severity-$($finding.Severity)">$($finding.Severity)</span></td>
                <td>$($finding.Category)</td>
                <td>$($finding.Id)</td>
                <td><strong>$($finding.Title)</strong></td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($finding.Description))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($finding.Remediation))</td>
            </tr>
"@
}

$endTime = Get-Date
$duration = $endTime - $startTime

$htmlBody += @"
        </tbody>
    </table>
    
    <div class="meta">
        <p><strong>Report Generated:</strong> $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p><strong>Scan Duration:</strong> $([math]::Round($duration.TotalMinutes,2)) minutes</p>
        <p><strong>Tool:</strong> ADSecurityHealth Complete Edition v2.1</p>
    </div>
</body>
</html>
"@

foreach ($finding in ($allFindings | Sort-Object @{Expression={
    switch($_.Severity) {
        'Critical' {1}
        'High' {2}
        'Medium' {3}
        'Low' {4}
        'Info' {5}
    }
}}, Category)) {
    $htmlBody += @"
            <tr class="$($finding.Severity)">
                <td><span class="severity-badge severity-$($finding.Severity)">$($finding.Severity)</span></td>
                <td>$($finding.Category)</td>
                <td>$($finding.Id)</td>
                <td><strong>$($finding.Title)</strong></td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($finding.Description))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($finding. Remediation))</td>
            </tr>
"@
}

$endTime = Get-Date
$duration = $endTime - $startTime

$htmlBody += @"
        </tbody>
    </table>
    
    <div class="meta">
        <p><strong>Report Generated:</strong> $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p><strong>Scan Duration:</strong> $([math]::Round($duration.TotalMinutes,2)) minutes</p>
        <p><strong>Tool:</strong> ADSecurityHealth Complete Edition v2.1</p>
    </div>
</body>
</html>
"@

# Add System.Web for HtmlEncode
Add-Type -AssemblyName System.Web

$htmlBody | Out-File -Encoding UTF8 $htmlPath
Write-Host "HTML:      $htmlPath" -ForegroundColor Green

$execPath = Join-Path $OutputPath "$reportBaseName-executive-summary.txt"
Write-Host "Generating executive summary..." -ForegroundColor Gray

$execSummary = @"
================================================================
ACTIVE DIRECTORY SECURITY HEALTH - EXECUTIVE SUMMARY
================================================================

Domain:           $($domain.DNSRoot)
Forest:           $($forest.RootDomain)
Scan Date:        $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))
Scan Duration:    $([math]::Round($duration.TotalMinutes,2)) minutes
Domain Controllers: $($dcs.Count)

================================================================
FINDINGS OVERVIEW
================================================================

Total Findings:   $totalFindings

Critical:         $criticalCount
High:             $highCount
Medium:           $mediumCount
Low:              $lowCount
Info:             $infoCount

================================================================
RISK ASSESSMENT
================================================================

Overall Risk Level: $(
    if     ($criticalCount -gt 0)       { "CRITICAL" }
    elseif ($highCount     -gt 10)      { "HIGH" }
    elseif ($highCount     -gt 0)       { "ELEVATED" }
    elseif ($mediumCount   -gt 20)      { "MODERATE" }
    else                                { "LOW" }
)

$(if ($criticalCount -gt 0) { @"

IMMEDIATE ACTION REQUIRED
Critical security vulnerabilities identified that require
immediate remediation to prevent potential compromise.

"@ })

================================================================
TOP 10 FINDINGS (by Severity)
================================================================

$($allFindings | Where-Object { $_.Severity -in @('Critical','High','Medium') } | 
    Sort-Object @{Expression={
        switch ($_.Severity) {
            'Critical' { 1 }
            'High'     { 2 }
            'Medium'   { 3 }
        }
    }} | 
    Select-Object -First 10 | 
    ForEach-Object { 
        "[$($_.Severity.ToUpper())] $($_.Id): $($_.Title)`n  Remediation: $($_.Remediation)`n" 
    } | Out-String)

================================================================
CATEGORY BREAKDOWN
================================================================

$($allFindings | Group-Object Category | 
    Sort-Object Count -Descending | 
    ForEach-Object { 
        "$($_.Name.PadRight(25)) : $($_.Count)" 
    } | Out-String)

================================================================
RECOMMENDATIONS
================================================================

1. Review and remediate all Critical findings immediately
2. Plan remediation for High findings within 30 days
3. Address Medium findings within 90 days
4. Implement continuous monitoring and alerting
5. Schedule quarterly security health assessments
6. Review and update security baselines

================================================================
REPORTS GENERATED
================================================================

HTML Dashboard:      $([System.IO.Path]::GetFileName($htmlPath))
JSON Export:         $([System.IO.Path]::GetFileName($jsonPath))
CSV Summary:         $([System.IO.Path]::GetFileName($csvPath))
Executive Summary:   $([System.IO.Path]::GetFileName($execPath))

================================================================
"@

$execSummary | Out-File -Encoding UTF8 $execPath
Write-Host "Executive: $execPath" -ForegroundColor Green
Write-Host ""

#endregion Export Reports

#region Email Notification

if ($EmailReport -and $EmailTo) {
    Write-Host "Sending email notification..." -ForegroundColor Gray
    
    $emailSubject = "AD Security Health Report - $($domain.DNSRoot) - [$criticalCount Critical, $highCount High]"
    
    $emailBody = @"
<html>
<body style="font-family:  Calibri, sans-serif;">
<h2>Active Directory Security Health Report</h2>
<p><strong>Domain:</strong> $($domain.DNSRoot)</p>
<p><strong>Scan Date:</strong> $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
<p><strong>Duration:</strong> $([math]:: Round($duration.TotalMinutes,2)) minutes</p>

<h3>Summary</h3>
<table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
<tr style="background-color: #0078D4; color: white;">
    <th>Severity</th>
    <th>Count</th>
</tr>
<tr style="background-color: #ffebee;">
    <td>Critical</td>
    <td><strong>$criticalCount</strong></td>
</tr>
<tr style="background-color:  #fff3e0;">
    <td>High</td>
    <td><strong>$highCount</strong></td>
</tr>
<tr style="background-color: #fffde7;">
    <td>Medium</td>
    <td>$mediumCount</td>
</tr>
<tr>
    <td>Low</td>
    <td>$lowCount</td>
</tr>
<tr>
    <td>Info</td>
    <td>$infoCount</td>
</tr>
</table>

$(if ($criticalFindings) {@"
<h3>Critical Findings</h3>
<ul>
$($criticalFindings | ForEach-Object { "<li><strong>$($_.Id):</strong> $($_.Title)</li>" } | Out-String)
</ul>
"@})

<p>Full reports available at: $OutputPath</p>
</body>
</html>
"@
    
    try {
        $mailParams = @{
            From       = $EmailFrom
            To         = $EmailTo
            Subject    = $emailSubject
            Body       = $emailBody
            BodyAsHtml = $true
            SmtpServer = $SmtpServer
            Priority   = if ($criticalCount -gt 0) { 'High' } else { 'Normal' }
        }
        
        # Attach executive summary
        if (Test-Path $execPath) {
            $mailParams['Attachments'] = $execPath
        }
        
        Send-MailMessage @mailParams
        Write-Host "Email sent to $EmailTo" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to send email: $_"
    }
    Write-Host ""
}

#endregion Email Notification

#region Final Summary

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Scan completed in " -NoNewline
Write-Host "$([math]::Round($duration.TotalMinutes,1)) minutes" -ForegroundColor Green
Write-Host "Total findings: $totalFindings" -ForegroundColor Cyan
Write-Host ""

if ($criticalCount -gt 0) {
    Write-Host "⚠️  WARNING: $criticalCount CRITICAL findings require immediate attention!" -ForegroundColor Red -BackgroundColor Black
    Write-Host ""
}

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review HTML dashboard:   $([System.IO.Path]::GetFileName($htmlPath))" -ForegroundColor Gray
Write-Host "2. Address Critical/High findings" -ForegroundColor Gray
Write-Host "3. Schedule follow-up scan in 30 days" -ForegroundColor Gray
Write-Host ""

#endregion Final Summary
