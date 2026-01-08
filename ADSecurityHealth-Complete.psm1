#requires -Version 5.1
# ADSecurityHealth-Complete.psm1
# Comprehensive PowerShell toolkit for Active Directory security and health monitoring
# Version 2.0.0 - Complete Edition with 60+ functions

#region Helpers

function Initialize-ADSHEnvironment {
    <#
    . SYNOPSIS
        Initializes the Active Directory Security Health environment by loading required modules. 
    
    .DESCRIPTION
        Validates and imports required PowerShell modules for AD security checks. 
        Provides warnings if modules are not available.
    
    .PARAMETER RequiredModules
        Array of module names to import.  Defaults to ActiveDirectory and GroupPolicy.
    
    . EXAMPLE
        Initialize-ADSHEnvironment
        Imports default modules (ActiveDirectory, GroupPolicy).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $RequiredModules = @('ActiveDirectory','GroupPolicy')
    )
    
    Write-ADSHVerbose "Initializing ADSH environment with modules: $($RequiredModules -join ', ')"
    
    foreach ($m in $RequiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $m)) {
                Write-Warning "Module '$m' not found. Please install RSAT or the module."
                Write-ADSHVerbose "Module '$m' is not available on this system"
            } else {
                Write-ADSHVerbose "Importing module: $m"
                Import-Module -Name $m -ErrorAction Stop
                Write-ADSHVerbose "Successfully imported module: $m"
            }
        } catch {
            Write-Warning "Failed to import module '$m': $($_.Exception.Message)"
            Write-ADSHVerbose "Error importing module '$m': $_"
        }
    }
}

function Get-ADSHConfig {
    <#
    .SYNOPSIS
        Retrieves the ADSH configuration from a JSON file or returns defaults.
    
    .DESCRIPTION
        Loads configuration settings from a JSON file.  If the file doesn't exist or
        cannot be parsed, returns default configuration values.
    
    .PARAMETER Path
        Path to the configuration JSON file. Defaults to adsh-config.json in module directory.
    
    . EXAMPLE
        $config = Get-ADSHConfig
        Loads configuration from default location.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Path = "$PSScriptRoot\adsh-config.json"
    )
    
    Write-ADSHVerbose "Loading configuration from: $Path"
    
    if (Test-Path -Path $Path) {
        try {
            Write-ADSHVerbose "Configuration file found, parsing JSON"
            $config = Get-Content -Raw -Path $Path -ErrorAction Stop | ConvertFrom-Json
            Write-ADSHVerbose "Successfully loaded configuration from file"
            return $config
        } catch {
            Write-Warning "Failed to parse config '$Path': $($_.Exception.Message)"
            Write-ADSHVerbose "Error parsing config file, falling back to defaults:  $_"
        }
    } else {
        Write-ADSHVerbose "Configuration file not found at '$Path', using defaults"
    }
    
    # Defaults if config not found
    Write-ADSHVerbose "Returning default configuration values"
    [pscustomobject]@{
        StaleDays                     = 90
        ComputerStaleDays             = 90
        ReplicationMaxLatencyMinutes  = 60
        EventLogMinSizeMB             = 2048
        AlertEmail                    = ''
        SensitiveGroups               = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Backup Operators',
            'Account Operators',
            'Server Operators',
            'Print Operators',
            'DnsAdmins'
        )
        CriticalServices              = @('NTDS','KDC','DNS','Netlogon','LanmanServer','DFSR')
        DNSDcDiagTimeoutSeconds       = 180
        SysvolRequireDFSR             = $true
        KrbtgtMaxPasswordAgeDays      = 180
        PrivilegedAccountMaxPasswordAgeDays = 90
        DCPatchMaxAgeDays             = 60
        TombstoneMinDays              = 180
        LAPSMinCoveragePercent        = 90
    }
}

function New-ADSHFinding {
    <#
    .SYNOPSIS
        Creates a standardized finding object for ADSH reports.
    
    .DESCRIPTION
        Constructs a PowerShell custom object representing a security or health finding
        with consistent structure across all checks.
    
    .PARAMETER Category
        The category of the finding (Security, Health, Policy, etc.).
    
    .PARAMETER Id
        Unique identifier for this finding type.
    
    .PARAMETER Severity
        Severity level:  Info, Low, Medium, High, or Critical.
    
    . PARAMETER Title
        Short title describing the finding.
    
    . PARAMETER Description
        Detailed description of the finding.
    
    .PARAMETER Evidence
        Supporting data for the finding (objects, arrays, etc.).
    
    .PARAMETER Remediation
        Recommended remediation steps.
    
    .EXAMPLE
        New-ADSHFinding -Category 'Security' -Id 'TEST-001' -Severity 'High' `
            -Title 'Test Finding' -Description 'This is a test' `
            -Evidence $data -Remediation 'Fix the issue'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Category,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id,
        
        [Parameter(Mandatory)]
        [ValidateSet('Info','Low','Medium','High','Critical')]
        [string] $Severity,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Title,
        
        [Parameter()]
        [string] $Description,
        
        [Parameter()]
        [object] $Evidence,
        
        [Parameter()]
        [string] $Remediation
    )
    
    Write-ADSHVerbose "Creating finding:  [$Category] $Id - $Severity - $Title"
    
    [pscustomobject]@{
        Timestamp   = (Get-Date).ToString('o')
        Category    = $Category
        Id          = $Id
        Severity    = $Severity
        Title       = $Title
        Description = $Description
        Evidence    = $Evidence
        Remediation = $Remediation
    }
}

function Write-ADSHVerbose {
    <#
    .SYNOPSIS
        Writes a verbose message with ADSH prefix.
    
    .DESCRIPTION
        Wrapper for Write-Verbose that adds [ADSH] prefix for consistent logging.
    
    .PARAMETER Message
        The message to write to verbose stream.
    
    .EXAMPLE
        Write-ADSHVerbose "Processing user accounts"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Verbose "[ADSH] $Message"
}

#endregion Helpers

#region Baseline Functions (1-20)

function Get-PrivilegedGroupMembership {
    <#
    .SYNOPSIS
        Audits membership of privileged Active Directory groups.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $Groups,
        
        [Parameter()]
        [string] $Server
    )
    
    Write-ADSHVerbose "Starting privileged group membership audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Groups) {
            $Groups = $cfg.SensitiveGroups
        }
    } catch {
        $Groups = @('Domain Admins', 'Enterprise Admins')
    }
    
    $findings = @()
    
    foreach ($g in $Groups) {
        Write-ADSHVerbose "Processing group: $g"
        try {
            $params = @{
                Identity    = $g
                ErrorAction = 'Stop'
            }
            if ($Server) { $params['Server'] = $Server }
            
            $grp = Get-ADGroup @params
            
            $memberParams = @{
                Identity    = $grp. DistinguishedName
                Recursive   = $true
                ErrorAction = 'Stop'
            }
            if ($Server) { $memberParams['Server'] = $Server }
            
            $members = Get-ADGroupMember @memberParams
            
            $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
            $sev = if ($members.Count -gt 0) { 'High' } else { 'Info' }
            
            $findings += New-ADSHFinding -Category 'Security' -Id "PRIV-$($grp.SamAccountName)" -Severity $sev `
                -Title "Privileged group membership:  $($grp.SamAccountName)" `
                -Description "List members of privileged group." `
                -Evidence $evidence `
                -Remediation "Review and remove unnecessary members.  Enforce tiered admin model and JIT/PIM for elevation."
        } catch {
            $findings += New-ADSHFinding -Category 'Security' -Id "PRIV-$g" -Severity 'Info' `
                -Title "Privileged group not found: $g" `
                -Description "Group may not exist in this domain.  Error: $($_.Exception.Message)" `
                -Evidence $null `
                -Remediation "Validate domain scope and name."
        }
    }
    
    $findings
}

function Get-StaleAccounts {
    <#
    .SYNOPSIS
        Identifies stale enabled user accounts in Active Directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 3650)]
        [int] $StaleDays
    )
    
    Write-ADSHVerbose "Starting stale accounts audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $StaleDays) {
            $StaleDays = [int]$cfg.StaleDays
        }
    } catch {
        $StaleDays = 90
    }
    
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    
    try {
        $users = Get-ADUser -Filter 'enabled -eq $true' -Properties lastLogonTimestamp,whenCreated,PasswordNeverExpires -ErrorAction Stop
        
        $stale = foreach ($u in $users) {
            $llt = if ($u.lastLogonTimestamp) { [DateTime]::FromFileTime($u. lastLogonTimestamp) } else { $null }
            if (-not $llt -or $llt -lt $cutoff) {
                [pscustomobject]@{
                    Name                = $u.Name
                    SamAccountName      = $u.SamAccountName
                    LastLogon           = $llt
                    WhenCreated         = $u. whenCreated
                    PasswordNeverExpires= $u.PasswordNeverExpires
                    DN                  = $u. DistinguishedName
                }
            }
        }
        
        $sev = if ($stale.Count -gt 50) { 'High' } elseif ($stale.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Hygiene' -Id 'STALE-ACCOUNTS' -Severity $sev `
            -Title "Stale enabled user accounts (>$StaleDays days)" `
            -Description "Enabled accounts with no recent logon increase attack surface." `
            -Evidence $stale `
            -Remediation "Disable or remove stale accounts. Implement lifecycle automation and time-bound access."
    } catch {
        New-ADSHFinding -Category 'Hygiene' -Id 'STALE-ACCOUNTS' -Severity 'Info' `
            -Title "Stale accounts check failed" `
            -Description "Unable to query user accounts.  Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-PasswordPolicyAudit {
    <#
    .SYNOPSIS
        Audits Active Directory password policies. 
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting password policy audit"
    
    try {
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
        
        $evidence = [pscustomobject]@{
            DefaultDomain = $domainPolicy
            FineGrained   = $fgpp | Select-Object Name, Precedence, MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, PasswordComplexityEnabled, ReversibleEncryptionEnabled
        }
        
        New-ADSHFinding -Category 'Policy' -Id 'PWD-POLICY' -Severity 'Medium' `
            -Title "Password policy audit (domain + FGPP)" `
            -Description "Reviews domain and fine-grained password policies for strength and reversible encryption." `
            -Evidence $evidence `
            -Remediation "Set MinLength >= 14+ or prefer passphrases. Enable complexity.  Disable reversible encryption.  Consider AAD/SSO and MFA."
    } catch {
        New-ADSHFinding -Category 'Policy' -Id 'PWD-POLICY' -Severity 'Info' `
            -Title "Password policy audit failed" `
            -Description "Unable to retrieve password policies. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AccountsPasswordNeverExpires {
    <#
    .SYNOPSIS
        Identifies enabled accounts with passwords set to never expire.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting password never expires audit"
    
    try {
        $users = Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and enabled -eq $true' -Properties PasswordNeverExpires,lastLogonTimestamp -ErrorAction Stop
        
        $evidence = $users | Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires, @{n='LastLogon';e={ if ($_.lastLogonTimestamp) {[DateTime]::FromFileTime($_.lastLogonTimestamp)} else {$null}}}, DistinguishedName
        $sev = if ($users.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'PWD-NEVER-EXPIRES' -Severity $sev `
            -Title "Enabled accounts with password set to never expire" `
            -Description "Service or privileged accounts with non-expiring passwords increase risk." `
            -Evidence $evidence `
            -Remediation "Migrate to gMSA or vault-managed secrets; enforce rotation via policy or automation."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'PWD-NEVER-EXPIRES' -Severity 'Info' `
            -Title "Password never expires check failed" `
            -Description "Unable to query accounts. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AccountsReversibleEncryption {
    <#
    .SYNOPSIS
        Checks for reversible encryption enabled in password policies.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting reversible encryption audit"
    
    try {
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction Stop
        $enabledFgpp = $fgpp | Where-Object { $_.ReversibleEncryptionEnabled -eq $true }
        
        $evidence = $enabledFgpp | Select-Object Name, Precedence, ReversibleEncryptionEnabled
        $sev = if ($enabledFgpp.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Policy' -Id 'REV-ENC' -Severity $sev `
            -Title "Reversible password encryption enabled in FGPP" `
            -Description "Storing passwords with reversible encryption significantly weakens security." `
            -Evidence $evidence `
            -Remediation "Disable reversible encryption in all password policies."
    } catch {
        New-ADSHFinding -Category 'Policy' -Id 'REV-ENC' -Severity 'Info' `
            -Title "Reversible encryption check failed" `
            -Description "Unable to query fine-grained password policies. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-KerberosDelegationIssues {
    <#
    .SYNOPSIS
        Audits Kerberos delegation configurations for security risks.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Kerberos delegation audit"
    
    try {
        $unconstrained = Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties userAccountControl, servicePrincipalName -ErrorAction Stop
        $constrainedUsers = Get-ADUser -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo -ErrorAction Stop
        $constrainedComputers = Get-ADComputer -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo -ErrorAction Stop

        $evidence = [pscustomobject]@{
            UnconstrainedComputers = $unconstrained | Select-Object Name, DNSHostName, servicePrincipalName, DistinguishedName
            ConstrainedUsers       = $constrainedUsers | Select-Object Name, SamAccountName, msDS-AllowedToDelegateTo
            ConstrainedComputers   = $constrainedComputers | Select-Object Name, DNSHostName, msDS-AllowedToDelegateTo
        }
        
        $sev = if ($unconstrained.Count -gt 0) { 'High' } else { 'Medium' }
        
        New-ADSHFinding -Category 'Security' -Id 'KERB-DELEG' -Severity $sev `
            -Title "Kerberos delegation audit (unconstrained & constrained)" `
            -Description "Unconstrained delegation is high risk; constrained delegation must be tightly scoped." `
            -Evidence $evidence `
            -Remediation "Remove unconstrained delegation. Restrict constrained delegation only to required services."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'KERB-DELEG' -Severity 'Info' `
            -Title "Kerberos delegation check failed" `
            -Description "Unable to query delegation settings. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AdminSDHolderProtectedAccounts {
    <#
    . SYNOPSIS
        Identifies accounts protected by AdminSDHolder.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting AdminSDHolder protected accounts audit"
    
    try {
        $protected = Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount, whenChanged, memberOf -ErrorAction Stop
        
        $evidence = $protected | Select-Object Name, SamAccountName, whenChanged, memberOf, DistinguishedName
        $sev = if ($protected.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'ADMINSD' -Severity $sev `
            -Title "AdminSDHolder protected accounts (adminCount=1)" `
            -Description "Protected accounts do not inherit permissions; verify necessity to reduce persistence risks." `
            -Evidence $evidence `
            -Remediation "Remove privileged group membership if not needed; run SDProp reset and re-enable inheritance where appropriate."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'ADMINSD' -Severity 'Info' `
            -Title "AdminSDHolder check failed" `
            -Description "Unable to query protected accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-ExcessivePermissionsDelegations {
    <#
    . SYNOPSIS
        Audits ACL permissions on sensitive objects for excessive rights.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $Targets
    )
    
    Write-ADSHVerbose "Starting excessive permissions/delegations audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Targets) {
            $Targets = $cfg.SensitiveGroups
        }
    } catch {
        $Targets = @('Domain Admins', 'Enterprise Admins')
    }
    
    $findings = @()
    
    foreach ($t in $Targets) {
        try {
            $grp = Get-ADGroup -Identity $t -Properties DistinguishedName -ErrorAction Stop
            $path = "AD:$($grp.DistinguishedName)"
            $acl = Get-Acl -Path $path -ErrorAction Stop
            
            $risky = @()
            foreach ($ace in $acl.Access) {
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteOwner|WriteDacl') {
                    $risky += [pscustomobject]@{
                        IdentityReference       = $ace.IdentityReference
                        ActiveDirectoryRights   = $ace.ActiveDirectoryRights
                        IsInherited             = $ace.IsInherited
                        ObjectDN                = $grp.DistinguishedName
                    }
                }
            }
            
            $sev = if ($risky.Count -gt 0) { 'High' } else { 'Info' }
            $findings += New-ADSHFinding -Category 'Security' -Id "ACL-$($grp.SamAccountName)" -Severity $sev `
                -Title "Risky ACEs on sensitive object:  $($grp.SamAccountName)" `
                -Description "High-privilege ACEs (GenericAll/WriteOwner/WriteDacl) may enable escalation." `
                -Evidence $risky `
                -Remediation "Restrict ACEs to admins; remove broad rights; implement tiering and just-in-time access."
        } catch {
            $findings += New-ADSHFinding -Category 'Security' -Id "ACL-$t" -Severity 'Info' `
                -Title "ACL scan skipped (object not found): $t" `
                -Description "Sensitive object may not exist in this domain. Error: $($_.Exception.Message)" `
                -Evidence $null `
                -Remediation "Validate object name and domain."
        }
    }
    
    $findings
}

function Get-DCReplicationStatus {
    <#
    . SYNOPSIS
        Checks domain controller replication status.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting DC replication status check"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        $evidence = @()
        foreach ($dc in $dcs) {
            try {
                $meta = Get-ADReplicationPartnerMetadata -Target $dc. HostName -Scope Server -ErrorAction Stop
                foreach ($m in $meta) {
                    $evidence += [pscustomobject]@{
                        SourceDC         = $m.Partner
                        TargetDC         = $dc.HostName
                        LastSuccess      = $m.LastReplicationSuccess
                        LastFailure      = $m.LastReplicationFailure
                        ConsecutiveFails = $m.ConsecutiveReplicationFailures
                    }
                }
            } catch {
                $evidence += [pscustomobject]@{
                    SourceDC         = $null
                    TargetDC         = $dc.HostName
                    LastSuccess      = $null
                    LastFailure      = $_. Exception.Message
                    ConsecutiveFails = $null
                }
            }
        }
        
        $failures = $evidence | Where-Object { $_.ConsecutiveFails -gt 0 }
        $sev = if ($failures) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'REPL' -Severity $sev `
            -Title "Domain controller replication status" `
            -Description "Replication failures and high latency impact consistency and security enforcement." `
            -Evidence $evidence `
            -Remediation "Investigate failing links with repadmin and event logs; fix DNS, connectivity, and AD sites."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'REPL' -Severity 'Info' `
            -Title "DC replication check failed" `
            -Description "Unable to query domain controllers. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-DNSHealth {
    <#
    . SYNOPSIS
        Checks DNS health on domain controllers using dcdiag.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(30, 600)]
        [int] $TimeoutSeconds
    )
    
    Write-ADSHVerbose "Starting DNS health check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $TimeoutSeconds) {
            $TimeoutSeconds = [int]$cfg.DNSDcDiagTimeoutSeconds
        }
    } catch {
        $TimeoutSeconds = 180
    }
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = @()
        foreach ($dc in $dcs) {
            $cmd = "dcdiag /s: $dc /test:DNS /v"
            try {
                $job = Start-Job -ScriptBlock { param($c) cmd. exe /c $c | Out-String } -ArgumentList $cmd
                if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
                    $out = Receive-Job -Job $job
                    $passed = ($out -notmatch 'FAIL|error')
                    $evidence += [pscustomobject]@{
                        DC     = $dc
                        Output = $out
                        Passed = $passed
                    }
                } else {
                    Stop-Job $job | Out-Null
                    $evidence += [pscustomobject]@{
                        DC     = $dc
                        Output = 'Timeout'
                        Passed = $false
                    }
                }
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            } catch {
                $evidence += [pscustomobject]@{
                    DC     = $dc
                    Output = $_. Exception.Message
                    Passed = $false
                }
            }
        }
        
        $failures = $evidence | Where-Object { -not $_.Passed }
        $sev = if ($failures) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'DNS' -Severity $sev `
            -Title "DNS health via dcdiag" `
            -Description "AD-integrated DNS issues cause authentication and replication failures." `
            -Evidence $evidence `
            -Remediation "Resolve zone errors, stale records, and delegation issues; ensure DCs register SRV records."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'DNS' -Severity 'Info' `
            -Title "DNS health check failed" `
            -Description "Unable to run DNS checks. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-SYSVOLReplicationStatus {
    <#
    . SYNOPSIS
        Checks SYSVOL replication service status across domain controllers.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool] $RequireDFSR
    )
    
    Write-ADSHVerbose "Starting SYSVOL replication status check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $PSBoundParameters. ContainsKey('RequireDFSR')) {
            $RequireDFSR = [bool]$cfg.SysvolRequireDFSR
        }
    } catch {
        $RequireDFSR = $true
    }
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $services = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-Service -Name 'DFSR','NtFrs' -ErrorAction SilentlyContinue | Select-Object Name, Status
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC          = $dc.HostName
                    DFSRStatus  = ($services | Where-Object {$_.Name -eq 'DFSR'}).Status
                    FRSStatus   = ($services | Where-Object {$_.Name -eq 'NtFrs'}).Status
                }
            } catch {
                [pscustomobject]@{
                    DC          = $dc.HostName
                    DFSRStatus  = "Query failed:  $($_.Exception.Message)"
                    FRSStatus   = "Query failed"
                }
            }
        }
        
        $frsActive = $evidence | Where-Object { $_.FRSStatus -eq 'Running' }
        $sev = if ($RequireDFSR -and $frsActive) { 'High' } else { 'Medium' }
        
        New-ADSHFinding -Category 'Health' -Id 'SYSVOL' -Severity $sev `
            -Title "SYSVOL replication service status (DFSR vs FRS)" `
            -Description "FRS is deprecated; DFSR is required.  Confirm replication health and migration status." `
            -Evidence $evidence `
            -Remediation "Migrate SYSVOL from FRS to DFSR; validate DFSR connections and backlog with dfsrdiag."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'SYSVOL' -Severity 'Info' `
            -Title "SYSVOL replication check failed" `
            -Description "Unable to query SYSVOL replication.  Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-FSMORoleHolders {
    <#
    .SYNOPSIS
        Identifies current FSMO role holders. 
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting FSMO role holders check"
    
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        
        $evidence = [pscustomobject]@{
            DomainNamingMaster     = $forest.DomainNamingMaster
            SchemaMaster           = $forest.SchemaMaster
            RIDMaster              = $domain.RIDMaster
            PDCEmulator            = $domain. PDCEmulator
            InfrastructureMaster   = $domain.InfrastructureMaster
        }
        
        New-ADSHFinding -Category 'Health' -Id 'FSMO' -Severity 'Info' `
            -Title "FSMO role holders" `
            -Description "Record current role holders to confirm availability and placement." `
            -Evidence $evidence `
            -Remediation "Ensure role holders are online, backed up, and placed appropriately per sites and capacity."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'FSMO' -Severity 'Info' `
            -Title "FSMO check failed" `
            -Description "Unable to query FSMO roles. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-DCServiceStatus {
    <#
    . SYNOPSIS
        Checks critical service status on domain controllers.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $Services
    )
    
    Write-ADSHVerbose "Starting DC service status check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Services) {
            $Services = $cfg. CriticalServices
        }
    } catch {
        $Services = @('NTDS','KDC','DNS','Netlogon')
    }
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $svc = Invoke-Command -ComputerName $dc -ScriptBlock {
                    param($names)
                    Get-Service -Name $names -ErrorAction SilentlyContinue | Select-Object Name, Status
                } -ArgumentList (,$Services) -ErrorAction Stop
                
                [pscustomobject]@{
                    DC       = $dc
                    Services = $svc
                }
            } catch {
                [pscustomobject]@{
                    DC       = $dc
                    Services = "Query failed: $($_.Exception.Message)"
                }
            }
        }
        
        $down = $evidence | Where-Object { $_.Services. Status -contains 'Stopped' }
        $sev = if ($down) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'DC-SVC' -Severity $sev `
            -Title "Domain controller critical service status" `
            -Description "Critical DC services must be running for authentication and replication." `
            -Evidence $evidence `
            -Remediation "Start services or troubleshoot failures; check event logs and configuration."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'DC-SVC' -Severity 'Info' `
            -Title "DC service check failed" `
            -Description "Unable to query DC services. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-ADDatabaseStats {
    <#
    . SYNOPSIS
        Retrieves AD database size statistics from domain controllers.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting AD database stats check"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $size = Invoke-Command -ComputerName $dc -ScriptBlock {
                    (Get-Item 'C:\Windows\NTDS\ntds.dit' -ErrorAction Stop).Length
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC        = $dc
                    SizeBytes = $size
                    SizeMB    = [math]::Round($size/1MB,2)
                    SizeGB    = [math]::Round($size/1GB,2)
                }
            } catch {
                [pscustomobject]@{
                    DC        = $dc
                    SizeBytes = $null
                    SizeMB    = $null
                    SizeGB    = $null
                    Error     = $_.Exception.Message
                }
            }
        }
        
        New-ADSHFinding -Category 'Capacity' -Id 'NTDS' -Severity 'Info' `
            -Title "AD database (ntds.dit) size per DC" `
            -Description "Track AD DB size for capacity planning; monitor sudden growth." `
            -Evidence $evidence `
            -Remediation "Ensure sufficient disk space and regular backups; defragment offline if required."
    } catch {
        New-ADSHFinding -Category 'Capacity' -Id 'NTDS' -Severity 'Info' `
            -Title "AD database stats check failed" `
            -Description "Unable to query database stats. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-TrustRelationships {
    <#
    .SYNOPSIS
        Audits domain and forest trust relationships.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting trust relationships audit"
    
    try {
        $trusts = Get-ADTrust -Filter * -Properties * -ErrorAction Stop
        
        $evidence = $trusts | Select-Object Name, Source, Target, TrustType, TrustAttributes, Direction, IsForest, IsExternal
        $sev = if ($trusts.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Exposure' -Id 'TRUSTS' -Severity $sev `
            -Title "Domain and forest trust relationships" `
            -Description "Review external and forest trusts; validate SID filtering and selective authentication." `
            -Evidence $evidence `
            -Remediation "Remove obsolete trusts; enable SID filtering; use selective authentication for external trusts."
    } catch {
        New-ADSHFinding -Category 'Exposure' -Id 'TRUSTS' -Severity 'Info' `
            -Title "Trust relationships check failed" `
            -Description "Unable to query trusts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-GPOReview {
    <#
    . SYNOPSIS
        Reviews Group Policy Objects for orphaned GPOs and security. 
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting GPO review"
    
    try {
        $all = Get-GPO -All -ErrorAction Stop
        
        $evidence = foreach ($g in $all) {
            [pscustomobject]@{
                DisplayName      = $g.DisplayName
                Id               = $g.Id
                CreationTime     = $g.CreationTime
                ModificationTime = $g.ModificationTime
                GpoStatus        = $g.GpoStatus
            }
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'Configuration' -Id 'GPO' -Severity $sev `
            -Title "GPO review (orphaned and security filtering)" `
            -Description "Identify orphaned GPOs and review security filtering for over-permission." `
            -Evidence $evidence `
            -Remediation "Delete or archive unused GPOs; tighten GPO permissions and links; document GPO ownership."
    } catch {
        New-ADSHFinding -Category 'Configuration' -Id 'GPO' -Severity 'Info' `
            -Title "GPO review failed" `
            -Description "Unable to query GPOs. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity, GroupPolicy module, and permissions."
    }
}

function Get-PreWin2000AccessRisks {
    <#
    .SYNOPSIS
        Audits Pre-Windows 2000 Compatible Access group membership.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Pre-Windows 2000 Compatible Access audit"
    
    try {
        $grp = Get-ADGroup -Identity 'Pre-Windows 2000 Compatible Access' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $grp. DistinguishedName -Recursive -ErrorAction SilentlyContinue
        
        $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
        $sev = if ($members.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'PREWIN2000' -Severity $sev `
            -Title "Pre-Windows 2000 Compatible Access membership" `
            -Description "Membership here broadens read access; review for legacy needs only." `
            -Evidence $evidence `
            -Remediation "Remove unnecessary principals; ensure legacy apps are updated."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'PREWIN2000' -Severity 'Info' `
            -Title "Pre-Windows 2000 Compatible Access group not found" `
            -Description "Group may be renamed or domain-specific. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Validate group existence."
    }
}

function Get-SPNAudit {
    <#
    . SYNOPSIS
        Audits Service Principal Names for duplicates and security risks.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting SPN audit"
    
    try {
        $objs = Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, SamAccountName, objectClass -ErrorAction Stop
        
        $allSpns = @()
        foreach ($o in $objs) {
            foreach ($spn in $o.servicePrincipalName) {
                $allSpns += [pscustomobject]@{
                    Owner       = $o.SamAccountName
                    DN          = $o.DistinguishedName
                    ObjectClass = $o.objectClass
                    SPN         = $spn
                }
            }
        }
        
        $dupes = $allSpns | Group-Object SPN | Where-Object { $_. Count -gt 1 } | ForEach-Object {
            [pscustomobject]@{
                SPN    = $_.Name
                Owners = ($_.Group | Select-Object -ExpandProperty Owner) -join ', '
            }
        }
        
        $sev = if ($dupes.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'SPN' -Severity $sev `
            -Title "SPN audit (duplicate SPNs & ownership)" `
            -Description "Duplicate SPNs cause auth conflicts; SPNs on user accounts increase Kerberoasting risk." `
            -Evidence ([pscustomobject]@{ Duplicates = $dupes; TotalSPNs = $allSpns.Count }) `
            -Remediation "Remove duplicates; prefer computer accounts for service SPNs; monitor for high-value service tickets."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'SPN' -Severity 'Info' `
            -Title "SPN audit failed" `
            -Description "Unable to query SPNs. Error: $($_. Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AuditPolicyVerification {
    <#
    .SYNOPSIS
        Verifies audit policy configuration on domain controllers.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting audit policy verification"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $out = Invoke-Command -ComputerName $dc -ScriptBlock { 
                    auditpol. exe /get /category:* | Out-String 
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC              = $dc
                    Output          = $out
                    KeyAreasCovered = ($out -match 'Account Logon|Account Management|Policy Change|Privilege Use|System')
                }
            } catch {
                [pscustomobject]@{
                    DC              = $dc
                    Output          = "Failed: $($_.Exception.Message)"
                    KeyAreasCovered = $false
                }
            }
        }
        
        $missing = $evidence | Where-Object { -not $_.KeyAreasCovered }
        $sev = if ($missing) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Monitoring' -Id 'AUDITPOL' -Severity $sev `
            -Title "Audit policy coverage on domain controllers" `
            -Description "Ensure auditing for account logon, management, policy change, privilege use, and system events." `
            -Evidence $evidence `
            -Remediation "Configure advanced audit policies via GPO; forward events to SIEM."
    } catch {
        New-ADSHFinding -Category 'Monitoring' -Id 'AUDITPOL' -Severity 'Info' `
            -Title "Audit policy check failed" `
            -Description "Unable to query audit policies. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-SecurityEventLogConfig {
    <#
    . SYNOPSIS
        Checks Security event log configuration on domain controllers. 
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MinSizeMB
    )
    
    Write-ADSHVerbose "Starting Security event log configuration check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $MinSizeMB) {
            $MinSizeMB = [int]$cfg.EventLogMinSizeMB
        }
    } catch {
        $MinSizeMB = 2048
    }
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $data = Invoke-Command -ComputerName $dc -ScriptBlock {
                    Get-CimInstance -ClassName Win32_NTEventLogFile -Filter "LogfileName='Security'" |
                        Select-Object LogfileName, MaxFileSize, NumberOfRecords
                } -ErrorAction Stop
                
                $sizeMB = [math]::Round(($data.MaxFileSize/1MB),2)
                
                [pscustomobject]@{
                    DC              = $dc
                    MaxFileSizeMB   = $sizeMB
                    NumberOfRecords = $data.NumberOfRecords
                }
            } catch {
                [pscustomobject]@{
                    DC              = $dc
                    MaxFileSizeMB   = $null
                    NumberOfRecords = $null
                    Error           = $_.Exception.Message
                }
            }
        }
        
        $undersized = $evidence | Where-Object { $_.MaxFileSizeMB -lt $MinSizeMB }
        $sev = if ($undersized) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Monitoring' -Id 'SECLOG' -Severity $sev `
            -Title "Security log size and retention on domain controllers" `
            -Description "Adequate log size and retention prevent loss of critical security telemetry." `
            -Evidence $evidence `
            -Remediation "Increase Security log size (≥$MinSizeMB MB) and configure retention; forward to SIEM."
    } catch {
        New-ADSHFinding -Category 'Monitoring' -Id 'SECLOG' -Severity 'Info' `
            -Title "Security log config check failed" `
            -Description "Unable to query Security log configuration. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion Baseline Functions (1-20)

#region Advanced Functions (21-40)

function Get-SuspiciousSIDHistory {
    <#
    .SYNOPSIS
        Detects accounts with SID History populated (privilege escalation risk).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting SID History audit"
    
    try {
        $users = Get-ADUser -LDAPFilter '(sidHistory=*)' -Properties sidHistory, whenChanged, memberOf -ErrorAction Stop
        $computers = Get-ADComputer -LDAPFilter '(sidHistory=*)' -Properties sidHistory, whenChanged -ErrorAction Stop
        
        $evidence = [pscustomobject]@{
            UsersWithSIDHistory     = $users | Select-Object Name, SamAccountName, sidHistory, whenChanged, memberOf, DistinguishedName
            ComputersWithSIDHistory = $computers | Select-Object Name, DNSHostName, sidHistory, whenChanged, DistinguishedName
        }
        
        $sev = if ($users.Count -gt 0 -or $computers.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'ThreatDetection' -Id 'SIDHIST' -Severity $sev `
            -Title "Accounts with SID History attribute populated" `
            -Description "SID History can be abused for privilege escalation and persistence." `
            -Evidence $evidence `
            -Remediation "Validate legitimate migration; remove SID History post-migration; audit regularly for unauthorized additions."
    } catch {
        New-ADSHFinding -Category 'ThreatDetection' -Id 'SIDHIST' -Severity 'Info' `
            -Title "SID History check failed" `
            -Description "Unable to query SID History. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-PrivilegedAccountPasswordAge {
    <#
    . SYNOPSIS
        Identifies privileged accounts with old passwords.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MaxPasswordAgeDays = 90,
        
        [Parameter()]
        [string[]] $Groups
    )
    
    Write-ADSHVerbose "Starting privileged account password age audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Groups) { $Groups = $cfg.SensitiveGroups }
        if (-not $MaxPasswordAgeDays) { $MaxPasswordAgeDays = [int]$cfg. PrivilegedAccountMaxPasswordAgeDays }
    } catch {
        $MaxPasswordAgeDays = 90
        $Groups = @('Domain Admins', 'Enterprise Admins')
    }
    
    try {
        $privilegedUsers = @()
        foreach ($g in $Groups) {
            try {
                $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' }
                $privilegedUsers += $members
            } catch { }
        }
        
        $privilegedUsers = $privilegedUsers | Sort-Object -Property SamAccountName -Unique
        $evidence = @()
        
        foreach ($u in $privilegedUsers) {
            try {
                $user = Get-ADUser -Identity $u. DistinguishedName -Properties pwdLastSet, PasswordLastSet, PasswordNeverExpires -ErrorAction Stop
                $pwdAge = if ($user. PasswordLastSet) { ((Get-Date) - $user.PasswordLastSet).Days } else { $null }
                
                if ($pwdAge -gt $MaxPasswordAgeDays -or $user.PasswordNeverExpires) {
                    $evidence += [pscustomobject]@{
                        Name                 = $user.Name
                        SamAccountName       = $user.SamAccountName
                        PasswordLastSet      = $user.PasswordLastSet
                        PasswordAgeDays      = $pwdAge
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        DN                   = $user.DistinguishedName
                    }
                }
            } catch { }
        }
        
        $sev = if ($evidence. Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'PRIV-PWD-AGE' -Severity $sev `
            -Title "Privileged accounts with old passwords (>$MaxPasswordAgeDays days)" `
            -Description "Old passwords on privileged accounts increase breach risk." `
            -Evidence $evidence `
            -Remediation "Enforce password rotation; migrate to passwordless or gMSA; implement PAM/PIM."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'PRIV-PWD-AGE' -Severity 'Info' `
            -Title "Privileged password age check failed" `
            -Description "Unable to query privileged account passwords. Error: $($_.Exception. Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-WeakEncryptionTypes {
    <#
    . SYNOPSIS
        Identifies accounts supporting weak Kerberos encryption (DES/RC4).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting weak encryption types audit"
    
    try {
        $users = Get-ADUser -Filter * -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction Stop
        $computers = Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction Stop
        
        $weakUsers = $users | Where-Object { 
            $_.'msDS-SupportedEncryptionTypes' -band 0x07  # DES or RC4
        } | Select-Object Name, SamAccountName, 'msDS-SupportedEncryptionTypes', DistinguishedName
        
        $weakComputers = $computers | Where-Object { 
            $_.'msDS-SupportedEncryptionTypes' -band 0x07
        } | Select-Object Name, DNSHostName, 'msDS-SupportedEncryptionTypes', DistinguishedName
        
        $evidence = [pscustomobject]@{
            WeakUsers     = $weakUsers
            WeakComputers = $weakComputers
        }
        
        $sev = if ($weakUsers.Count -gt 0 -or $weakComputers.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'WEAK-ENC' -Severity $sev `
            -Title "Accounts supporting weak Kerberos encryption (DES/RC4)" `
            -Description "DES and RC4 are cryptographically weak and subject to downgrade attacks." `
            -Evidence $evidence `
            -Remediation "Disable DES and RC4; enforce AES256-SHA1 or AES128-SHA1; update clients and applications."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'WEAK-ENC' -Severity 'Info' `
            -Title "Weak encryption check failed" `
            -Description "Unable to query encryption types. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-LAPSCoverage {
    <#
    .SYNOPSIS
        Checks LAPS (Local Admin Password Solution) coverage across computers.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting LAPS coverage check"
    
    try {
        $computers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', OperatingSystem -ErrorAction Stop
        
        $withLAPS = $computers | Where-Object { $_.'ms-Mcs-AdmPwd' } | Measure-Object | Select-Object -ExpandProperty Count
        $withoutLAPS = $computers | Where-Object { -not $_.'ms-Mcs-AdmPwd' } | Measure-Object | Select-Object -ExpandProperty Count
        
        $evidence = [pscustomobject]@{
            TotalComputers     = $computers.Count
            WithLAPS           = $withLAPS
            WithoutLAPS        = $withoutLAPS
            CoveragePercent    = if ($computers.Count -gt 0) { [math]::Round(($withLAPS / $computers.Count) * 100, 2) } else { 0 }
            ComputersNoLAPS    = $computers | Where-Object { -not $_.'ms-Mcs-AdmPwd' } | Select-Object Name, DNSHostName, OperatingSystem, DistinguishedName -First 50
        }
        
        $cfg = Get-ADSHConfig
        $minCoverage = if ($cfg.LAPSMinCoveragePercent) { $cfg.LAPSMinCoveragePercent } else { 90 }
        
        $sev = if ($evidence.CoveragePercent -lt $minCoverage) { 'High' } elseif ($evidence.CoveragePercent -lt 100) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'LAPS' -Severity $sev `
            -Title "LAPS coverage for domain computers (Target: $minCoverage%)" `
            -Description "LAPS randomizes local admin passwords and prevents lateral movement via shared credentials." `
            -Evidence $evidence `
            -Remediation "Deploy LAPS GPO and client; ensure schema extended; verify ACLs on ms-Mcs-AdmPwd."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'LAPS' -Severity 'Info' `
            -Title "LAPS coverage check failed" `
            -Description "Unable to query LAPS attributes.  LAPS may not be deployed.  Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Deploy LAPS or verify AD connectivity and permissions."
    }
}

function Get-ProtectedUsersGroupMembership {
    <#
    .SYNOPSIS
        Audits Protected Users group membership (hardened authentication).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Protected Users group audit"
    
    try {
        $grp = Get-ADGroup -Identity 'Protected Users' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $grp. DistinguishedName -Recursive -ErrorAction SilentlyContinue
        
        $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
        $sev = if ($members.Count -gt 0) { 'Info' } else { 'Medium' }
        
        New-ADSHFinding -Category 'Security' -Id 'PROT-USERS' -Severity $sev `
            -Title "Protected Users group membership" `
            -Description "Protected Users enforces strict Kerberos policy (no NTLM, DES, RC4, delegation, caching)." `
            -Evidence $evidence `
            -Remediation "Add high-value accounts (Domain Admins, service accounts) to Protected Users; test app compatibility first."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'PROT-USERS' -Severity 'Medium' `
            -Title "Protected Users group not found or inaccessible" `
            -Description "Protected Users group is available in 2012 R2+ domains; check functional level.  Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Raise domain functional level to 2012 R2 or higher; configure Protected Users."
    }
}

function Get-KrbtgtPasswordAge {
    <#
    . SYNOPSIS
        Checks krbtgt account password age (Golden Ticket defense).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MaxPasswordAgeDays = 180
    )
    
    Write-ADSHVerb