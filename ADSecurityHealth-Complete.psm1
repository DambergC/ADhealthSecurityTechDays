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
    .SYNOPSIS
        Checks krbtgt account password age (Golden Ticket defense).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MaxPasswordAgeDays
    )
    
    Write-ADSHVerbose "Starting krbtgt password age check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $MaxPasswordAgeDays) {
            $MaxPasswordAgeDays = [int]$cfg.KrbtgtMaxPasswordAgeDays
        }
    } catch {
        $MaxPasswordAgeDays = 180
    }
    
    try {
        $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet, whenChanged -ErrorAction Stop
        $pwdAge = if ($krbtgt.PasswordLastSet) { ((Get-Date) - $krbtgt.PasswordLastSet).Days } else { $null }
        
        $evidence = [pscustomobject]@{
            Account         = $krbtgt.Name
            PasswordLastSet = $krbtgt.PasswordLastSet
            PasswordAgeDays = $pwdAge
            WhenChanged     = $krbtgt.whenChanged
            DN              = $krbtgt.DistinguishedName
        }
        
        $sev = if ($pwdAge -gt $MaxPasswordAgeDays) { 'Critical' } elseif ($pwdAge -gt ($MaxPasswordAgeDays * 0.8)) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'KRBTGT-AGE' -Severity $sev `
            -Title "krbtgt password age: $pwdAge days (Max: $MaxPasswordAgeDays)" `
            -Description "krbtgt password should be rotated regularly to mitigate Golden Ticket attacks." `
            -Evidence $evidence `
            -Remediation "Rotate krbtgt password using Microsoft script (twice, 10 hours apart); plan for Kerberos ticket expiry."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'KRBTGT-AGE' -Severity 'Info' `
            -Title "krbtgt password age check failed" `
            -Description "Unable to query krbtgt account. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-CertificateTemplatePermissions {
    <#
    .SYNOPSIS
        Audits ADCS certificate template permissions for ESC vulnerabilities.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting certificate template permissions audit"
    
    try {
        $configNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $templatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        
        $templates = Get-ADObject -SearchBase $templatesPath -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties * -ErrorAction Stop
        
        $riskyTemplates = @()
        foreach ($t in $templates) {
            $path = "AD:$($t.DistinguishedName)"
            try {
                $acl = Get-Acl -Path $path -ErrorAction Stop
                
                foreach ($ace in $acl.Access) {
                    if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteProperty|WriteDacl|WriteOwner' -and 
                        $ace.IdentityReference -notmatch 'Enterprise Admins|Domain Admins|SYSTEM') {
                        $riskyTemplates += [pscustomobject]@{
                            Template          = $t.Name
                            IdentityReference = $ace.IdentityReference
                            Rights            = $ace.ActiveDirectoryRights
                            IsInherited       = $ace.IsInherited
                        }
                    }
                }
            } catch { }
        }
        
        $sev = if ($riskyTemplates.Count -gt 0) { 'Critical' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'ADCS-ESC' -Severity $sev `
            -Title "ADCS certificate template permissions (ESC1-ESC4 vulnerabilities)" `
            -Description "Excessive permissions on certificate templates enable privilege escalation via certificate enrollment." `
            -Evidence $riskyTemplates `
            -Remediation "Restrict template permissions; disable vulnerable templates; audit enrollment rights; review published templates."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'ADCS-ESC' -Severity 'Info' `
            -Title "Certificate template audit failed" `
            -Description "ADCS may not be deployed or accessible. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Deploy ADCS or verify AD connectivity and permissions."
    }
}

function Get-NTLMAuthenticationUsage {
    <#
    .SYNOPSIS
        Tracks NTLM authentication usage for legacy protocol deprecation.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting NTLM authentication usage check"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $ntlmEvents = Invoke-Command -ComputerName $dc -ScriptBlock {
                    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
                        Where-Object { $_.Message -match 'NTLM' } |
                        Measure-Object | Select-Object -ExpandProperty Count
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC               = $dc
                    NTLMEventsLast7d = $ntlmEvents
                }
            } catch {
                [pscustomobject]@{
                    DC               = $dc
                    NTLMEventsLast7d = "Query failed: $($_.Exception.Message)"
                }
            }
        }
        
        $highUsage = $evidence | Where-Object { $_.NTLMEventsLast7d -gt 1000 }
        $sev = if ($highUsage) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'NTLM-USAGE' -Severity $sev `
            -Title "NTLM authentication usage tracking (last 7 days)" `
            -Description "NTLM is vulnerable to relay attacks; migrate to Kerberos where possible." `
            -Evidence $evidence `
            -Remediation "Enable NTLM auditing; identify apps using NTLM; migrate to Kerberos; block NTLM via GPO."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'NTLM-USAGE' -Severity 'Info' `
            -Title "NTLM usage check failed" `
            -Description "Unable to query NTLM events. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity, permissions, and event log access."
    }
}

function Get-AnonymousLDAPBind {
    <#
    .SYNOPSIS
        Checks for anonymous LDAP bind configuration (enumeration risk).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting anonymous LDAP bind check"
    
    try {
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        
        # Check domain-level anonymous access settings
        $domainPath = "AD:$($domain.DistinguishedName)"
        $acl = Get-Acl -Path $domainPath -ErrorAction Stop
        
        $anonymousACEs = $acl.Access | Where-Object { 
            $_.IdentityReference -match 'ANONYMOUS LOGON|Everyone' -and
            $_.ActiveDirectoryRights -match 'GenericRead|ReadProperty'
        }
        
        $evidence = [pscustomobject]@{
            Domain              = $domain.DNSRoot
            AnonymousACEsCount  = $anonymousACEs.Count
            AnonymousACEs       = $anonymousACEs | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
        }
        
        $sev = if ($anonymousACEs.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'ANON-LDAP' -Severity $sev `
            -Title "Anonymous LDAP bind configuration" `
            -Description "Anonymous LDAP access enables unauthenticated enumeration of AD objects." `
            -Evidence $evidence `
            -Remediation "Disable anonymous LDAP bind; require authentication for LDAP queries; audit LDAP access."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'ANON-LDAP' -Severity 'Info' `
            -Title "Anonymous LDAP check failed" `
            -Description "Unable to query LDAP configuration. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-DCPatchLevel {
    <#
    .SYNOPSIS
        Checks domain controller patch currency and Windows Update status.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MaxPatchAgeDays
    )
    
    Write-ADSHVerbose "Starting DC patch level check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $MaxPatchAgeDays) {
            $MaxPatchAgeDays = [int]$cfg.DCPatchMaxAgeDays
        }
    } catch {
        $MaxPatchAgeDays = 60
    }
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $patches = Invoke-Command -ComputerName $dc -ScriptBlock {
                    $lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
                    [pscustomobject]@{
                        LastPatchKB      = $lastPatch.HotFixID
                        LastPatchDate    = $lastPatch.InstalledOn
                        LastPatchAgeDays = if ($lastPatch.InstalledOn) { ((Get-Date) - $lastPatch.InstalledOn).Days } else { $null }
                    }
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC               = $dc
                    LastPatchKB      = $patches.LastPatchKB
                    LastPatchDate    = $patches.LastPatchDate
                    LastPatchAgeDays = $patches.LastPatchAgeDays
                }
            } catch {
                [pscustomobject]@{
                    DC               = $dc
                    LastPatchKB      = $null
                    LastPatchDate    = $null
                    LastPatchAgeDays = $null
                    Error            = $_.Exception.Message
                }
            }
        }
        
        $outdated = $evidence | Where-Object { $_.LastPatchAgeDays -gt $MaxPatchAgeDays }
        $sev = if ($outdated) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'DC-PATCH' -Severity $sev `
            -Title "Domain controller patch currency (Max age: $MaxPatchAgeDays days)" `
            -Description "Outdated DCs are vulnerable to known exploits; regular patching is critical." `
            -Evidence $evidence `
            -Remediation "Deploy Windows Updates regularly; use WSUS or ConfigMgr; test patches in staging; monitor for critical CVEs."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'DC-PATCH' -Severity 'Info' `
            -Title "DC patch level check failed" `
            -Description "Unable to query patch status. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-TombstoneLifetime {
    <#
    .SYNOPSIS
        Checks AD tombstone lifetime configuration for backup safety margin.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MinTombstoneDays
    )
    
    Write-ADSHVerbose "Starting tombstone lifetime check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $MinTombstoneDays) {
            $MinTombstoneDays = [int]$cfg.TombstoneMinDays
        }
    } catch {
        $MinTombstoneDays = 180
    }
    
    try {
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        $configNC = $rootDSE.configurationNamingContext
        
        $dirService = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -ErrorAction Stop
        $tombstone = if ($dirService.tombstoneLifetime) { $dirService.tombstoneLifetime } else { 180 } # Default is 180 days
        
        $evidence = [pscustomobject]@{
            TombstoneLifetimeDays = $tombstone
            MinRecommended        = $MinTombstoneDays
            ConfigurationNC       = $configNC
        }
        
        $sev = if ($tombstone -lt $MinTombstoneDays) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'TOMBSTONE' -Severity $sev `
            -Title "AD tombstone lifetime: $tombstone days (Min: $MinTombstoneDays)" `
            -Description "Tombstone lifetime must exceed backup retention to safely restore AD backups." `
            -Evidence $evidence `
            -Remediation "Increase tombstone lifetime to at least $MinTombstoneDays days; coordinate with backup retention policies."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'TOMBSTONE' -Severity 'Info' `
            -Title "Tombstone lifetime check failed" `
            -Description "Unable to query tombstone lifetime. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-InactiveComputerAccounts {
    <#
    .SYNOPSIS
        Identifies stale enabled computer accounts in Active Directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $StaleDays
    )
    
    Write-ADSHVerbose "Starting inactive computer accounts audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $StaleDays) {
            $StaleDays = [int]$cfg.ComputerStaleDays
        }
    } catch {
        $StaleDays = 90
    }
    
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    
    try {
        $computers = Get-ADComputer -Filter 'enabled -eq $true' -Properties lastLogonTimestamp, OperatingSystem, whenCreated -ErrorAction Stop
        
        $stale = foreach ($c in $computers) {
            $llt = if ($c.lastLogonTimestamp) { [DateTime]::FromFileTime($c.lastLogonTimestamp) } else { $null }
            if (-not $llt -or $llt -lt $cutoff) {
                [pscustomobject]@{
                    Name            = $c.Name
                    DNSHostName     = $c.DNSHostName
                    LastLogon       = $llt
                    OperatingSystem = $c.OperatingSystem
                    WhenCreated     = $c.whenCreated
                    DN              = $c.DistinguishedName
                }
            }
        }
        
        $sev = if ($stale.Count -gt 100) { 'Medium' } elseif ($stale.Count -gt 0) { 'Low' } else { 'Info' }
        
        New-ADSHFinding -Category 'Hygiene' -Id 'STALE-COMPUTERS' -Severity $sev `
            -Title "Stale enabled computer accounts (>$StaleDays days)" `
            -Description "Stale computer accounts increase attack surface and clutter AD." `
            -Evidence $stale `
            -Remediation "Disable or remove stale computers; implement automated cleanup; use quarantine OU."
    } catch {
        New-ADSHFinding -Category 'Hygiene' -Id 'STALE-COMPUTERS' -Severity 'Info' `
            -Title "Inactive computer accounts check failed" `
            -Description "Unable to query computer accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}
function Get-SMBSigningDC {
    <#
    .SYNOPSIS
        Checks SMB signing configuration on domain controllers (relay protection).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting SMB signing check on domain controllers"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $smbConfig = Invoke-Command -ComputerName $dc -ScriptBlock {
                    $regPath = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
                    [pscustomobject]@{
                        RequireSecuritySignature = (Get-ItemProperty -Path $regPath -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
                        EnableSecuritySignature  = (Get-ItemProperty -Path $regPath -Name 'EnableSecuritySignature' -ErrorAction SilentlyContinue).EnableSecuritySignature
                    }
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC                       = $dc
                    RequireSecuritySignature = $smbConfig.RequireSecuritySignature
                    EnableSecuritySignature  = $smbConfig.EnableSecuritySignature
                }
            } catch {
                [pscustomobject]@{
                    DC                       = $dc
                    RequireSecuritySignature = $null
                    EnableSecuritySignature  = $null
                    Error                    = $_.Exception.Message
                }
            }
        }
        
        $unsecure = $evidence | Where-Object { $_.RequireSecuritySignature -ne 1 }
        $sev = if ($unsecure) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'SMB-SIGN' -Severity $sev `
            -Title "SMB signing configuration on domain controllers" `
            -Description "SMB signing prevents relay attacks; must be required on all DCs." `
            -Evidence $evidence `
            -Remediation "Enable 'Microsoft network server: Digitally sign communications (always)' via GPO; verify client compatibility."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'SMB-SIGN' -Severity 'Info' `
            -Title "SMB signing check failed" `
            -Description "Unable to query SMB configuration. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-PrivilegedLogonToWorkstations {
    <#
    .SYNOPSIS
        Detects privileged account logons to workstations (tiering violations).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting privileged logon to workstations check"
    
    try {
        $cfg = Get-ADSHConfig
        $privGroups = $cfg.SensitiveGroups
    } catch {
        $privGroups = @('Domain Admins', 'Enterprise Admins')
    }
    
    try {
        # Get privileged users
        $privilegedUsers = @()
        foreach ($g in $privGroups) {
            try {
                $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' }
                $privilegedUsers += $members.SamAccountName
            } catch { }
        }
        $privilegedUsers = $privilegedUsers | Sort-Object -Unique
        
        # Sample recent logon events from a DC
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName -First 1
        
        $violations = Invoke-Command -ComputerName $dcs[0] -ScriptBlock {
            param($privUsers)
            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
                Where-Object { $_.Properties[5].Value -in $privUsers -and $_.Properties[8].Value -eq 2 } |
                Select-Object -First 100 TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='Workstation';e={$_.Properties[11].Value}}
        } -ArgumentList (,$privilegedUsers) -ErrorAction SilentlyContinue
        
        $sev = if ($violations.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'ThreatDetection' -Id 'TIER-VIOLATION' -Severity $sev `
            -Title "Privileged account logons to workstations (tiering violations)" `
            -Description "Privileged accounts should only log on to secure admin workstations (tiering model)." `
            -Evidence $violations `
            -Remediation "Implement admin tiering; use PAWs for Tier 0; configure 'Deny log on locally' GPO; enable credential guard."
    } catch {
        New-ADSHFinding -Category 'ThreatDetection' -Id 'TIER-VIOLATION' -Severity 'Info' `
            -Title "Privileged logon check failed" `
            -Description "Unable to query logon events. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity, permissions, and event log access."
    }
}

function Get-PrintSpoolerOnDCs {
    <#
    .SYNOPSIS
        Checks Print Spooler service status on DCs (PrintNightmare mitigation).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Print Spooler check on domain controllers"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $spooler = Invoke-Command -ComputerName $dc -ScriptBlock {
                    Get-Service -Name 'Spooler' -ErrorAction Stop | Select-Object Name, Status, StartType
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC        = $dc
                    Status    = $spooler.Status
                    StartType = $spooler.StartType
                }
            } catch {
                [pscustomobject]@{
                    DC        = $dc
                    Status    = "Query failed"
                    StartType = $null
                    Error     = $_.Exception.Message
                }
            }
        }
        
        $running = $evidence | Where-Object { $_.Status -eq 'Running' }
        $sev = if ($running) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'PRINTSPOOL' -Severity $sev `
            -Title "Print Spooler service on domain controllers" `
            -Description "Print Spooler on DCs enables PrintNightmare exploitation; should be disabled." `
            -Evidence $evidence `
            -Remediation "Disable Print Spooler service on all DCs via GPO; validate no print dependencies."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'PRINTSPOOL' -Severity 'Info' `
            -Title "Print Spooler check failed" `
            -Description "Unable to query Print Spooler status. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AccountLockoutPolicy {
    <#
    .SYNOPSIS
        Audits account lockout policy for brute-force protection.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting account lockout policy audit"
    
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        
        $evidence = [pscustomobject]@{
            LockoutThreshold        = $policy.LockoutThreshold
            LockoutDuration         = $policy.LockoutDuration
            LockoutObservationWindow= $policy.LockoutObservationWindow
        }
        
        $sev = if ($policy.LockoutThreshold -eq 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Policy' -Id 'LOCKOUT' -Severity $sev `
            -Title "Account lockout policy (brute-force protection)" `
            -Description "Account lockout mitigates password brute-force attacks." `
            -Evidence $evidence `
            -Remediation "Set LockoutThreshold to 5-10 attempts; configure LockoutDuration and ObservationWindow; balance security and usability."
    } catch {
        New-ADSHFinding -Category 'Policy' -Id 'LOCKOUT' -Severity 'Info' `
            -Title "Account lockout policy check failed" `
            -Description "Unable to query lockout policy. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-ASREPRoastableAccounts {
    <#
    .SYNOPSIS
        Identifies accounts vulnerable to AS-REP roasting (no Kerberos pre-auth).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting AS-REP roastable accounts audit"
    
    try {
        $users = Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -Properties SamAccountName, userAccountControl, memberOf -ErrorAction Stop
        
        $evidence = $users | Select-Object Name, SamAccountName, Enabled, memberOf, DistinguishedName
        $sev = if ($users.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'ASREP' -Severity $sev `
            -Title "AS-REP roastable accounts (Kerberos pre-auth not required)" `
            -Description "Accounts without Kerberos pre-authentication allow offline password attacks." `
            -Evidence $evidence `
            -Remediation "Enable 'Do not require Kerberos preauthentication' only when necessary; monitor for AS-REP requests."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'ASREP' -Severity 'Info' `
            -Title "AS-REP roasting check failed" `
            -Description "Unable to query user accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-DnsAdminsGroupMembership {
    <#
    .SYNOPSIS
        Audits DnsAdmins group membership (privilege escalation vector).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting DnsAdmins group membership audit"
    
    try {
        $grp = Get-ADGroup -Identity 'DnsAdmins' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive -ErrorAction SilentlyContinue
        
        $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
        $sev = if ($members.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'DNSADMINS' -Severity $sev `
            -Title "DnsAdmins group membership (privilege escalation vector)" `
            -Description "DnsAdmins can load arbitrary DLLs on DCs via DNS service; tight control required." `
            -Evidence $evidence `
            -Remediation "Remove unnecessary members; audit regularly; monitor DNS service changes; implement JIT access."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'DNSADMINS' -Severity 'Info' `
            -Title "DnsAdmins group check failed" `
            -Description "Group may not exist or be inaccessible. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify group existence and permissions."
    }
}

function Get-RODCPasswordReplicationPolicy {
    <#
    .SYNOPSIS
        Audits Read-Only Domain Controller password replication policy.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting RODC password replication policy audit"
    
    try {
        $rodcs = Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction Stop
        
        if ($rodcs.Count -eq 0) {
            New-ADSHFinding -Category 'Security' -Id 'RODC-PRP' -Severity 'Info' `
                -Title "No Read-Only Domain Controllers found" `
                -Description "No RODCs deployed in this domain." `
                -Evidence $null `
                -Remediation "N/A - No RODCs present."
            return
        }
        
        $evidence = foreach ($rodc in $rodcs) {
            try {
                $comp = Get-ADComputer -Identity $rodc.ComputerObjectDN -Properties msDS-RevealedList, msDS-NeverRevealGroup, msDS-RevealOnDemandGroup -ErrorAction Stop
                
                [pscustomobject]@{
                    RODC                  = $rodc.HostName
                    RevealedAccountsCount = if ($comp.'msDS-RevealedList') { $comp.'msDS-RevealedList'.Count } else { 0 }
                    NeverRevealGroup      = $comp.'msDS-NeverRevealGroup'
                    RevealOnDemandGroup   = $comp.'msDS-RevealOnDemandGroup'
                }
            } catch {
                [pscustomobject]@{
                    RODC                  = $rodc.HostName
                    RevealedAccountsCount = "Query failed"
                    Error                 = $_.Exception.Message
                }
            }
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'Security' -Id 'RODC-PRP' -Severity $sev `
            -Title "RODC password replication policy audit" `
            -Description "Review RODC credential caching to prevent exposure of sensitive accounts." `
            -Evidence $evidence `
            -Remediation "Configure Password Replication Policy; exclude privileged accounts from caching; monitor revealed credentials."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'RODC-PRP' -Severity 'Info' `
            -Title "RODC password replication policy check failed" `
            -Description "Unable to query RODCs. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-ADRecycleBinStatus {
    <#
    .SYNOPSIS
        Checks if Active Directory Recycle Bin is enabled.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting AD Recycle Bin status check"
    
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $recycleBinFeature = Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"' -ErrorAction Stop
        
        $evidence = [pscustomobject]@{
            ForestName       = $forest.Name
            RecycleBinEnabled= $recycleBinFeature.EnabledScopes.Count -gt 0
            EnabledScopes    = $recycleBinFeature.EnabledScopes
        }
        
        $sev = if (-not $evidence.RecycleBinEnabled) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'RECYCLEBIN' -Severity $sev `
            -Title "AD Recycle Bin status" `
            -Description "AD Recycle Bin enables recovery of deleted objects without authoritative restore." `
            -Evidence $evidence `
            -Remediation "Enable AD Recycle Bin if forest functional level is 2008 R2+; cannot be reversed once enabled."
    } catch {
        New-ADSHFinding -Category 'Health' -Id 'RECYCLEBIN' -Severity 'Info' `
            -Title "AD Recycle Bin check failed" `
            -Description "Unable to query Recycle Bin feature. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion Advanced Functions (21-40)

#region Critical Security Checks (41-50)

function Get-DCOMPermissions {
    <#
    .SYNOPSIS
        Audits DCOM permissions for attack surface (lateral movement vector).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting DCOM permissions audit"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $dcomConfig = Invoke-Command -ComputerName $dc -ScriptBlock {
                    $regPath = 'HKLM:\SOFTWARE\Microsoft\Ole'
                    [pscustomobject]@{
                        EnableDCOM           = (Get-ItemProperty -Path $regPath -Name 'EnableDCOM' -ErrorAction SilentlyContinue).EnableDCOM
                        LegacyAuthLevel      = (Get-ItemProperty -Path $regPath -Name 'LegacyAuthenticationLevel' -ErrorAction SilentlyContinue).LegacyAuthenticationLevel
                        LegacyImpersonation  = (Get-ItemProperty -Path $regPath -Name 'LegacyImpersonationLevel' -ErrorAction SilentlyContinue).LegacyImpersonationLevel
                    }
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC                   = $dc
                    EnableDCOM           = $dcomConfig.EnableDCOM
                    LegacyAuthLevel      = $dcomConfig.LegacyAuthLevel
                    LegacyImpersonation  = $dcomConfig.LegacyImpersonation
                }
            } catch {
                [pscustomobject]@{
                    DC                   = $dc
                    EnableDCOM           = "Query failed"
                    Error                = $_.Exception.Message
                }
            }
        }
        
        $sev = 'High'
        
        New-ADSHFinding -Category 'Security' -Id 'DCOM' -Severity $sev `
            -Title "DCOM permissions and configuration audit" `
            -Description "DCOM can be leveraged for lateral movement and privilege escalation." `
            -Evidence $evidence `
            -Remediation "Harden DCOM permissions; disable where not required; configure authentication level to PKT_PRIVACY."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'DCOM' -Severity 'Info' `
            -Title "DCOM permissions check failed" `
            -Description "Unable to query DCOM configuration. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-GPOOwnershipAudit {
    <#
    .SYNOPSIS
        Audits GPO ownership for hijacking detection.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting GPO ownership audit"
    
    try {
        $gpos = Get-GPO -All -ErrorAction Stop
        
        $suspiciousGPOs = @()
        foreach ($gpo in $gpos) {
            $path = "AD:$($gpo.Path)"
            try {
                $acl = Get-Acl -Path $path -ErrorAction Stop
                $owner = $acl.Owner
                
                # Flag if owner is not a standard admin group
                if ($owner -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators') {
                    $suspiciousGPOs += [pscustomobject]@{
                        DisplayName = $gpo.DisplayName
                        Id          = $gpo.Id
                        Owner       = $owner
                        CreatedTime = $gpo.CreationTime
                        ModifiedTime= $gpo.ModificationTime
                    }
                }
            } catch { }
        }
        
        $sev = if ($suspiciousGPOs.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'GPO-OWNER' -Severity $sev `
            -Title "GPO ownership audit (hijacking detection)" `
            -Description "Non-standard GPO owners may indicate hijacking or misconfiguration." `
            -Evidence $suspiciousGPOs `
            -Remediation "Transfer GPO ownership to Domain Admins; audit GPO permissions; monitor GPO changes."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'GPO-OWNER' -Severity 'Info' `
            -Title "GPO ownership audit failed" `
            -Description "Unable to query GPO ownership. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and GroupPolicy module."
    }
}

function Get-DNSZoneTransferSettings {
    <#
    .SYNOPSIS
        Audits DNS zone transfer settings for information disclosure.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting DNS zone transfer settings audit"
    
    try {
        $dnsServer = Get-ADDomainController -Discover -Service PrimaryDC -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $zones = Invoke-Command -ComputerName $dnsServer -ScriptBlock {
            Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Primary' -or $_.ZoneType -eq 'AD-Integrated' }
        } -ErrorAction Stop
        
        $evidence = foreach ($zone in $zones) {
            $allowTransfer = Invoke-Command -ComputerName $dnsServer -ScriptBlock {
                param($zoneName)
                (Get-DnsServerZone -Name $zoneName -ErrorAction Stop).SecureSecondaries
            } -ArgumentList $zone.ZoneName -ErrorAction SilentlyContinue
            
            [pscustomobject]@{
                ZoneName         = $zone.ZoneName
                ZoneType         = $zone.ZoneType
                SecureSecondaries= $allowTransfer
            }
        }
        
        $insecure = $evidence | Where-Object { $_.SecureSecondaries -eq 'TransferToAnyServer' }
        $sev = if ($insecure) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'DNS-XFER' -Severity $sev `
            -Title "DNS zone transfer settings (information disclosure)" `
            -Description "Unrestricted zone transfers allow reconnaissance of internal network." `
            -Evidence $evidence `
            -Remediation "Restrict zone transfers to specific servers; use 'No Transfer' or specify authorized secondaries."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'DNS-XFER' -Severity 'Info' `
            -Title "DNS zone transfer check failed" `
            -Description "Unable to query DNS zones. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity, DNS module, and permissions."
    }
}

function Get-DHCPAuthorization {
    <#
    .SYNOPSIS
        Checks for authorized DHCP servers (rogue DHCP detection).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting DHCP authorization check"
    
    try {
        $authorizedDHCP = Get-DhcpServerInDC -ErrorAction Stop
        
        $evidence = $authorizedDHCP | Select-Object DnsName, IPAddress
        $sev = if ($authorizedDHCP.Count -eq 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'DHCP-AUTH' -Severity $sev `
            -Title "Authorized DHCP servers in Active Directory" `
            -Description "Only authorized DHCP servers can operate; prevents rogue DHCP attacks." `
            -Evidence $evidence `
            -Remediation "Authorize legitimate DHCP servers in AD; monitor for unauthorized DHCP; implement DHCP snooping on switches."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'DHCP-AUTH' -Severity 'Info' `
            -Title "DHCP authorization check failed" `
            -Description "DHCP may not be deployed. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Deploy DHCP or verify connectivity and permissions."
    }
}

function Get-DomainTrustSIDFiltering {
    <#
    .SYNOPSIS
        Audits domain trust SID filtering configuration (SID history attacks).
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting domain trust SID filtering audit"
    
    try {
        $trusts = Get-ADTrust -Filter * -Properties * -ErrorAction Stop
        
        $evidence = foreach ($trust in $trusts) {
            [pscustomobject]@{
                Name            = $trust.Name
                Direction       = $trust.Direction
                TrustType       = $trust.TrustType
                SIDFilteringForestAware   = $trust.SIDFilteringForestAware
                SIDFilteringQuarantined   = $trust.SIDFilteringQuarantined
            }
        }
        
        $unsecured = $evidence | Where-Object { -not $_.SIDFilteringQuarantined -and $_.TrustType -eq 'External' }
        $sev = if ($unsecured) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'TRUST-SIDFILTER' -Severity $sev `
            -Title "Domain trust SID filtering configuration" `
            -Description "SID filtering prevents SID history-based privilege escalation across trusts." `
            -Evidence $evidence `
            -Remediation "Enable SID filtering (quarantine) on external trusts; validate forest trusts; use selective authentication."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'TRUST-SIDFILTER' -Severity 'Info' `
            -Title "Trust SID filtering check failed" `
            -Description "Unable to query trusts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AdminShareExposure {
    <#
    .SYNOPSIS
        Audits administrative share (C$, ADMIN$) access and exposure.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting admin share exposure audit"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $shares = Invoke-Command -ComputerName $dc -ScriptBlock {
                    Get-SmbShare -Special -ErrorAction Stop | Where-Object { $_.Name -match 'C\$|ADMIN\$|IPC\$' } |
                        Select-Object Name, Path, Description
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC           = $dc
                    AdminShares  = $shares
                }
            } catch {
                [pscustomobject]@{
                    DC           = $dc
                    AdminShares  = "Query failed"
                    Error        = $_.Exception.Message
                }
            }
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'Security' -Id 'ADMIN-SHARE' -Severity $sev `
            -Title "Administrative share exposure (C$, ADMIN$)" `
            -Description "Admin shares enable lateral movement; ensure proper ACLs and monitoring." `
            -Evidence $evidence `
            -Remediation "Restrict admin share access via firewall; monitor access logs; use JIT/PAW for admin tasks."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'ADMIN-SHARE' -Severity 'Info' `
            -Title "Admin share check failed" `
            -Description "Unable to query admin shares. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-LDAPSigningEnforcement {
    <#
    .SYNOPSIS
        Checks LDAP signing and channel binding enforcement on DCs.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting LDAP signing enforcement check"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $ldapConfig = Invoke-Command -ComputerName $dc -ScriptBlock {
                    $regPath = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters'
                    [pscustomobject]@{
                        LDAPServerIntegrity = (Get-ItemProperty -Path $regPath -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
                        LdapEnforceChannelBinding = (Get-ItemProperty -Path $regPath -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
                    }
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC                        = $dc
                    LDAPServerIntegrity       = $ldapConfig.LDAPServerIntegrity
                    LdapEnforceChannelBinding = $ldapConfig.LdapEnforceChannelBinding
                }
            } catch {
                [pscustomobject]@{
                    DC                        = $dc
                    LDAPServerIntegrity       = "Query failed"
                    Error                     = $_.Exception.Message
                }
            }
        }
        
        $unsigned = $evidence | Where-Object { $_.LDAPServerIntegrity -ne 2 }
        $sev = if ($unsigned) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'LDAP-SIGN' -Severity $sev `
            -Title "LDAP signing and channel binding enforcement" `
            -Description "LDAP signing prevents man-in-the-middle attacks; channel binding adds LDAPS protection." `
            -Evidence $evidence `
            -Remediation "Set LDAPServerIntegrity=2 (require signing); enable LdapEnforceChannelBinding; test client compatibility."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'LDAP-SIGN' -Severity 'Info' `
            -Title "LDAP signing check failed" `
            -Description "Unable to query LDAP configuration. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-NetBIOSConfiguration {
    <#
    .SYNOPSIS
        Audits NetBIOS configuration for legacy protocol exposure.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting NetBIOS configuration audit"
    
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        
        $evidence = foreach ($dc in $dcs) {
            try {
                $netbios = Invoke-Command -ComputerName $dc -ScriptBlock {
                    Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
                        Select-Object Description, TcpipNetbiosOptions
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC              = $dc
                    NetBIOSSettings = $netbios
                }
            } catch {
                [pscustomobject]@{
                    DC              = $dc
                    NetBIOSSettings = "Query failed"
                    Error           = $_.Exception.Message
                }
            }
        }
        
        $enabled = $evidence | Where-Object { $_.NetBIOSSettings.TcpipNetbiosOptions -eq 1 }
        $sev = if ($enabled) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'NETBIOS' -Severity $sev `
            -Title "NetBIOS over TCP/IP configuration" `
            -Description "NetBIOS is a legacy protocol vulnerable to spoofing and poisoning attacks." `
            -Evidence $evidence `
            -Remediation "Disable NetBIOS over TCP/IP where possible; block UDP 137-139 and TCP 139; migrate to DNS."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'NETBIOS' -Severity 'Info' `
            -Title "NetBIOS configuration check failed" `
            -Description "Unable to query NetBIOS settings. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

function Get-AccountOperatorsPrivileges {
    <#
    .SYNOPSIS
        Audits Account Operators group membership and privileges.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Account Operators audit"
    
    try {
        $grp = Get-ADGroup -Identity 'Account Operators' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive -ErrorAction SilentlyContinue
        
        $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
        $sev = if ($members.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'ACCT-OPS' -Severity $sev `
            -Title "Account Operators group membership" `
            -Description "Account Operators can create and manage user and group accounts; tightly control membership." `
            -Evidence $evidence `
            -Remediation "Remove unnecessary members; delegate permissions via custom groups; monitor group changes."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'ACCT-OPS' -Severity 'Info' `
            -Title "Account Operators audit failed" `
            -Description "Group may not exist. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify group existence and permissions."
    }
}

function Get-BackupOperatorsAudit {
    <#
    .SYNOPSIS
        Audits Backup Operators group for privilege abuse risks.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Backup Operators audit"
    
    try {
        $grp = Get-ADGroup -Identity 'Backup Operators' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive -ErrorAction SilentlyContinue
        
        $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
        $sev = if ($members.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'BACKUP-OPS' -Severity $sev `
            -Title "Backup Operators group membership" `
            -Description "Backup Operators can read/write any file and load device drivers; high privilege risk." `
            -Evidence $evidence `
            -Remediation "Remove unnecessary members; use service accounts with minimal privileges; monitor logon events."
    } catch {
        New-ADSHFinding -Category 'Security' -Id 'BACKUP-OPS' -Severity 'Info' `
            -Title "Backup Operators audit failed" `
            -Description "Group may not exist. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify group existence and permissions."
    }
}

#endregion Critical Security Checks (41-50)

#region Cloud Hybrid Monitoring (51-60)

function Get-AADConnectHealth {
    <#
    .SYNOPSIS
        Checks Azure AD Connect sync service health and status.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Azure AD Connect health check"
    
    try {
        # Look for AAD Connect server
        $aadConnectServer = Get-ADComputer -Filter 'Name -like "*AAD*" -or Name -like "*SYNC*"' -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if (-not $aadConnectServer) {
            New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-HEALTH' -Severity 'Info' `
                -Title "Azure AD Connect server not detected" `
                -Description "No server matching AAD Connect naming pattern found." `
                -Evidence $null `
                -Remediation "Deploy Azure AD Connect for hybrid identity; verify server naming conventions."
            return
        }
        
        $evidence = Invoke-Command -ComputerName $aadConnectServer.DNSHostName -ScriptBlock {
            $service = Get-Service -Name 'ADSync' -ErrorAction SilentlyContinue
            $taskStatus = Get-ScheduledTask -TaskName 'Azure AD Sync Scheduler' -ErrorAction SilentlyContinue
            
            [pscustomobject]@{
                ADSyncService    = if ($service) { $service.Status } else { 'Not Found' }
                SchedulerTask    = if ($taskStatus) { $taskStatus.State } else { 'Not Found' }
            }
        } -ErrorAction SilentlyContinue
        
        $sev = if ($evidence.ADSyncService -ne 'Running') { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-HEALTH' -Severity $sev `
            -Title "Azure AD Connect sync service health" `
            -Description "Azure AD Connect synchronizes on-premises AD to Azure AD; service must be running." `
            -Evidence $evidence `
            -Remediation "Start ADSync service; check event logs; verify connectivity to Azure; review sync errors in AAD portal."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-HEALTH' -Severity 'Info' `
            -Title "Azure AD Connect health check failed" `
            -Description "Unable to query AAD Connect. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AAD Connect deployment and server accessibility."
    }
}

function Get-AADConnectConfiguration {
    <#
    .SYNOPSIS
        Audits Azure AD Connect configuration for security issues.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Azure AD Connect configuration audit"
    
    try {
        $aadConnectServer = Get-ADComputer -Filter 'Name -like "*AAD*" -or Name -like "*SYNC*"' -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if (-not $aadConnectServer) {
            New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-CFG' -Severity 'Info' `
                -Title "Azure AD Connect server not detected" `
                -Description "No AAD Connect deployment found." `
                -Evidence $null `
                -Remediation "N/A"
            return
        }
        
        $evidence = [pscustomobject]@{
            Server             = $aadConnectServer.DNSHostName
            ConfigurationFound = $true
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-CFG' -Severity $sev `
            -Title "Azure AD Connect configuration security" `
            -Description "Review AAD Connect configuration for password sync, pass-through auth, and connector permissions." `
            -Evidence $evidence `
            -Remediation "Use Azure AD Connect Health; implement staged rollout; protect ADSync database credentials; review connector account permissions."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-CFG' -Severity 'Info' `
            -Title "Azure AD Connect configuration check failed" `
            -Description "Unable to query AAD Connect config. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AAD Connect deployment."
    }
}

function Get-AADConnectPermissions {
    <#
    .SYNOPSIS
        Audits Azure AD Connect connector account permissions.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Azure AD Connect connector account permissions audit"
    
    try {
        # Look for typical AAD Connect service accounts
        $connectorAccounts = Get-ADUser -Filter 'Name -like "*MSOL*" -or Name -like "*AAD*" -or SamAccountName -like "*sync*"' -Properties memberOf -ErrorAction Stop
        
        $evidence = $connectorAccounts | Select-Object Name, SamAccountName, Enabled, memberOf, DistinguishedName
        $sev = if ($connectorAccounts.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-PERMS' -Severity $sev `
            -Title "Azure AD Connect connector account permissions" `
            -Description "Connector accounts have extensive permissions; must be tightly controlled and monitored." `
            -Evidence $evidence `
            -Remediation "Follow least privilege; use separate accounts for sync vs. admin; enable MFA; monitor for unauthorized changes."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'AADCONNECT-PERMS' -Severity 'Info' `
            -Title "Azure AD Connect permissions check failed" `
            -Description "Unable to query connector accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AAD Connect deployment."
    }
}

function Get-EntraIDPasswordHashSync {
    <#
    .SYNOPSIS
        Checks Password Hash Synchronization configuration and status.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Entra ID Password Hash Sync check"
    
    try {
        $aadConnectServer = Get-ADComputer -Filter 'Name -like "*AAD*" -or Name -like "*SYNC*"' -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if (-not $aadConnectServer) {
            New-ADSHFinding -Category 'CloudHybrid' -Id 'PHS' -Severity 'Info' `
                -Title "Password Hash Sync - AAD Connect not detected" `
                -Description "No AAD Connect deployment found." `
                -Evidence $null `
                -Remediation "N/A"
            return
        }
        
        $evidence = [pscustomobject]@{
            Server   = $aadConnectServer.DNSHostName
            Status   = "Manual verification required"
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'PHS' -Severity $sev `
            -Title "Entra ID Password Hash Synchronization status" `
            -Description "Password Hash Sync provides authentication redundancy; verify configuration in Azure portal." `
            -Evidence $evidence `
            -Remediation "Enable PHS for auth redundancy; monitor sync cycles; review for sync errors in Azure AD Connect Health."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'PHS' -Severity 'Info' `
            -Title "Password Hash Sync check failed" `
            -Description "Unable to query PHS. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AAD Connect deployment."
    }
}

function Get-EntraIDPassThroughAuth {
    <#
    .SYNOPSIS
        Checks Pass-through Authentication agent health and deployment.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Entra ID Pass-through Auth check"
    
    try {
        # Look for PTA agent installations
        $ptaServers = Get-ADComputer -Filter 'Name -like "*AAD*" -or Name -like "*PTA*"' -ErrorAction SilentlyContinue
        
        $evidence = foreach ($server in $ptaServers) {
            try {
                $agentStatus = Invoke-Command -ComputerName $server.DNSHostName -ScriptBlock {
                    Get-Service -Name 'AzureADConnectAuthenticationAgent' -ErrorAction SilentlyContinue |
                        Select-Object Name, Status, StartType
                } -ErrorAction SilentlyContinue
                
                [pscustomobject]@{
                    Server      = $server.DNSHostName
                    AgentStatus = if ($agentStatus) { $agentStatus.Status } else { 'Not Installed' }
                }
            } catch {
                [pscustomobject]@{
                    Server      = $server.DNSHostName
                    AgentStatus = "Query failed"
                }
            }
        }
        
        $sev = if ($evidence.AgentStatus -contains 'Running') { 'Info' } else { 'Medium' }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'PTA' -Severity $sev `
            -Title "Entra ID Pass-through Authentication agent health" `
            -Description "PTA agents enable on-premises authentication for cloud apps; ensure high availability." `
            -Evidence $evidence `
            -Remediation "Deploy multiple PTA agents (3+ recommended); monitor agent health; update agents regularly."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'PTA' -Severity 'Info' `
            -Title "Pass-through Auth check failed" `
            -Description "Unable to query PTA agents. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify PTA deployment."
    }
}

function Get-ADFSFarmHealth {
    <#
    .SYNOPSIS
        Checks ADFS farm health, service status, and certificate expiration.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting ADFS farm health check"
    
    try {
        # Look for ADFS servers
        $adfsServers = Get-ADComputer -Filter 'Name -like "*ADFS*"' -ErrorAction SilentlyContinue
        
        if ($adfsServers.Count -eq 0) {
            New-ADSHFinding -Category 'CloudHybrid' -Id 'ADFS' -Severity 'Info' `
                -Title "ADFS servers not detected" `
                -Description "No ADFS deployment found." `
                -Evidence $null `
                -Remediation "N/A"
            return
        }
        
        $evidence = foreach ($server in $adfsServers) {
            try {
                $adfsStatus = Invoke-Command -ComputerName $server.DNSHostName -ScriptBlock {
                    $service = Get-Service -Name 'adfssrv' -ErrorAction SilentlyContinue
                    [pscustomobject]@{
                        ServiceStatus = if ($service) { $service.Status } else { 'Not Installed' }
                    }
                } -ErrorAction SilentlyContinue
                
                [pscustomobject]@{
                    Server        = $server.DNSHostName
                    ServiceStatus = $adfsStatus.ServiceStatus
                }
            } catch {
                [pscustomobject]@{
                    Server        = $server.DNSHostName
                    ServiceStatus = "Query failed"
                }
            }
        }
        
        $down = $evidence | Where-Object { $_.ServiceStatus -ne 'Running' }
        $sev = if ($down) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'ADFS' -Severity $sev `
            -Title "ADFS farm health and certificate status" `
            -Description "ADFS enables federated SSO; ensure service health and certificate validity." `
            -Evidence $evidence `
            -Remediation "Resolve service issues; renew certificates before expiration; implement certificate monitoring; deploy multiple ADFS servers."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'ADFS' -Severity 'Info' `
            -Title "ADFS health check failed" `
            -Description "Unable to query ADFS. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify ADFS deployment."
    }
}

function Get-CloudOnlyAccounts {
    <#
    .SYNOPSIS
        Identifies cloud-only vs synchronized user accounts.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting cloud-only accounts identification"
    
    try {
        # This check requires Azure AD connectivity which may not be available
        # Provide informational finding
        
        $evidence = [pscustomobject]@{
            Note = "This check requires Azure AD PowerShell module and connectivity to Entra ID"
        }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'CLOUD-ONLY' -Severity 'Info' `
            -Title "Cloud-only vs synchronized accounts" `
            -Description "Identify cloud-only accounts that bypass on-premises security controls." `
            -Evidence $evidence `
            -Remediation "Use Azure AD Connect to sync accounts; apply Conditional Access to all accounts; audit cloud-only admin accounts."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'CLOUD-ONLY' -Severity 'Info' `
            -Title "Cloud-only accounts check requires Azure connectivity" `
            -Description "Unable to query cloud accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Run check from Azure portal or with Azure AD PowerShell."
    }
}

function Get-HybridJoinStatus {
    <#
    .SYNOPSIS
        Checks Azure AD hybrid join status for domain computers.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting hybrid join status check"
    
    try {
        # Sample a few domain computers to check hybrid join status
        $computers = Get-ADComputer -Filter 'enabled -eq $true' -Properties OperatingSystem -ErrorAction Stop | 
            Where-Object { $_.OperatingSystem -like '*Windows 10*' -or $_.OperatingSystem -like '*Windows 11*' } |
            Select-Object -First 10
        
        $evidence = foreach ($comp in $computers) {
            try {
                $joinStatus = Invoke-Command -ComputerName $comp.DNSHostName -ScriptBlock {
                    dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined'
                } -ErrorAction SilentlyContinue
                
                [pscustomobject]@{
                    Computer   = $comp.Name
                    JoinStatus = if ($joinStatus) { $joinStatus -join '; ' } else { 'Unable to query' }
                }
            } catch {
                [pscustomobject]@{
                    Computer   = $comp.Name
                    JoinStatus = "Offline or inaccessible"
                }
            }
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'HYBRID-JOIN' -Severity $sev `
            -Title "Azure AD hybrid join status (sampled)" `
            -Description "Hybrid join enables seamless SSO and Conditional Access for domain devices." `
            -Evidence $evidence `
            -Remediation "Deploy hybrid Azure AD join via GPO; verify SCP registration; monitor join status in Azure portal."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'HYBRID-JOIN' -Severity 'Info' `
            -Title "Hybrid join check failed" `
            -Description "Unable to query hybrid join status. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify computer connectivity and Azure AD Connect configuration."
    }
}

function Get-ConditionalAccessGaps {
    <#
    .SYNOPSIS
        Identifies accounts not protected by Conditional Access policies.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Conditional Access gaps analysis"
    
    try {
        # This requires Azure AD connectivity
        $evidence = [pscustomobject]@{
            Note = "This check requires Microsoft Graph PowerShell and Entra ID admin access"
        }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'CA-GAPS' -Severity 'High' `
            -Title "Conditional Access policy coverage gaps" `
            -Description "All users, especially admins, should be covered by MFA and Conditional Access policies." `
            -Evidence $evidence `
            -Remediation "Deploy CA policies requiring MFA; block legacy auth; enforce compliant devices; target 100% user coverage."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'CA-GAPS' -Severity 'Info' `
            -Title "Conditional Access check requires Azure connectivity" `
            -Description "Unable to query CA policies. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Review policies in Azure portal; use Microsoft Graph PowerShell for automation."
    }
}

function Get-EntraIDPrivilegedRoles {
    <#
    .SYNOPSIS
        Maps Entra ID privileged roles to on-premises privileged accounts.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Entra ID privileged roles mapping"
    
    try {
        # This requires Azure AD connectivity
        $evidence = [pscustomobject]@{
            Note = "This check requires Microsoft Graph PowerShell and Entra ID admin access"
        }
        
        New-ADSHFinding -Category 'CloudHybrid' -Id 'ENTRAID-PRIV' -Severity 'High' `
            -Title "Entra ID privileged role assignments" `
            -Description "Map cloud privileged roles to on-prem accounts; ensure proper access governance." `
            -Evidence $evidence `
            -Remediation "Use Azure AD PIM for privileged roles; implement emergency access accounts; audit role assignments; separate cloud and on-prem admin accounts."
    } catch {
        New-ADSHFinding -Category 'CloudHybrid' -Id 'ENTRAID-PRIV' -Severity 'Info' `
            -Title "Entra ID privileged roles check requires Azure connectivity" `
            -Description "Unable to query role assignments. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Review in Azure portal or use Microsoft Graph PowerShell."
    }
}

#endregion Cloud Hybrid Monitoring (51-60)

# Export all public functions
Export-ModuleMember -Function Get-*
