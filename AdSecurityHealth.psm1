#requires -Version 5.1
# ADSecurityHealth.psm1
# PowerShell toolkit for Active Directory security and health monitoring

#region Helpers

function Initialize-ADSHEnvironment {
    <#
    .SYNOPSIS
        Initializes the Active Directory Security Health environment by loading required modules.
    
    .DESCRIPTION
        Validates and imports required PowerShell modules for AD security checks.
        Provides warnings if modules are not available.
    
    .PARAMETER RequiredModules
        Array of module names to import. Defaults to ActiveDirectory and GroupPolicy.
    
    .EXAMPLE
        Initialize-ADSHEnvironment
        Imports default modules (ActiveDirectory, GroupPolicy).
    
    .EXAMPLE
        Initialize-ADSHEnvironment -RequiredModules @('ActiveDirectory')
        Imports only the ActiveDirectory module.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
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
        Loads configuration settings from a JSON file. If the file doesn't exist or
        cannot be parsed, returns default configuration values.
    
    .PARAMETER Path
        Path to the configuration JSON file. Defaults to adsh-config.json in module directory.
    
    .EXAMPLE
        $config = Get-ADSHConfig
        Loads configuration from default location.
    
    .EXAMPLE
        $config = Get-ADSHConfig -Path "C:\custom\config.json"
        Loads configuration from a custom path.
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
            Write-ADSHVerbose "Error parsing config file, falling back to defaults: $_"
        }
    } else {
        Write-ADSHVerbose "Configuration file not found at '$Path', using defaults"
    }
    
    # Defaults if config not found
    Write-ADSHVerbose "Returning default configuration values"
    [pscustomobject]@{
        StaleDays                     = 90
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
            'Print Operators'
        )
        CriticalServices              = @('NTDS','KDC','DNS','Netlogon','LanmanServer','DFSR')
        DNSDcDiagTimeoutSeconds       = 180
        SysvolRequireDFSR             = $true
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
        Severity level: Info, Low, Medium, High, or Critical.
    
    .PARAMETER Title
        Short title describing the finding.
    
    .PARAMETER Description
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
    
    Write-ADSHVerbose "Creating finding: [$Category] $Id - $Severity - $Title"
    
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

#region 1. Privileged Group Membership

function Get-PrivilegedGroupMembership {
    <#
    .SYNOPSIS
        Audits membership of privileged Active Directory groups.
    
    .DESCRIPTION
        Enumerates members of sensitive/privileged AD groups to identify potential
        security risks. Returns findings for each group checked.
    
    .PARAMETER Groups
        Array of group names to check. Defaults to sensitive groups from configuration.
    
    .PARAMETER Server
        Target domain controller. If not specified, uses default DC.
    
    .EXAMPLE
        Get-PrivilegedGroupMembership
        Checks default privileged groups.
    
    .EXAMPLE
        Get-PrivilegedGroupMembership -Groups 'Domain Admins' -Server 'DC01'
        Checks specific group on a specific DC.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]] $Groups,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Server
    )
    
    Write-ADSHVerbose "Starting privileged group membership audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Groups) {
            $Groups = $cfg.SensitiveGroups
            Write-ADSHVerbose "Using default sensitive groups from configuration: $($Groups.Count) groups"
        }
    } catch {
        Write-Warning "Failed to load configuration: $($_.Exception.Message)"
        Write-ADSHVerbose "Error loading config: $_"
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
            Write-ADSHVerbose "Found group: $($grp.DistinguishedName)"
            
            $memberParams = @{
                Identity    = $grp.DistinguishedName
                Recursive   = $true
                ErrorAction = 'Stop'
            }
            if ($Server) { $memberParams['Server'] = $Server }
            
            $members = Get-ADGroupMember @memberParams
            Write-ADSHVerbose "Group '$g' has $($members.Count) members"
            
            $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
            $sev = if ($members.Count -gt 0) { 'High' } else { 'Info' }
            
            $findings += New-ADSHFinding -Category 'Security' -Id "PRIV-$($grp.SamAccountName)" -Severity $sev `
                -Title "Privileged group membership: $($grp.SamAccountName)" `
                -Description "List members of privileged group." `
                -Evidence $evidence `
                -Remediation "Review and remove unnecessary members. Enforce tiered admin model and JIT/PIM for elevation."
        } catch {
            Write-Warning "Failed to process group '$g': $($_.Exception.Message)"
            Write-ADSHVerbose "Error processing group '$g': $_"
            
            $findings += New-ADSHFinding -Category 'Security' -Id "PRIV-$g" -Severity 'Info' `
                -Title "Privileged group not found: $g" `
                -Description "Group may not exist in this domain. Error: $($_.Exception.Message)" `
                -Evidence $null `
                -Remediation "Validate domain scope and name."
        }
    }
    
    Write-ADSHVerbose "Completed privileged group membership audit with $($findings.Count) findings"
    $findings
}

#endregion

#region 2. Stale/Inactive Accounts

function Get-StaleAccounts {
    <#
    .SYNOPSIS
        Identifies stale enabled user accounts in Active Directory.
    
    .DESCRIPTION
        Finds enabled user accounts that haven't logged on within the specified
        number of days. Helps identify unused accounts that increase attack surface.
    
    .PARAMETER StaleDays
        Number of days without logon to consider an account stale. Defaults to config value.
    
    .EXAMPLE
        Get-StaleAccounts
        Uses default stale days threshold from configuration.
    
    .EXAMPLE
        Get-StaleAccounts -StaleDays 60
        Finds accounts with no logon in 60+ days.
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
            Write-ADSHVerbose "Using stale days threshold from configuration: $StaleDays days"
        }
    } catch {
        Write-Warning "Failed to load configuration, using default of 90 days"
        $StaleDays = 90
    }
    
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    Write-ADSHVerbose "Cutoff date for stale accounts: $($cutoff.ToString('yyyy-MM-dd'))"
    
    try {
        Write-ADSHVerbose "Querying enabled user accounts"
        $users = Get-ADUser -Filter 'enabled -eq $true' -Properties lastLogonTimestamp,whenCreated,PasswordNeverExpires -ErrorAction Stop
        Write-ADSHVerbose "Found $($users.Count) enabled user accounts"
        
        $stale = foreach ($u in $users) {
            $llt = if ($u.lastLogonTimestamp) { [DateTime]::FromFileTime($u.lastLogonTimestamp) } else { $null }
            if (-not $llt -or $llt -lt $cutoff) {
                [pscustomobject]@{
                    Name                = $u.Name
                    SamAccountName      = $u.SamAccountName
                    LastLogon           = $llt
                    WhenCreated         = $u.whenCreated
                    PasswordNeverExpires= $u.PasswordNeverExpires
                    DN                  = $u.DistinguishedName
                }
            }
        }
        
        Write-ADSHVerbose "Identified $($stale.Count) stale accounts"
        
        $sev = if ($stale.Count -gt 50) { 'High' } elseif ($stale.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Hygiene' -Id 'STALE-ACCOUNTS' -Severity $sev `
            -Title "Stale enabled user accounts (>$StaleDays days)" `
            -Description "Enabled accounts with no recent logon increase attack surface." `
            -Evidence $stale `
            -Remediation "Disable or remove stale accounts. Implement lifecycle automation and time-bound access."
    } catch {
        Write-Warning "Failed to query user accounts: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying accounts: $_"
        
        New-ADSHFinding -Category 'Hygiene' -Id 'STALE-ACCOUNTS' -Severity 'Info' `
            -Title "Stale accounts check failed" `
            -Description "Unable to query user accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 3. Password Policy Audit

function Get-PasswordPolicyAudit {
    <#
    .SYNOPSIS
        Audits Active Directory password policies.
    
    .DESCRIPTION
        Reviews domain default password policy and fine-grained password policies (FGPP)
        for security weaknesses.
    
    .EXAMPLE
        Get-PasswordPolicyAudit
        Returns findings about password policies.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting password policy audit"
    
    try {
        Write-ADSHVerbose "Querying default domain password policy"
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        Write-ADSHVerbose "Retrieved default domain policy"
        
        Write-ADSHVerbose "Querying fine-grained password policies"
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
        Write-ADSHVerbose "Found $($fgpp.Count) fine-grained password policies"
        
        $evidence = [pscustomobject]@{
            DefaultDomain = $domainPolicy
            FineGrained   = $fgpp | Select-Object Name, Precedence, MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, PasswordComplexityEnabled, ReversibleEncryptionEnabled
        }
        
        $sev = 'Medium'
        
        New-ADSHFinding -Category 'Policy' -Id 'PWD-POLICY' -Severity $sev `
            -Title "Password policy audit (domain + FGPP)" `
            -Description "Reviews domain and fine-grained password policies for strength and reversible encryption." `
            -Evidence $evidence `
            -Remediation "Set MinLength >= 14+ or prefer passphrases. Enable complexity. Disable reversible encryption. Consider AAD/SSO and MFA."
    } catch {
        Write-Warning "Failed to retrieve password policies: $($_.Exception.Message)"
        Write-ADSHVerbose "Error retrieving password policies: $_"
        
        New-ADSHFinding -Category 'Policy' -Id 'PWD-POLICY' -Severity 'Info' `
            -Title "Password policy audit failed" `
            -Description "Unable to retrieve password policies. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 4. Accounts with Password Never Expires

function Get-AccountsPasswordNeverExpires {
    <#
    .SYNOPSIS
        Identifies enabled accounts with passwords set to never expire.
    
    .DESCRIPTION
        Finds enabled user accounts with PasswordNeverExpires attribute set,
        which increases security risk.
    
    .EXAMPLE
        Get-AccountsPasswordNeverExpires
        Returns findings about accounts with non-expiring passwords.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting password never expires audit"
    
    try {
        Write-ADSHVerbose "Querying enabled accounts with PasswordNeverExpires=true"
        $users = Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and enabled -eq $true' -Properties PasswordNeverExpires,lastLogonTimestamp -ErrorAction Stop
        Write-ADSHVerbose "Found $($users.Count) accounts with password never expires"
        
        $evidence = $users | Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires, @{n='LastLogon';e={ if ($_.lastLogonTimestamp) {[DateTime]::FromFileTime($_.lastLogonTimestamp)} else {$null}}}, DistinguishedName
        $sev = if ($users.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'PWD-NEVER-EXPIRES' -Severity $sev `
            -Title "Enabled accounts with password set to never expire" `
            -Description "Service or privileged accounts with non-expiring passwords increase risk." `
            -Evidence $evidence `
            -Remediation "Migrate to gMSA or vault-managed secrets; enforce rotation via policy or automation."
    } catch {
        Write-Warning "Failed to query accounts with PasswordNeverExpires: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying accounts: $_"
        
        New-ADSHFinding -Category 'Security' -Id 'PWD-NEVER-EXPIRES' -Severity 'Info' `
            -Title "Password never expires check failed" `
            -Description "Unable to query accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 5. Accounts with Reversible Encryption

function Get-AccountsReversibleEncryption {
    <#
    .SYNOPSIS
        Checks for reversible encryption enabled in password policies.
    
    .DESCRIPTION
        Identifies fine-grained password policies with reversible encryption enabled,
        which significantly weakens password security.
    
    .EXAMPLE
        Get-AccountsReversibleEncryption
        Returns findings about reversible encryption in password policies.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting reversible encryption audit"
    
    try {
        # Note: Reversible encryption is controlled by domain/FGPP policy; enumerate FGPP for msDS-PasswordReversibleEncryptionEnabled.
        Write-ADSHVerbose "Querying fine-grained password policies"
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction Stop
        Write-ADSHVerbose "Found $($fgpp.Count) fine-grained password policies"
        
        $enabledFgpp = $fgpp | Where-Object { $_.ReversibleEncryptionEnabled -eq $true -or $_.'msDS-PasswordReversibleEncryptionEnabled' -eq $true }
        Write-ADSHVerbose "Found $($enabledFgpp.Count) policies with reversible encryption enabled"
        
        $evidence = $enabledFgpp | Select-Object Name, Precedence, ReversibleEncryptionEnabled, 'msDS-PasswordReversibleEncryptionEnabled'
        $sev = if ($enabledFgpp.Count -gt 0) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Policy' -Id 'REV-ENC' -Severity $sev `
            -Title "Reversible password encryption enabled in FGPP" `
            -Description "Storing passwords with reversible encryption significantly weakens security." `
            -Evidence $evidence `
            -Remediation "Disable reversible encryption in all password policies. Validate via Group Policy 'Accounts: Store passwords using reversible encryption'."
    } catch {
        Write-Warning "Failed to query fine-grained password policies: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying FGPP: $_"
        
        New-ADSHFinding -Category 'Policy' -Id 'REV-ENC' -Severity 'Info' `
            -Title "Reversible encryption check failed" `
            -Description "Unable to query fine-grained password policies. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 6. Kerberos Delegation Issues

function Get-KerberosDelegationIssues {
    <#
    .SYNOPSIS
        Audits Kerberos delegation configurations for security risks.
    
    .DESCRIPTION
        Identifies computers with unconstrained delegation and accounts/computers
        with constrained delegation. Unconstrained delegation is high risk.
    
    .EXAMPLE
        Get-KerberosDelegationIssues
        Returns findings about Kerberos delegation configurations.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Kerberos delegation audit"
    
    try {
        # Unconstrained delegation on computers (TRUSTED_FOR_DELEGATION flag: 0x80000 = 524288)
        Write-ADSHVerbose "Querying computers with unconstrained delegation"
        $unconstrained = Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties userAccountControl, servicePrincipalName -ErrorAction Stop
        Write-ADSHVerbose "Found $($unconstrained.Count) computers with unconstrained delegation"
        
        # Accounts allowed to delegate to specific services (constrained)
        Write-ADSHVerbose "Querying users with constrained delegation"
        $constrainedUsers = Get-ADUser -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo -ErrorAction Stop
        Write-ADSHVerbose "Found $($constrainedUsers.Count) users with constrained delegation"
        
        Write-ADSHVerbose "Querying computers with constrained delegation"
        $constrainedComputers = Get-ADComputer -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo -ErrorAction Stop
        Write-ADSHVerbose "Found $($constrainedComputers.Count) computers with constrained delegation"

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
            -Remediation "Remove unconstrained delegation. Restrict constrained delegation only to required services; prefer protocol transition off."
    } catch {
        Write-Warning "Failed to query Kerberos delegation: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying delegation: $_"
        
        New-ADSHFinding -Category 'Security' -Id 'KERB-DELEG' -Severity 'Info' `
            -Title "Kerberos delegation check failed" `
            -Description "Unable to query delegation settings. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 7. AdminSDHolder Protected Accounts

function Get-AdminSDHolderProtectedAccounts {
    <#
    .SYNOPSIS
        Identifies accounts protected by AdminSDHolder.
    
    .DESCRIPTION
        Finds user accounts with adminCount=1, indicating they are or were members
        of privileged groups and are protected by AdminSDHolder.
    
    .EXAMPLE
        Get-AdminSDHolderProtectedAccounts
        Returns findings about AdminSDHolder protected accounts.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting AdminSDHolder protected accounts audit"
    
    try {
        Write-ADSHVerbose "Querying accounts with adminCount=1"
        $protected = Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount, whenChanged, memberOf -ErrorAction Stop
        Write-ADSHVerbose "Found $($protected.Count) protected accounts"
        
        $evidence = $protected | Select-Object Name, SamAccountName, whenChanged, memberOf, DistinguishedName
        $sev = if ($protected.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'ADMINSD' -Severity $sev `
            -Title "AdminSDHolder protected accounts (adminCount=1)" `
            -Description "Protected accounts do not inherit permissions; verify necessity to reduce persistence risks." `
            -Evidence $evidence `
            -Remediation "Remove privileged group membership if not needed; run SDProp reset and re-enable inheritance where appropriate."
    } catch {
        Write-Warning "Failed to query AdminSDHolder protected accounts: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying protected accounts: $_"
        
        New-ADSHFinding -Category 'Security' -Id 'ADMINSD' -Severity 'Info' `
            -Title "AdminSDHolder check failed" `
            -Description "Unable to query protected accounts. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 8. Excessive Permissions/Delegations (ACL scan for sensitive groups)

function Get-ExcessivePermissionsDelegations {
    <#
    .SYNOPSIS
        Audits ACL permissions on sensitive objects for excessive rights.
    
    .DESCRIPTION
        Examines ACLs on sensitive groups and objects for risky permissions like
        GenericAll, WriteOwner, or WriteDacl that could enable privilege escalation.
    
    .PARAMETER Targets
        Array of group names to check. Defaults to sensitive groups from configuration.
    
    .EXAMPLE
        Get-ExcessivePermissionsDelegations
        Checks ACLs on default sensitive groups.
    
    .EXAMPLE
        Get-ExcessivePermissionsDelegations -Targets 'Domain Admins'
        Checks ACLs on a specific group.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]] $Targets
    )
    
    Write-ADSHVerbose "Starting excessive permissions/delegations audit"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Targets) {
            $Targets = $cfg.SensitiveGroups
            Write-ADSHVerbose "Using default sensitive groups from configuration: $($Targets.Count) groups"
        }
    } catch {
        Write-Warning "Failed to load configuration: $($_.Exception.Message)"
        $Targets = @('Domain Admins', 'Enterprise Admins')
    }
    
    $findings = @()
    
    foreach ($t in $Targets) {
        Write-ADSHVerbose "Processing target: $t"
        try {
            $grp = Get-ADGroup -Identity $t -Properties DistinguishedName -ErrorAction Stop
            Write-ADSHVerbose "Found group: $($grp.DistinguishedName)"
            
            $path = "AD:$($grp.DistinguishedName)"
            $acl = Get-Acl -Path $path -ErrorAction Stop
            Write-ADSHVerbose "Retrieved ACL for $t"
            
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
            
            Write-ADSHVerbose "Found $($risky.Count) risky ACEs on $t"
            
            $sev = if ($risky.Count -gt 0) { 'High' } else { 'Info' }
            $findings += New-ADSHFinding -Category 'Security' -Id "ACL-$($grp.SamAccountName)" -Severity $sev `
                -Title "Risky ACEs on sensitive object: $($grp.SamAccountName)" `
                -Description "High-privilege ACEs (GenericAll/WriteOwner/WriteDacl) may enable escalation." `
                -Evidence $risky `
                -Remediation "Restrict ACEs to admins; remove broad rights; implement tiering and just-in-time access."
        } catch {
            Write-Warning "Failed to process target '$t': $($_.Exception.Message)"
            Write-ADSHVerbose "Error processing target '$t': $_"
            
            $findings += New-ADSHFinding -Category 'Security' -Id "ACL-$t" -Severity 'Info' `
                -Title "ACL scan skipped (object not found): $t" `
                -Description "Sensitive object may not exist in this domain. Error: $($_.Exception.Message)" `
                -Evidence $null `
                -Remediation "Validate object name and domain."
        }
    }
    
    Write-ADSHVerbose "Completed ACL audit with $($findings.Count) findings"
    $findings
}

#endregion

#region 9. DC Replication Status

function Get-DCReplicationStatus {
    <#
    .SYNOPSIS
        Checks domain controller replication status.
    
    .DESCRIPTION
        Queries replication partner metadata for all domain controllers to identify
        replication failures and latency issues.
    
    .EXAMPLE
        Get-DCReplicationStatus
        Returns findings about DC replication health.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting DC replication status check"
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = @()
        foreach ($dc in $dcs) {
            Write-ADSHVerbose "Checking replication for DC: $($dc.HostName)"
            try {
                $meta = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Server -ErrorAction Stop
                foreach ($m in $meta) {
                    $evidence += [pscustomobject]@{
                        SourceDC         = $m.Partner
                        TargetDC         = $dc.HostName
                        LastSuccess      = $m.LastReplicationSuccess
                        LastFailure      = $m.LastReplicationFailure
                        ConsecutiveFails = $m.ConsecutiveReplicationFailures
                    }
                }
                Write-ADSHVerbose "Successfully retrieved replication metadata for $($dc.HostName)"
            } catch {
                Write-Warning "Failed to get replication metadata for $($dc.HostName): $($_.Exception.Message)"
                Write-ADSHVerbose "Error querying replication for $($dc.HostName): $_"
                
                $evidence += [pscustomobject]@{
                    SourceDC         = $null
                    TargetDC         = $dc.HostName
                    LastSuccess      = $null
                    LastFailure      = $_.Exception.Message
                    ConsecutiveFails = $null
                }
            }
        }
        
        $failures = $evidence | Where-Object { $_.ConsecutiveFails -gt 0 }
        Write-ADSHVerbose "Found $($failures.Count) DCs with replication failures"
        
        $sev = if ($failures) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'REPL' -Severity $sev `
            -Title "Domain controller replication status" `
            -Description "Replication failures and high latency impact consistency and security enforcement." `
            -Evidence $evidence `
            -Remediation "Investigate failing links with repadmin and event logs; fix DNS, connectivity, and AD sites."
    } catch {
        Write-Warning "Failed to query domain controllers: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying DCs: $_"
        
        New-ADSHFinding -Category 'Health' -Id 'REPL' -Severity 'Info' `
            -Title "DC replication check failed" `
            -Description "Unable to query domain controllers. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 10. DNS Health

function Get-DNSHealth {
    <#
    .SYNOPSIS
        Checks DNS health on domain controllers using dcdiag.
    
    .DESCRIPTION
        Runs dcdiag DNS tests on all domain controllers to identify DNS issues
        that could affect Active Directory functionality.
    
    .PARAMETER TimeoutSeconds
        Timeout in seconds for each dcdiag test. Defaults to configuration value.
    
    .EXAMPLE
        Get-DNSHealth
        Checks DNS health with default timeout.
    
    .EXAMPLE
        Get-DNSHealth -TimeoutSeconds 120
        Checks DNS health with 120 second timeout.
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
            Write-ADSHVerbose "Using timeout from configuration: $TimeoutSeconds seconds"
        }
    } catch {
        Write-Warning "Failed to load configuration, using default timeout of 180 seconds"
        $TimeoutSeconds = 180
    }
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = @()
        foreach ($dc in $dcs) {
            Write-ADSHVerbose "Running DNS check for DC: $dc (timeout: $TimeoutSeconds seconds)"
            $cmd = "dcdiag /s:$dc /test:DNS /v"
            try {
                $job = Start-Job -ScriptBlock { param($c) cmd.exe /c $c | Out-String } -ArgumentList $cmd
                if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
                    $out = Receive-Job -Job $job
                    $passed = ($out -notmatch 'FAIL|error')
                    $evidence += [pscustomobject]@{
                        DC     = $dc
                        Output = $out
                        Passed = $passed
                    }
                    Write-ADSHVerbose "DNS check for $dc completed: Passed=$passed"
                } else {
                    Stop-Job $job | Out-Null
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                    $evidence += [pscustomobject]@{
                        DC     = $dc
                        Output = 'Timeout'
                        Passed = $false
                    }
                    Write-ADSHVerbose "DNS check for $dc timed out"
                }
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Failed DNS check for $dc`: $($_.Exception.Message)"
                Write-ADSHVerbose "Error running DNS check for $dc`: $_"
                
                $evidence += [pscustomobject]@{
                    DC     = $dc
                    Output = $_.Exception.Message
                    Passed = $false
                }
            }
        }
        
        $failures = $evidence | Where-Object { -not $_.Passed }
        Write-ADSHVerbose "Found $($failures.Count) DCs with DNS issues"
        
        $sev = if ($failures) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'DNS' -Severity $sev `
            -Title "DNS health via dcdiag" `
            -Description "AD-integrated DNS issues cause authentication and replication failures." `
            -Evidence $evidence `
            -Remediation "Resolve zone errors, stale records, and delegation issues; ensure DCs register SRV records."
    } catch {
        Write-Warning "Failed to check DNS health: $($_.Exception.Message)"
        Write-ADSHVerbose "Error checking DNS: $_"
        
        New-ADSHFinding -Category 'Health' -Id 'DNS' -Severity 'Info' `
            -Title "DNS health check failed" `
            -Description "Unable to run DNS checks. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 11. SYSVOL Replication

function Get-SYSVOLReplicationStatus {
    <#
    .SYNOPSIS
        Checks SYSVOL replication service status across domain controllers.
    
    .DESCRIPTION
        Verifies whether domain controllers are using DFSR or deprecated FRS for
        SYSVOL replication. FRS is deprecated and should be migrated to DFSR.
    
    .PARAMETER RequireDFSR
        When true, flags FRS usage as high severity. Defaults to configuration value.
    
    .EXAMPLE
        Get-SYSVOLReplicationStatus
        Checks SYSVOL replication using default configuration.
    
    .EXAMPLE
        Get-SYSVOLReplicationStatus -RequireDFSR $true
        Requires DFSR and flags FRS as high severity.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool] $RequireDFSR
    )
    
    Write-ADSHVerbose "Starting SYSVOL replication status check"
    
    try {
        $cfg = Get-ADSHConfig
        if ($PSBoundParameters.ContainsKey('RequireDFSR') -eq $false) {
            $RequireDFSR = [bool]$cfg.SysvolRequireDFSR
            Write-ADSHVerbose "Using RequireDFSR from configuration: $RequireDFSR"
        }
    } catch {
        Write-Warning "Failed to load configuration, defaulting to RequireDFSR=$true"
        $RequireDFSR = $true
    }
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = foreach ($dc in $dcs) {
            Write-ADSHVerbose "Checking SYSVOL replication services on: $($dc.HostName)"
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
                Write-Warning "Failed to query services on $($dc.HostName): $($_.Exception.Message)"
                Write-ADSHVerbose "Error querying services on $($dc.HostName): $_"
                
                [pscustomobject]@{
                    DC          = $dc.HostName
                    DFSRStatus  = "Error: $($_.Exception.Message)"
                    FRSStatus   = $null
                }
            }
        }
        
        $frsActive = $evidence | Where-Object { $_.FRSStatus -eq 'Running' }
        Write-ADSHVerbose "Found $($frsActive.Count) DCs running FRS"
        
        $sev = if ($RequireDFSR -and $frsActive) { 'High' } else { 'Medium' }
        
        New-ADSHFinding -Category 'Health' -Id 'SYSVOL' -Severity $sev `
            -Title "SYSVOL replication service status (DFSR vs FRS)" `
            -Description "FRS is deprecated; DFSR is required. Confirm replication health and migration status." `
            -Evidence $evidence `
            -Remediation "Migrate SYSVOL from FRS to DFSR; validate DFSR connections and backlog with dfsrdiag."
    } catch {
        Write-Warning "Failed to check SYSVOL replication: $($_.Exception.Message)"
        Write-ADSHVerbose "Error checking SYSVOL: $_"
        
        New-ADSHFinding -Category 'Health' -Id 'SYSVOL' -Severity 'Info' `
            -Title "SYSVOL replication check failed" `
            -Description "Unable to query SYSVOL replication status. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 12. FSMO Role Holders

function Get-FSMORoleHolders {
    <#
    .SYNOPSIS
        Retrieves current FSMO role holders.
    
    .DESCRIPTION
        Identifies which domain controllers hold the five FSMO roles:
        Schema Master, Domain Naming Master, RID Master, PDC Emulator, and Infrastructure Master.
    
    .EXAMPLE
        Get-FSMORoleHolders
        Returns findings listing current FSMO role holders.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting FSMO role holders check"
    
    try {
        Write-ADSHVerbose "Querying domain and forest information"
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        
        $evidence = [pscustomobject]@{
            DomainNamingMaster     = $forest.DomainNamingMaster
            SchemaMaster           = $forest.SchemaMaster
            RIDMaster              = $domain.RIDMaster
            PDCEmulator            = $domain.PDCEmulator
            InfrastructureMaster   = $domain.InfrastructureMaster
        }
        
        Write-ADSHVerbose "FSMO roles identified - Schema: $($forest.SchemaMaster), PDC: $($domain.PDCEmulator)"
        
        New-ADSHFinding -Category 'Health' -Id 'FSMO' -Severity 'Info' `
            -Title "FSMO role holders" `
            -Description "Record current role holders to confirm availability and placement." `
            -Evidence $evidence `
            -Remediation "Ensure role holders are online, backed up, and placed appropriately per sites and capacity."
    } catch {
        Write-Warning "Failed to query FSMO roles: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying FSMO roles: $_"
        
        New-ADSHFinding -Category 'Health' -Id 'FSMO' -Severity 'Info' `
            -Title "FSMO role holders check failed" `
            -Description "Unable to query FSMO roles. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 13. DC Service Status

function Get-DCServiceStatus {
    <#
    .SYNOPSIS
        Checks critical service status on domain controllers.
    
    .DESCRIPTION
        Queries the status of critical AD services (NTDS, KDC, DNS, etc.) on all
        domain controllers to identify service failures.
    
    .PARAMETER Services
        Array of service names to check. Defaults to critical services from configuration.
    
    .EXAMPLE
        Get-DCServiceStatus
        Checks default critical services.
    
    .EXAMPLE
        Get-DCServiceStatus -Services 'NTDS','KDC'
        Checks specific services.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]] $Services
    )
    
    Write-ADSHVerbose "Starting DC service status check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $Services) {
            $Services = $cfg.CriticalServices
            Write-ADSHVerbose "Using critical services from configuration: $($Services -join ', ')"
        }
    } catch {
        Write-Warning "Failed to load configuration: $($_.Exception.Message)"
        $Services = @('NTDS','KDC','DNS','Netlogon')
    }
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = foreach ($dc in $dcs) {
            Write-ADSHVerbose "Checking services on: $dc"
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
                Write-Warning "Failed to query services on $dc`: $($_.Exception.Message)"
                Write-ADSHVerbose "Error querying services on $dc`: $_"
                
                [pscustomobject]@{
                    DC       = $dc
                    Services = @([pscustomobject]@{ Name = 'Error'; Status = $_.Exception.Message })
                }
            }
        }
        
        $down = $evidence | Where-Object { $_.Services | Where-Object { $_.Status -ne 'Running' } }
        Write-ADSHVerbose "Found $($down.Count) DCs with service issues"
        
        $sev = if ($down) { 'High' } else { 'Info' }
        
        New-ADSHFinding -Category 'Health' -Id 'DC-SVC' -Severity $sev `
            -Title "Domain controller critical service status" `
            -Description "Critical DC services must be running for authentication and replication." `
            -Evidence $evidence `
            -Remediation "Start services or troubleshoot failures; check event logs and configuration."
    } catch {
        Write-Warning "Failed to check DC service status: $($_.Exception.Message)"
        Write-ADSHVerbose "Error checking services: $_"
        
        New-ADSHFinding -Category 'Health' -Id 'DC-SVC' -Severity 'Info' `
            -Title "DC service status check failed" `
            -Description "Unable to query DC services. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 14. AD Database Size and Growth

function Get-ADDatabaseStats {
    <#
    .SYNOPSIS
        Retrieves Active Directory database size statistics.
    
    .DESCRIPTION
        Queries the size of ntds.dit file on all domain controllers for
        capacity planning and monitoring.
    
    .EXAMPLE
        Get-ADDatabaseStats
        Returns AD database size for all DCs.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting AD database stats check"
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = foreach ($dc in $dcs) {
            Write-ADSHVerbose "Checking NTDS.dit size on: $dc"
            try {
                $path = Invoke-Command -ComputerName $dc -ScriptBlock {
                    (Get-Item 'C:\Windows\NTDS\ntds.dit' -ErrorAction Stop).FullName
                } -ErrorAction Stop
                
                $size = Invoke-Command -ComputerName $dc -ScriptBlock {
                    (Get-Item 'C:\Windows\NTDS\ntds.dit' -ErrorAction Stop).Length
                } -ErrorAction Stop
                
                Write-ADSHVerbose "DC $dc NTDS.dit size: $([math]::Round($size/1MB,2)) MB"
                
                [pscustomobject]@{
                    DC        = $dc
                    NtdsDit   = $path
                    SizeBytes = $size
                    SizeMB    = [math]::Round($size/1MB,2)
                }
            } catch {
                Write-Warning "Failed to get database size from $dc`: $($_.Exception.Message)"
                Write-ADSHVerbose "Error querying database on $dc`: $_"
                
                [pscustomobject]@{
                    DC        = $dc
                    NtdsDit   = 'Unknown'
                    SizeBytes = $null
                    SizeMB    = $null
                }
            }
        }
        
        New-ADSHFinding -Category 'Capacity' -Id 'NTDS' -Severity 'Info' `
            -Title "AD database (ntds.dit) size per DC" `
            -Description "Track AD DB size for capacity planning; monitor sudden growth." `
            -Evidence $evidence `
            -Remediation "Ensure sufficient disk space and regular backups; defragment offline if required by Microsoft guidance."
    } catch {
        Write-Warning "Failed to check AD database stats: $($_.Exception.Message)"
        Write-ADSHVerbose "Error checking database: $_"
        
        New-ADSHFinding -Category 'Capacity' -Id 'NTDS' -Severity 'Info' `
            -Title "AD database stats check failed" `
            -Description "Unable to query database statistics. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 15. Trust Relationships

function Get-TrustRelationships {
    <#
    .SYNOPSIS
        Audits domain and forest trust relationships.
    
    .DESCRIPTION
        Lists all trust relationships to identify potential security exposure points.
        External and forest trusts require careful review.
    
    .EXAMPLE
        Get-TrustRelationships
        Returns findings about trust relationships.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting trust relationships audit"
    
    try {
        Write-ADSHVerbose "Querying AD trust relationships"
        $trusts = Get-ADTrust -Filter * -Properties * -ErrorAction Stop
        Write-ADSHVerbose "Found $($trusts.Count) trust relationships"
        
        $evidence = $trusts | Select-Object Name, Source, Target, TrustType, TrustAttributes, Direction, IsForest, IsExternal
        $sev = if ($trusts.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Exposure' -Id 'TRUSTS' -Severity $sev `
            -Title "Domain and forest trust relationships" `
            -Description "Review external and forest trusts; validate SID filtering and selective authentication." `
            -Evidence $evidence `
            -Remediation "Remove obsolete trusts; enable SID filtering; use selective authentication for external trusts."
    } catch {
        Write-Warning "Failed to query trust relationships: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying trusts: $_"
        
        New-ADSHFinding -Category 'Exposure' -Id 'TRUSTS' -Severity 'Info' `
            -Title "Trust relationships check failed" `
            -Description "Unable to query trust relationships. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 16. GPO Review (links, permissions)

function Get-GPOReview {
    <#
    .SYNOPSIS
        Reviews Group Policy Objects for orphaned GPOs and security issues.
    
    .DESCRIPTION
        Analyzes all GPOs to identify those that are not linked (orphaned) and
        reviews security filtering configurations.
    
    .EXAMPLE
        Get-GPOReview
        Returns findings about GPO configuration.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting GPO review"
    
    try {
        # Requires GroupPolicy module
        Write-ADSHVerbose "Querying all GPOs"
        $all = Get-GPO -All -ErrorAction Stop
        Write-ADSHVerbose "Found $($all.Count) GPOs"
        
        $xmls = @()
        foreach ($g in $all) {
            Write-ADSHVerbose "Processing GPO: $($g.DisplayName)"
            try {
                $temp = New-TemporaryFile
                Get-GPOReport -Guid $g.Id -ReportType Xml -Path $temp.FullName -ErrorAction Stop
                $xml = [xml](Get-Content -Raw $temp.FullName)
                Remove-Item $temp.FullName -Force -ErrorAction SilentlyContinue
                
                $xmls += [pscustomobject]@{
                    DisplayName = $g.DisplayName
                    Id          = $g.Id
                    CreationTime= $g.CreationTime
                    ModificationTime = $g.ModificationTime
                    LinksToCount= ($xml.GPO.LinksTo | Measure-Object).Count
                    SecurityFiltering = ($xml.GPO.SecurityDescriptor | Out-String)
                }
            } catch {
                Write-Warning "Failed to get GPO report for $($g.DisplayName): $($_.Exception.Message)"
                Write-ADSHVerbose "Error processing GPO $($g.DisplayName): $_"
                
                $xmls += [pscustomobject]@{
                    DisplayName = $g.DisplayName
                    Id          = $g.Id
                    CreationTime= $g.CreationTime
                    ModificationTime = $g.ModificationTime
                    LinksToCount= 0
                    SecurityFiltering = 'Report failed'
                }
            }
        }
        
        $orphans = $xmls | Where-Object { $_.LinksToCount -eq 0 }
        Write-ADSHVerbose "Found $($orphans.Count) orphaned GPOs"
        
        $sev = if ($orphans.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Configuration' -Id 'GPO' -Severity $sev `
            -Title "GPO review (orphaned and security filtering)" `
            -Description "Identify orphaned GPOs and review security filtering for over-permission." `
            -Evidence $xmls `
            -Remediation "Delete or archive unused GPOs; tighten GPO permissions and links; document GPO ownership."
    } catch {
        Write-Warning "Failed to review GPOs: $($_.Exception.Message)"
        Write-ADSHVerbose "Error reviewing GPOs: $_"
        
        New-ADSHFinding -Category 'Configuration' -Id 'GPO' -Severity 'Info' `
            -Title "GPO review failed" `
            -Description "Unable to query GPOs. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify GroupPolicy module is installed and permissions are adequate."
    }
}

#endregion

#region 17. Pre-Windows 2000 Compatible Access Group

function Get-PreWin2000AccessRisks {
    <#
    .SYNOPSIS
        Audits Pre-Windows 2000 Compatible Access group membership.
    
    .DESCRIPTION
        Checks membership of the Pre-Windows 2000 Compatible Access group,
        which grants broad read access and should be empty in modern environments.
    
    .EXAMPLE
        Get-PreWin2000AccessRisks
        Returns findings about Pre-Windows 2000 Compatible Access group.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting Pre-Windows 2000 Compatible Access audit"
    
    try {
        Write-ADSHVerbose "Querying Pre-Windows 2000 Compatible Access group"
        $grp = Get-ADGroup -Identity 'Pre-Windows 2000 Compatible Access' -ErrorAction Stop
        Write-ADSHVerbose "Found group: $($grp.DistinguishedName)"
        
        $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive -ErrorAction Stop
        Write-ADSHVerbose "Group has $($members.Count) members"
        
        $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
        $sev = if ($members.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'PREWIN2000' -Severity $sev `
            -Title "Pre-Windows 2000 Compatible Access membership" `
            -Description "Membership here broadens read access; review for legacy needs only." `
            -Evidence $evidence `
            -Remediation "Remove unnecessary principals; ensure legacy apps are updated."
    } catch {
        Write-Warning "Failed to query Pre-Windows 2000 Compatible Access group: $($_.Exception.Message)"
        Write-ADSHVerbose "Error querying group: $_"
        
        New-ADSHFinding -Category 'Security' -Id 'PREWIN2000' -Severity 'Info' `
            -Title "Pre-Windows 2000 Compatible Access group not found" `
            -Description "Group may be renamed or domain-specific. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Validate group existence."
    }
}

#endregion

#region 18. SPN Audit (duplicates & roasting risks)

function Get-SPNAudit {
    <#
    .SYNOPSIS
        Audits Service Principal Names (SPNs) for duplicates and roasting risks.
    
    .DESCRIPTION
        Identifies duplicate SPNs which cause authentication conflicts, and SPNs
        on user accounts which increase Kerberoasting risk.
    
    .EXAMPLE
        Get-SPNAudit
        Returns findings about SPN configuration.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting SPN audit"
    
    try {
        Write-ADSHVerbose "Querying objects with SPNs"
        $objs = Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, SamAccountName, objectClass, userAccountControl -ErrorAction Stop
        Write-ADSHVerbose "Found $($objs.Count) objects with SPNs"
        
        $allSpns = @()
        foreach ($o in $objs) {
            foreach ($spn in $o.servicePrincipalName) {
                $allSpns += [pscustomobject]@{
                    Owner          = $o.SamAccountName
                    DN             = $o.DistinguishedName
                    ObjectClass    = $o.objectClass
                    SPN            = $spn
                }
            }
        }
        
        Write-ADSHVerbose "Total SPNs found: $($allSpns.Count)"
        
        $dupes = $allSpns | Group-Object SPN | Where-Object { $_.Count -gt 1 } | ForEach-Object {
            [pscustomobject]@{
                SPN    = $_.Name
                Owners = ($_.Group | Select-Object -ExpandProperty Owner) -join ', '
            }
        }
        
        Write-ADSHVerbose "Found $($dupes.Count) duplicate SPNs"
        
        $sev = if ($dupes.Count -gt 0) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Security' -Id 'SPN' -Severity $sev `
            -Title "SPN audit (duplicate SPNs & ownership)" `
            -Description "Duplicate SPNs cause auth conflicts; SPNs on user accounts increase Kerberoasting risk." `
            -Evidence ([pscustomobject]@{ Duplicates = $dupes; AllSPNs = $allSpns }) `
            -Remediation "Remove duplicates; prefer computer accounts for service SPNs; monitor for high-value service tickets."
    } catch {
        Write-Warning "Failed to audit SPNs: $($_.Exception.Message)"
        Write-ADSHVerbose "Error auditing SPNs: $_"
        
        New-ADSHFinding -Category 'Security' -Id 'SPN' -Severity 'Info' `
            -Title "SPN audit failed" `
            -Description "Unable to query SPNs. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 19. Audit Policy Verification

function Get-AuditPolicyVerification {
    <#
    .SYNOPSIS
        Verifies audit policy configuration on domain controllers.
    
    .DESCRIPTION
        Checks that critical audit categories are enabled on all domain controllers
        to ensure security events are properly logged.
    
    .EXAMPLE
        Get-AuditPolicyVerification
        Returns findings about audit policy configuration.
    #>
    [CmdletBinding()]
    param()
    
    Write-ADSHVerbose "Starting audit policy verification"
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = foreach ($dc in $dcs) {
            Write-ADSHVerbose "Checking audit policy on: $dc"
            try {
                $out = Invoke-Command -ComputerName $dc -ScriptBlock {
                    auditpol.exe /get /category:* | Out-String
                } -ErrorAction Stop
                
                [pscustomobject]@{
                    DC     = $dc
                    Output = $out
                    KeyAreasCovered = ($out -match 'Account Logon|Account Management|Policy Change|Privilege Use|System')
                }
            } catch {
                Write-Warning "Failed to get audit policy from $dc`: $($_.Exception.Message)"
                Write-ADSHVerbose "Error querying audit policy on $dc`: $_"
                
                [pscustomobject]@{
                    DC     = $dc
                    Output = "Failed: $($_.Exception.Message)"
                    KeyAreasCovered = $false
                }
            }
        }
        
        $missing = $evidence | Where-Object { -not $_.KeyAreasCovered }
        Write-ADSHVerbose "Found $($missing.Count) DCs with missing key audit areas"
        
        $sev = if ($missing) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Monitoring' -Id 'AUDITPOL' -Severity $sev `
            -Title "Audit policy coverage on domain controllers" `
            -Description "Ensure auditing for account logon, management, policy change, privilege use, and system events." `
            -Evidence $evidence `
            -Remediation "Configure advanced audit policies via GPO; forward events to SIEM."
    } catch {
        Write-Warning "Failed to verify audit policies: $($_.Exception.Message)"
        Write-ADSHVerbose "Error verifying audit policies: $_"
        
        New-ADSHFinding -Category 'Monitoring' -Id 'AUDITPOL' -Severity 'Info' `
            -Title "Audit policy verification failed" `
            -Description "Unable to verify audit policies. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region 20. Security Event Log Configuration

function Get-SecurityEventLogConfig {
    <#
    .SYNOPSIS
        Checks Security event log configuration on domain controllers.
    
    .DESCRIPTION
        Verifies that Security event log size and retention settings are adequate
        to prevent loss of security telemetry.
    
    .PARAMETER MinSizeMB
        Minimum required Security log size in MB. Defaults to configuration value.
    
    .EXAMPLE
        Get-SecurityEventLogConfig
        Checks log configuration with default minimum size.
    
    .EXAMPLE
        Get-SecurityEventLogConfig -MinSizeMB 4096
        Checks with 4GB minimum requirement.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(512, 20480)]
        [int] $MinSizeMB
    )
    
    Write-ADSHVerbose "Starting Security event log configuration check"
    
    try {
        $cfg = Get-ADSHConfig
        if (-not $MinSizeMB) {
            $MinSizeMB = [int]$cfg.EventLogMinSizeMB
            Write-ADSHVerbose "Using minimum log size from configuration: $MinSizeMB MB"
        }
    } catch {
        Write-Warning "Failed to load configuration, using default minimum of 2048 MB"
        $MinSizeMB = 2048
    }
    
    try {
        Write-ADSHVerbose "Querying domain controllers"
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        Write-ADSHVerbose "Found $($dcs.Count) domain controllers"
        
        $evidence = foreach ($dc in $dcs) {
            Write-ADSHVerbose "Checking Security log configuration on: $dc"
            try {
                $data = Invoke-Command -ComputerName $dc -ScriptBlock {
                    Get-CimInstance -ClassName Win32_NTEventLogFile -Filter "LogfileName='Security'" |
                        Select-Object LogfileName, MaxFileSize, NumberOfRecords, OverwriteOutdated, OverwriteFile, Name
                } -ErrorAction Stop
                
                $sizeMB = [math]::Round(($data.MaxFileSize/1MB),2)
                
                [pscustomobject]@{
                    DC              = $dc
                    MaxFileSizeMB   = $sizeMB
                    NumberOfRecords = $data.NumberOfRecords
                    OverwritePolicy = if ($data.OverwriteOutdated) { 'Overwrite oldest' } elseif ($data.OverwriteFile) { 'Overwrite as needed' } else { 'Do not overwrite' }
                }
            } catch {
                Write-Warning "Failed to get log configuration from $dc`: $($_.Exception.Message)"
                Write-ADSHVerbose "Error querying log config on $dc`: $_"
                
                [pscustomobject]@{
                    DC              = $dc
                    MaxFileSizeMB   = $null
                    NumberOfRecords = $null
                    OverwritePolicy = "Failed: $($_.Exception.Message)"
                }
            }
        }
        
        $undersized = $evidence | Where-Object { $_.MaxFileSizeMB -and $_.MaxFileSizeMB -lt $MinSizeMB }
        Write-ADSHVerbose "Found $($undersized.Count) DCs with undersized Security logs"
        
        $sev = if ($undersized) { 'Medium' } else { 'Info' }
        
        New-ADSHFinding -Category 'Monitoring' -Id 'SECLOG' -Severity $sev `
            -Title "Security log size and retention on domain controllers" `
            -Description "Adequate log size and retention prevent loss of critical security telemetry." `
            -Evidence $evidence `
            -Remediation "Increase Security log size (≥$MinSizeMB MB) and configure retention; forward to SIEM."
    } catch {
        Write-Warning "Failed to check Security log configuration: $($_.Exception.Message)"
        Write-ADSHVerbose "Error checking log config: $_"
        
        New-ADSHFinding -Category 'Monitoring' -Id 'SECLOG' -Severity 'Info' `
            -Title "Security log configuration check failed" `
            -Description "Unable to check log configuration. Error: $($_.Exception.Message)" `
            -Evidence $null `
            -Remediation "Verify AD connectivity and permissions."
    }
}

#endregion

#region Orchestrator

function Invoke-ADSecurityHealthCheck {
    <#
    .SYNOPSIS
        Executes all Active Directory security and health checks.
    
    .DESCRIPTION
        Orchestrator function that runs all security and health audit functions
        and returns consolidated findings.
    
    .PARAMETER IncludeRawEvidence
        When specified, includes full evidence data in results. Otherwise returns
        summary view with evidence trimmed.
    
    .EXAMPLE
        Invoke-ADSecurityHealthCheck
        Runs all checks with summary output.
    
    .EXAMPLE
        Invoke-ADSecurityHealthCheck -IncludeRawEvidence
        Runs all checks with full evidence data.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch] $IncludeRawEvidence
    )
    
    Write-ADSHVerbose "========================================="
    Write-ADSHVerbose "Starting AD Security Health Check"
    Write-ADSHVerbose "========================================="
    Write-ADSHVerbose "Include Raw Evidence: $IncludeRawEvidence"
    
    try {
        Write-ADSHVerbose "Initializing environment"
        Initialize-ADSHEnvironment
    } catch {
        Write-Warning "Failed to initialize environment: $($_.Exception.Message)"
        Write-ADSHVerbose "Initialization error: $_"
    }
    
    $results = @()
    
    # Execute all checks with error handling
    $checks = @(
        @{ Name = "Privileged Group Membership"; Function = { Get-PrivilegedGroupMembership } }
        @{ Name = "Stale Accounts"; Function = { Get-StaleAccounts } }
        @{ Name = "Password Policy Audit"; Function = { Get-PasswordPolicyAudit } }
        @{ Name = "Accounts Password Never Expires"; Function = { Get-AccountsPasswordNeverExpires } }
        @{ Name = "Accounts Reversible Encryption"; Function = { Get-AccountsReversibleEncryption } }
        @{ Name = "Kerberos Delegation Issues"; Function = { Get-KerberosDelegationIssues } }
        @{ Name = "AdminSDHolder Protected Accounts"; Function = { Get-AdminSDHolderProtectedAccounts } }
        @{ Name = "Excessive Permissions Delegations"; Function = { Get-ExcessivePermissionsDelegations } }
        @{ Name = "DC Replication Status"; Function = { Get-DCReplicationStatus } }
        @{ Name = "DNS Health"; Function = { Get-DNSHealth } }
        @{ Name = "SYSVOL Replication Status"; Function = { Get-SYSVOLReplicationStatus } }
        @{ Name = "FSMO Role Holders"; Function = { Get-FSMORoleHolders } }
        @{ Name = "DC Service Status"; Function = { Get-DCServiceStatus } }
        @{ Name = "AD Database Stats"; Function = { Get-ADDatabaseStats } }
        @{ Name = "Trust Relationships"; Function = { Get-TrustRelationships } }
        @{ Name = "GPO Review"; Function = { Get-GPOReview } }
        @{ Name = "Pre-Win2000 Access Risks"; Function = { Get-PreWin2000AccessRisks } }
        @{ Name = "SPN Audit"; Function = { Get-SPNAudit } }
        @{ Name = "Audit Policy Verification"; Function = { Get-AuditPolicyVerification } }
        @{ Name = "Security Event Log Config"; Function = { Get-SecurityEventLogConfig } }
    )
    
    foreach ($check in $checks) {
        Write-ADSHVerbose "---"
        Write-ADSHVerbose "Executing check: $($check.Name)"
        try {
            $checkResults = & $check.Function
            if ($checkResults) {
                $results += $checkResults
                Write-ADSHVerbose "Check completed: $($check.Name) - $($checkResults.Count) findings"
            } else {
                Write-ADSHVerbose "Check completed: $($check.Name) - no findings"
            }
        } catch {
            Write-Warning "Check '$($check.Name)' failed: $($_.Exception.Message)"
            Write-ADSHVerbose "Error in check '$($check.Name)': $_"
        }
    }

    Write-ADSHVerbose "---"
    Write-ADSHVerbose "All checks completed. Total findings: $($results.Count)"
    
    if (-not $IncludeRawEvidence) {
        # Trim very large evidence if needed in summary view
        Write-ADSHVerbose "Trimming evidence for summary view"
        $results = $results | ForEach-Object {
            $obj = $_ | Select-Object Timestamp, Category, Id, Severity, Title, Description, Remediation
            $obj
        }
    }
    
    Write-ADSHVerbose "========================================="
    Write-ADSHVerbose "AD Security Health Check Complete"
    Write-ADSHVerbose "========================================="
    
    $results
}

#endregion