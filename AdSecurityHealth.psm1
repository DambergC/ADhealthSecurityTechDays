#requires -Version 5.1
# ADSecurityHealth.psm1
# PowerShell toolkit for Active Directory security and health monitoring

#region Helpers

function Initialize-ADSHEnvironment {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $RequiredModules = @('ActiveDirectory','GroupPolicy')
    )
    foreach ($m in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Warning "Module '$m' not found. Please install RSAT or the module."
        } else {
            Import-Module -Name $m -ErrorAction SilentlyContinue
        }
    }
}

function Get-ADSHConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $Path = "$PSScriptRoot\adsh-config.json"
    )
    if (Test-Path -Path $Path) {
        try {
            return Get-Content -Raw -Path $Path | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to parse config '$Path': $_"
        }
    }
    # Defaults if config not found
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('Info','Low','Medium','High','Critical')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter()] [string] $Description,
        [Parameter()] [object] $Evidence,
        [Parameter()] [string] $Remediation
    )
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
    param([string]$Message)
    Write-Verbose "[ADSH] $Message"
}

#endregion Helpers

#region 1. Privileged Group Membership

function Get-PrivilegedGroupMembership {
    [CmdletBinding()]
    param(
        [string[]] $Groups,
        [string] $Server
    )
    $cfg = Get-ADSHConfig
    if (-not $Groups) { $Groups = $cfg.SensitiveGroups }
    $findings = @()
    foreach ($g in $Groups) {
        try {
            $grp = Get-ADGroup -Identity $g -Server $Server -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive -Server $Server -ErrorAction SilentlyContinue
            $evidence = $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
            $sev = if ($members.Count -gt 0) { 'High' } else { 'Info' }
            $findings += New-ADSHFinding -Category 'Security' -Id "PRIV-$($grp.SamAccountName)" -Severity $sev `
                -Title "Privileged group membership: $($grp.SamAccountName)" `
                -Description "List members of privileged group." `
                -Evidence $evidence `
                -Remediation "Review and remove unnecessary members. Enforce tiered admin model and JIT/PIM for elevation."
        } catch {
            $findings += New-ADSHFinding -Category 'Security' -Id "PRIV-$g" -Severity 'Info' `
                -Title "Privileged group not found: $g" `
                -Description "Group may not exist in this domain." `
                -Evidence $null `
                -Remediation "Validate domain scope and name."
        }
    }
    $findings
}

#endregion

#region 2. Stale/Inactive Accounts

function Get-StaleAccounts {
    [CmdletBinding()]
    param(
        [int] $StaleDays
    )
    $cfg = Get-ADSHConfig
    if (-not $StaleDays) { $StaleDays = [int]$cfg.StaleDays }
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $users = Get-ADUser -Filter 'enabled -eq $true' -Properties lastLogonTimestamp,whenCreated,PasswordNeverExpires
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
    $sev = if ($stale.Count -gt 50) { 'High' } elseif ($stale.Count -gt 0) { 'Medium' } else { 'Info' }
    New-ADSHFinding -Category 'Hygiene' -Id 'STALE-ACCOUNTS' -Severity $sev `
        -Title "Stale enabled user accounts (>$StaleDays days)" `
        -Description "Enabled accounts with no recent logon increase attack surface." `
        -Evidence $stale `
        -Remediation "Disable or remove stale accounts. Implement lifecycle automation and time-bound access."
}

#endregion

#region 3. Password Policy Audit

function Get-PasswordPolicyAudit {
    [CmdletBinding()]
    param()
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
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
}

#endregion

#region 4. Accounts with Password Never Expires

function Get-AccountsPasswordNeverExpires {
    [CmdletBinding()]
    param()
    $users = Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and enabled -eq $true' -Properties PasswordNeverExpires,lastLogonTimestamp
    $evidence = $users | Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires, @{n='LastLogon';e={ if ($_.lastLogonTimestamp) {[DateTime]::FromFileTime($_.lastLogonTimestamp)} else {$null}}}, DistinguishedName
    $sev = if ($users.Count -gt 0) { 'High' } else { 'Info' }
    New-ADSHFinding -Category 'Security' -Id 'PWD-NEVER-EXPIRES' -Severity $sev `
        -Title "Enabled accounts with password set to never expire" `
        -Description "Service or privileged accounts with non-expiring passwords increase risk." `
        -Evidence $evidence `
        -Remediation "Migrate to gMSA or vault-managed secrets; enforce rotation via policy or automation."
}

#endregion

#region 5. Accounts with Reversible Encryption

function Get-AccountsReversibleEncryption {
    [CmdletBinding()]
    param()
    # Note: Reversible encryption is controlled by domain/FGPP policy; enumerate FGPP for msDS-PasswordReversibleEncryptionEnabled.
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
    $enabledFgpp = $fgpp | Where-Object { $_.ReversibleEncryptionEnabled -eq $true -or $_.'msDS-PasswordReversibleEncryptionEnabled' -eq $true }
    $evidence = $enabledFgpp | Select-Object Name, Precedence, ReversibleEncryptionEnabled, 'msDS-PasswordReversibleEncryptionEnabled'
    $sev = if ($enabledFgpp.Count -gt 0) { 'High' } else { 'Info' }
    New-ADSHFinding -Category 'Policy' -Id 'REV-ENC' -Severity $sev `
        -Title "Reversible password encryption enabled in FGPP" `
        -Description "Storing passwords with reversible encryption significantly weakens security." `
        -Evidence $evidence `
        -Remediation "Disable reversible encryption in all password policies. Validate via Group Policy 'Accounts: Store passwords using reversible encryption'."
}

#endregion

#region 6. Kerberos Delegation Issues

function Get-KerberosDelegationIssues {
    [CmdletBinding()]
    param()
    # Unconstrained delegation on computers (TRUSTED_FOR_DELEGATION flag: 0x80000 = 524288)
    $unconstrained = Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties userAccountControl, servicePrincipalName
    # Accounts allowed to delegate to specific services (constrained)
    $constrainedUsers = Get-ADUser -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo
    $constrainedComputers = Get-ADComputer -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo

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
}

#endregion

#region 7. AdminSDHolder Protected Accounts

function Get-AdminSDHolderProtectedAccounts {
    [CmdletBinding()]
    param()
    $protected = Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount, whenChanged, memberOf
    $evidence = $protected | Select-Object Name, SamAccountName, whenChanged, memberOf, DistinguishedName
    $sev = if ($protected.Count -gt 0) { 'Medium' } else { 'Info' }
    New-ADSHFinding -Category 'Security' -Id 'ADMINSD' -Severity $sev `
        -Title "AdminSDHolder protected accounts (adminCount=1)" `
        -Description "Protected accounts do not inherit permissions; verify necessity to reduce persistence risks." `
        -Evidence $evidence `
        -Remediation "Remove privileged group membership if not needed; run SDProp reset and re-enable inheritance where appropriate."
}

#endregion

#region 8. Excessive Permissions/Delegations (ACL scan for sensitive groups)

function Get-ExcessivePermissionsDelegations {
    [CmdletBinding()]
    param(
        [string[]] $Targets
    )
    $cfg = Get-ADSHConfig
    if (-not $Targets) { $Targets = $cfg.SensitiveGroups }
    $findings = @()
    foreach ($t in $Targets) {
        try {
            $grp = Get-ADGroup -Identity $t -Properties DistinguishedName
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
                -Title "Risky ACEs on sensitive object: $($grp.SamAccountName)" `
                -Description "High-privilege ACEs (GenericAll/WriteOwner/WriteDacl) may enable escalation." `
                -Evidence $risky `
                -Remediation "Restrict ACEs to admins; remove broad rights; implement tiering and just-in-time access."
        } catch {
            $findings += New-ADSHFinding -Category 'Security' -Id "ACL-$t" -Severity 'Info' `
                -Title "ACL scan skipped (object not found): $t" `
                -Description "Sensitive object may not exist in this domain." `
                -Evidence $null `
                -Remediation "Validate object name and domain."
        }
    }
    $findings
}

#endregion

#region 9. DC Replication Status

function Get-DCReplicationStatus {
    [CmdletBinding()]
    param()
    $dcs = Get-ADDomainController -Filter *
    $evidence = @()
    foreach ($dc in $dcs) {
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
        } catch {
            $evidence += [pscustomobject]@{
                SourceDC         = $null
                TargetDC         = $dc.HostName
                LastSuccess      = $null
                LastFailure      = $_.Exception.Message
                ConsecutiveFails = $null
            }
        }
    }
    $sev = if ($evidence | Where-Object { $_.ConsecutiveFails -gt 0 }) { 'High' } else { 'Info' }
    New-ADSHFinding -Category 'Health' -Id 'REPL' -Severity $sev `
        -Title "Domain controller replication status" `
        -Description "Replication failures and high latency impact consistency and security enforcement." `
        -Evidence $evidence `
        -Remediation "Investigate failing links with repadmin and event logs; fix DNS, connectivity, and AD sites."
}

#endregion

#region 10. DNS Health

function Get-DNSHealth {
    [CmdletBinding()]
    param(
        [int] $TimeoutSeconds
    )
    $cfg = Get-ADSHConfig
    if (-not $TimeoutSeconds) { $TimeoutSeconds = [int]$cfg.DNSDcDiagTimeoutSeconds }
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $evidence = @()
    foreach ($dc in $dcs) {
        $cmd = "dcdiag /s:$dc /test:DNS /v"
        try {
            $job = Start-Job -ScriptBlock { param($c) cmd.exe /c $c | Out-String } -ArgumentList $cmd
            if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
                $out = Receive-Job -Job $job
                $evidence += [pscustomobject]@{
                    DC     = $dc
                    Output = $out
                    Passed = ($out -notmatch 'FAIL|error')
                }
            } else {
                Stop-Job $job | Out-Null
                $evidence += [pscustomobject]@{
                    DC     = $dc
                    Output = 'Timeout'
                    Passed = $false
                }
            }
        } catch {
            $evidence += [pscustomobject]@{
                DC     = $dc
                Output = $_.Exception.Message
                Passed = $false
            }
        }
    }
    $sev = if ($evidence | Where-Object { -not $_.Passed }) { 'High' } else { 'Info' }
    New-ADSHFinding -Category 'Health' -Id 'DNS' -Severity $sev `
        -Title "DNS health via dcdiag" `
        -Description "AD-integrated DNS issues cause authentication and replication failures." `
        -Evidence $evidence `
        -Remediation "Resolve zone errors, stale records, and delegation issues; ensure DCs register SRV records."
}

#endregion

#region 11. SYSVOL Replication

function Get-SYSVOLReplicationStatus {
    [CmdletBinding()]
    param(
        [bool] $RequireDFSR
    )
    $cfg = Get-ADSHConfig
    if ($PSBoundParameters.ContainsKey('RequireDFSR') -eq $false) { $RequireDFSR = [bool]$cfg.SysvolRequireDFSR }
    $dcs = Get-ADDomainController -Filter *
    $evidence = foreach ($dc in $dcs) {
        $services = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            Get-Service -Name 'DFSR','NtFrs' -ErrorAction SilentlyContinue | Select-Object Name, Status
        } -ErrorAction SilentlyContinue
        [pscustomobject]@{
            DC          = $dc.HostName
            DFSRStatus  = ($services | Where-Object {$_.Name -eq 'DFSR'}).Status
            FRSStatus   = ($services | Where-Object {$_.Name -eq 'NtFrs'}).Status
        }
    }
    $frsActive = $evidence | Where-Object { $_.FRSStatus -eq 'Running' }
    $sev = if ($RequireDFSR -and $frsActive) { 'High' } else { 'Medium' }
    New-ADSHFinding -Category 'Health' -Id 'SYSVOL' -Severity $sev `
        -Title "SYSVOL replication service status (DFSR vs FRS)" `
        -Description "FRS is deprecated; DFSR is required. Confirm replication health and migration status." `
        -Evidence $evidence `
        -Remediation "Migrate SYSVOL from FRS to DFSR; validate DFSR connections and backlog with dfsrdiag."
}

#endregion

#region 12. FSMO Role Holders

function Get-FSMORoleHolders {
    [CmdletBinding()]
    param()
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $evidence = [pscustomobject]@{
        DomainNamingMaster     = $forest.DomainNamingMaster
        SchemaMaster           = $forest.SchemaMaster
        RIDMaster              = $domain.RIDMaster
        PDCEmulator            = $domain.PDCEmulator
        InfrastructureMaster   = $domain.InfrastructureMaster
    }
    New-ADSHFinding -Category 'Health' -Id 'FSMO' -Severity 'Info' `
        -Title "FSMO role holders" `
        -Description "Record current role holders to confirm availability and placement." `
        -Evidence $evidence `
        -Remediation "Ensure role holders are online, backed up, and placed appropriately per sites and capacity."
}

#endregion

#region 13. DC Service Status

function Get-DCServiceStatus {
    [CmdletBinding()]
    param(
        [string[]] $Services
    )
    $cfg = Get-ADSHConfig
    if (-not $Services) { $Services = $cfg.CriticalServices }
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $evidence = foreach ($dc in $dcs) {
        $svc = Invoke-Command -ComputerName $dc -ScriptBlock {
            param($names)
            Get-Service -Name $names -ErrorAction SilentlyContinue | Select-Object Name, Status
        } -ArgumentList ($Services) -ErrorAction SilentlyContinue
        [pscustomobject]@{
            DC       = $dc
            Services = $svc
        }
    }
    $down = $evidence | Where-Object { $_.Services | Where-Object { $_.Status -ne 'Running' } }
    $sev = if ($down) { 'High' } else { 'Info' }
    New-ADSHFinding -Category 'Health' -Id 'DC-SVC' -Severity $sev `
        -Title "Domain controller critical service status" `
        -Description "Critical DC services must be running for authentication and replication." `
        -Evidence $evidence `
        -Remediation "Start services or troubleshoot failures; check event logs and configuration."
}

#endregion

#region 14. AD Database Size and Growth

function Get-ADDatabaseStats {
    [CmdletBinding()]
    param()
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $evidence = foreach ($dc in $dcs) {
        try {
            $path = Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-Item 'C:\Windows\NTDS\ntds.dit' -ErrorAction Stop).FullName
            } -ErrorAction Stop
            $size = Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-Item 'C:\Windows\NTDS\ntds.dit').Length
            } -ErrorAction Stop
            [pscustomobject]@{
                DC        = $dc
                NtdsDit   = $path
                SizeBytes = $size
                SizeMB    = [math]::Round($size/1MB,2)
            }
        } catch {
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
}

#endregion

#region 15. Trust Relationships

function Get-TrustRelationships {
    [CmdletBinding()]
    param()
    $trusts = Get-ADTrust -Filter * -Properties *
    $evidence = $trusts | Select-Object Name, Source, Target, TrustType, TrustAttributes, Direction, IsForest, IsExternal
    $sev = if ($trusts.Count -gt 0) { 'Medium' } else { 'Info' }
    New-ADSHFinding -Category 'Exposure' -Id 'TRUSTS' -Severity $sev `
        -Title "Domain and forest trust relationships" `
        -Description "Review external and forest trusts; validate SID filtering and selective authentication." `
        -Evidence $evidence `
        -Remediation "Remove obsolete trusts; enable SID filtering; use selective authentication for external trusts."
}

#endregion

#region 16. GPO Review (links, permissions)

function Get-GPOReview {
    [CmdletBinding()]
    param()
    # Requires GroupPolicy module
    $all = Get-GPO -All -ErrorAction SilentlyContinue
    $xmls = @()
    foreach ($g in $all) {
        try {
            $temp = New-TemporaryFile
            Get-GPOReport -Guid $g.Id -ReportType Xml -Path $temp.FullName
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
    $sev = if ($orphans.Count -gt 0) { 'Medium' } else { 'Info' }
    New-ADSHFinding -Category 'Configuration' -Id 'GPO' -Severity $sev `
        -Title "GPO review (orphaned and security filtering)" `
        -Description "Identify orphaned GPOs and review security filtering for over-permission." `
        -Evidence $xmls `
        -Remediation "Delete or archive unused GPOs; tighten GPO permissions and links; document GPO ownership."
}

#endregion

#region 17. Pre-Windows 2000 Compatible Access Group

function Get-PreWin2000AccessRisks {
    [CmdletBinding()]
    param()
    try {
        $grp = Get-ADGroup -Identity 'Pre-Windows 2000 Compatible Access' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $grp.DistinguishedName -Recursive -ErrorAction SilentlyContinue
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
            -Description "Group may be renamed or domain-specific." `
            -Evidence $null `
            -Remediation "Validate group existence."
    }
}

#endregion

#region 18. SPN Audit (duplicates & roasting risks)

function Get-SPNAudit {
    [CmdletBinding()]
    param()
    $objs = Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, SamAccountName, objectClass, userAccountControl
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
    $dupes = $allSpns | Group-Object SPN | Where-Object { $_.Count -gt 1 } | ForEach-Object {
        [pscustomobject]@{
            SPN    = $_.Name
            Owners = ($_.Group | Select-Object -ExpandProperty Owner) -join ', '
        }
    }
    $sev = if ($dupes.Count -gt 0) { 'Medium' } else { 'Info' }
    New-ADSHFinding -Category 'Security' -Id 'SPN' -Severity $sev `
        -Title "SPN audit (duplicate SPNs & ownership)" `
        -Description "Duplicate SPNs cause auth conflicts; SPNs on user accounts increase Kerberoasting risk." `
        -Evidence [pscustomobject]@{ Duplicates = $dupes; AllSPNs = $allSpns }
        -Remediation "Remove duplicates; prefer computer accounts for service SPNs; monitor for high-value service tickets."
}

#endregion

#region 19. Audit Policy Verification

function Get-AuditPolicyVerification {
    [CmdletBinding()]
    param()
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $evidence = foreach ($dc in $dcs) {
        try {
            $out = Invoke-Command -ComputerName $dc -ScriptBlock { auditpol.exe /get /category:* | Out-String }
            [pscustomobject]@{
                DC     = $dc
                Output = $out
                KeyAreasCovered = ($out -match 'Account Logon|Account Management|Policy Change|Privilege Use|System')
            }
        } catch {
            [pscustomobject]@{
                DC     = $dc
                Output = "Failed: $($_.Exception.Message)"
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
}

#endregion

#region 20. Security Event Log Configuration

function Get-SecurityEventLogConfig {
    [CmdletBinding()]
    param(
        [int] $MinSizeMB
    )
    $cfg = Get-ADSHConfig
    if (-not $MinSizeMB) { $MinSizeMB = [int]$cfg.EventLogMinSizeMB }
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $evidence = foreach ($dc in $dcs) {
        try {
            $data = Invoke-Command -ComputerName $dc -ScriptBlock {
                Get-CimInstance -ClassName Win32_NTEventLogFile -Filter "LogfileName='Security'" |
                    Select-Object LogfileName, MaxFileSize, NumberOfRecords, OverwriteOutdated, OverwriteFile, Name
            }
            $sizeMB = [math]::Round(($data.MaxFileSize/1MB),2)
            [pscustomobject]@{
                DC              = $dc
                MaxFileSizeMB   = $sizeMB
                NumberOfRecords = $data.NumberOfRecords
                OverwritePolicy = if ($data.OverwriteOutdated) { 'Overwrite oldest' } elseif ($data.OverwriteFile) { 'Overwrite as needed' } else { 'Do not overwrite' }
            }
        } catch {
            [pscustomobject]@{
                DC              = $dc
                MaxFileSizeMB   = $null
                NumberOfRecords = $null
                OverwritePolicy = "Failed: $($_.Exception.Message)"
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
}

#endregion

#region Orchestrator

function Invoke-ADSecurityHealthCheck {
    [CmdletBinding()]
    param(
        [switch] $IncludeRawEvidence
    )
    Initialize-ADSHEnvironment
    $results = @()
    $results += Get-PrivilegedGroupMembership
    $results += Get-StaleAccounts
    $results += Get-PasswordPolicyAudit
    $results += Get-AccountsPasswordNeverExpires
    $results += Get-AccountsReversibleEncryption
    $results += Get-KerberosDelegationIssues
    $results += Get-AdminSDHolderProtectedAccounts
    $results += Get-ExcessivePermissionsDelegations
    $results += Get-DCReplicationStatus
    $results += Get-DNSHealth
    $results += Get-SYSVOLReplicationStatus
    $results += Get-FSMORoleHolders
    $results += Get-DCServiceStatus
    $results += Get-ADDatabaseStats
    $results += Get-TrustRelationships
    $results += Get-GPOReview
    $results += Get-PreWin2000AccessRisks
    $results += Get-SPNAudit
    $results += Get-AuditPolicyVerification
    $results += Get-SecurityEventLogConfig

    if (-not $IncludeRawEvidence) {
        # Trim very large evidence if needed in summary view
        $results = $results | ForEach-Object {
            $obj = $_ | Select-Object Timestamp, Category, Id, Severity, Title, Description, Remediation
            $obj
        }
    }
    $results
}

#endregion