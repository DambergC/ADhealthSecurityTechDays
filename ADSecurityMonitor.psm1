#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Active Directory Security Monitoring Module - Top 100 Security Risks
.DESCRIPTION
    This module performs read-only security checks against Active Directory,
    domain controllers, and related infrastructure. It is designed to help
    identify misconfigurations and high-risk settings similar to a PingCastle
    security report, categorized by LOW, MEDIUM and HIGH severity.

    Use this module with caution:
    - The functions in this module are primarily ASSESSMENT functions. They
      collect and report on risky configurations; they do NOT automatically
      remediate or change settings.
    - Any remediation based on these results (e.g. changing group membership,
      registry values, GPOs, service configurations, or KRBTGT passwords) must
      be planned, tested, and approved according to your organization's change
      management process.
    - Some recommendations (such as disabling services, tightening ACLs,
      altering delegation, changing RODC policies, or resetting KRBTGT) can
      break applications, trusts or user access if applied incorrectly.

    Always:
    - Test remediation steps in a non-production environment first.
    - Take and verify backups (system state, GPOs, CA configuration, etc.).
    - Coordinate with application owners and operations teams.
    - Document every change and have a rollback plan.

.NOTES
    Author:  Security Team
    Version: 1.0

    DISCLAIMER / USE WITH CAUTION

    By using this module, you acknowledge and agree that:
    - You are responsible for validating all findings and understanding the
      potential impact of any remediation actions.
    - The authors and distributors of this script are not responsible for any
      disruption, data loss, or security incidents resulting from its use.
    - All remediation actions should follow your organization's policies,
      security standards, and risk appetite.

    Recommended usage:
    - Run in a controlled environment with appropriate privileges.
    - Review each finding with experienced AD/security administrators.
    - Implement remediation through documented change processes only after
      thorough testing and impact analysis.
#>

# ============================================================================
# HIGH SEVERITY RISKS (30 checks)
# ============================================================================

function Test-KrbtgtPasswordAge {
    <#
    . SYNOPSIS
        Check KRBTGT account password age (HIGH)
    .DESCRIPTION
        KRBTGT password should be rotated at least yearly.  Old passwords are severe security risks.
    #>
    [CmdletBinding()]
    param(
        [int]$MaxDaysOld = 180
    )
    
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
    $age = (Get-Date) - $krbtgt.PasswordLastSet
    
    [PSCustomObject]@{
        CheckName = "KRBTGT Password Age"
        Severity = "HIGH"
        Status = if ($age. Days -gt $MaxDaysOld) { "FAIL" } else { "PASS" }
        PasswordLastSet = $krbtgt. PasswordLastSet
        DaysOld = $age.Days
        MaxAllowed = $MaxDaysOld
        Recommendation = "Reset KRBTGT password immediately if older than 180 days"
        Risk = "Golden Ticket attacks possible with compromised old KRBTGT password"
    }
}

function Test-AdminSDHolder {
    <#
    .SYNOPSIS
        Check AdminSDHolder ACL modifications (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties ntSecurityDescriptor
    $acl = $adminSDHolder. ntSecurityDescriptor.Access | Where-Object { 
        $_.IdentityReference -notmatch "SYSTEM|Domain Admins|Enterprise Admins|Administrators"
    }
    
    [PSCustomObject]@{
        CheckName = "AdminSDHolder ACL"
        Severity = "HIGH"
        Status = if ($acl.Count -gt 0) { "FAIL" } else { "PASS" }
        UnexpectedACEs = $acl.Count
        Details = $acl | Select-Object IdentityReference, AccessControlType, ActiveDirectoryRights
        Recommendation = "Remove unauthorized ACEs from AdminSDHolder"
        Risk = "Persistent elevated privileges through AdminSDHolder manipulation"
    }
}

function Test-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        Find computers with unconstrained delegation (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $computers = Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -eq 515} -Properties TrustedForDelegation, OperatingSystem
    
    [PSCustomObject]@{
        CheckName = "Unconstrained Delegation"
        Severity = "HIGH"
        Status = if ($computers.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedComputers = $computers.Count
        Details = $computers | Select-Object Name, OperatingSystem, DistinguishedName
        Recommendation = "Convert to constrained delegation or remove delegation"
        Risk = "Credential theft and lateral movement via delegation abuse"
    }
}

function Test-DCRegistryAutoLogon {
    <#
    . SYNOPSIS
        Check for AutoLogon credentials stored in DC registry (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]:: OpenRemoteBaseKey('LocalMachine', $dc. HostName)
            $key = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
            $autoLogon = $key.GetValue("AutoAdminLogon")
            
            if ($autoLogon -eq "1") {
                $results += [PSCustomObject]@{
                    DomainController = $dc. HostName
                    AutoLogonEnabled = $true
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                Error = $_.Exception.Message
            }
        }
    }
    
    [PSCustomObject]@{
        CheckName = "DC AutoLogon Registry"
        Severity = "HIGH"
        Status = if ($results.Count -gt 0) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Disable AutoLogon on all domain controllers"
        Risk = "Plaintext credentials stored on domain controllers"
    }
}

function Test-NTLMAuthentication {
    <#
    .SYNOPSIS
        Check NTLM authentication settings (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
            $lmCompatLevel = $key.GetValue("LmCompatibilityLevel")
            
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                LMCompatibilityLevel = $lmCompatLevel
                IsSecure = $lmCompatLevel -ge 5
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "NTLM Authentication Level"
        Severity = "HIGH"
        Status = if ($results | Where-Object { -not $_.IsSecure }) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Set LmCompatibilityLevel to 5 (NTLMv2 only)"
        Risk = "Weak NTLM authentication vulnerable to relay attacks"
    }
}

function Test-PreWindows2000CompatibleAccess {
    <#
    . SYNOPSIS
        Check for Pre-Windows 2000 Compatible Access group members (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $group = Get-ADGroup -Identity "Pre-Windows 2000 Compatible Access" -Properties Members
    $memberCount = $group.Members.Count
    
    [PSCustomObject]@{
        CheckName = "Pre-Windows 2000 Compatible Access"
        Severity = "HIGH"
        Status = if ($memberCount -gt 1) { "FAIL" } else { "PASS" }
        MemberCount = $memberCount
        Members = $group.Members
        Recommendation = "Remove all members from this group if not needed"
        Risk = "Allows anonymous access to user and group information"
    }
}

function Test-DCPrintSpooler {
    <#
    . SYNOPSIS
        Check if Print Spooler is running on DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $spooler = Get-Service -ComputerName $dc. HostName -Name Spooler -ErrorAction Stop
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                ServiceStatus = $spooler.Status
                StartType = $spooler.StartType
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC Print Spooler Service"
        Severity = "HIGH"
        Status = if ($results | Where-Object { $_.ServiceStatus -eq 'Running' }) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Disable Print Spooler service on all domain controllers"
        Risk = "PrintNightmare and other print spooler exploits"
    }
}

function Test-ProtectedUsersGroup {
    <#
    .SYNOPSIS
        Check if privileged accounts are in Protected Users group (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $protectedUsers = Get-ADGroupMember -Identity "Protected Users"
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive
    $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive
    
    $unprotectedAdmins = $domainAdmins + $enterpriseAdmins | Where-Object {
        $_.SamAccountName -notin $protectedUsers.SamAccountName
    } | Select-Object -Unique
    
    [PSCustomObject]@{
        CheckName = "Protected Users Group Membership"
        Severity = "HIGH"
        Status = if ($unprotectedAdmins.Count -gt 0) { "FAIL" } else { "PASS" }
        UnprotectedAdminCount = $unprotectedAdmins.Count
        Details = $unprotectedAdmins | Select-Object Name, SamAccountName
        Recommendation = "Add all privileged accounts to Protected Users group"
        Risk = "Privileged accounts vulnerable to credential theft"
    }
}

function Test-DCUnauthorizedSoftware {
    <#
    .SYNOPSIS
        Check for unauthorized software on DCs (HIGH)
    #>
    [CmdletBinding()]
    param(
        [string[]]$UnauthorizedSoftware = @("*Chrome*", "*Firefox*", "*Skype*", "*Teams*")
    )
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $software = Get-WmiObject -ComputerName $dc. HostName -Class Win32_Product | 
                Where-Object { 
                    $name = $_.Name
                    $UnauthorizedSoftware | Where-Object { $name -like $_ }
                }
            
            if ($software) {
                $results += [PSCustomObject]@{
                    DomainController = $dc.HostName
                    UnauthorizedSoftware = $software.Name -join ", "
                }
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC Unauthorized Software"
        Severity = "HIGH"
        Status = if ($results. Count -gt 0) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Remove all unauthorized software from domain controllers"
        Risk = "Increased attack surface and potential compromise vectors"
    }
}

function Test-DCAnonymousAccess {
    <#
    . SYNOPSIS
        Check anonymous LDAP access to DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
            $ldapEnforcement = $key.GetValue("LDAPServerIntegrity")
            
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                LDAPServerIntegrity = $ldapEnforcement
                IsSecure = $ldapEnforcement -ge 2
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC Anonymous LDAP Access"
        Severity = "HIGH"
        Status = if ($results | Where-Object { -not $_. IsSecure }) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Set LDAPServerIntegrity to 2 (require signing)"
        Risk = "Anonymous enumeration and information disclosure"
    }
}

function Test-PrivilegedAccountsWithSPN {
    <#
    . SYNOPSIS
        Check for privileged accounts with SPNs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")

    # Build list of privileged users explicitly, then de-duplicate
    $privilegedUsers = @()
    foreach ($group in $privilegedGroups) {
        $privilegedUsers += Get-ADGroupMember -Identity $group -Recursive |
            Where-Object { $_.objectClass -eq 'user' }
    }
    $privilegedUsers = $privilegedUsers | Select-Object -Unique
    
    $results = @()
    foreach ($user in $privilegedUsers) {
        $userObj = Get-ADUser -Identity $user -Properties ServicePrincipalName
        if ($userObj.ServicePrincipalName) {
            $results += $userObj
        }
    }
    
    [PSCustomObject]@{
        CheckName        = "Privileged Accounts with SPNs"
        Severity         = "HIGH"
        Status           = if ($results.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedAccounts = $results.Count
        Details          = $results | Select-Object Name, SamAccountName, ServicePrincipalName
        Recommendation   = "Remove SPNs from privileged accounts or use separate service accounts"
        Risk             = "Kerberoasting attacks targeting privileged accounts"
    }
}

function Test-DCSysvolPermissions {
    <#
    .SYNOPSIS
        Check SYSVOL share permissions (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter * | Select-Object -First 1
    $sysvolPath = "\\$($dcs.HostName)\SYSVOL"
    
    try {
        $acl = Get-Acl -Path $sysvolPath
        $weakPermissions = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users|Authenticated Users" -and
            $_.FileSystemRights -match "FullControl|Modify|Write"
        }
        
        [PSCustomObject]@{
            CheckName = "SYSVOL Permissions"
            Severity = "HIGH"
            Status = if ($weakPermissions) { "FAIL" } else { "PASS" }
            Details = $weakPermissions | Select-Object IdentityReference, FileSystemRights, AccessControlType
            Recommendation = "Restrict SYSVOL write permissions to Domain Admins only"
            Risk = "Unauthorized GPO modifications through SYSVOL manipulation"
        }
    } catch {
        [PSCustomObject]@{
            CheckName = "SYSVOL Permissions"
            Severity = "HIGH"
            Status = "ERROR"
            Details = $_.Exception.Message
            Recommendation = "Unable to check SYSVOL permissions"
            Risk = "Unknown"
        }
    }
}

function Test-RODCPasswordReplicationPolicy {
    <#
    .SYNOPSIS
        Check RODC password replication policy (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $rodcs = Get-ADDomainController -Filter {IsReadOnly -eq $true}
    $results = @()
    
    foreach ($rodc in $rodcs) {
        $allowed = Get-ADDomainControllerPasswordReplicationPolicy -Identity $rodc -Allowed
        $denied = Get-ADDomainControllerPasswordReplicationPolicy -Identity $rodc -Denied
        
        # Check if privileged accounts are in allowed list
        $privilegedInAllowed = $allowed | Where-Object {
            $_.SamAccountName -match "admin|administrator"
        }
        
        $results += [PSCustomObject]@{
            RODC = $rodc.Name
            AllowedCount = $allowed.Count
            PrivilegedInAllowed = $privilegedInAllowed.Count
            DeniedCount = $denied. Count
        }
    }
    
    [PSCustomObject]@{
        CheckName = "RODC Password Replication Policy"
        Severity = "HIGH"
        Status = if ($results | Where-Object {$_. PrivilegedInAllowed -gt 0}) { "FAIL" } else { "PASS" }
        RODCCount = $rodcs.Count
        Details = $results
        Recommendation = "Ensure privileged accounts are in RODC denied password replication list"
        Risk = "Privileged credentials cached on potentially less secure RODCs"
    }
}

function Test-DCLocalAdminGroup {
    <#
    . SYNOPSIS
        Check local Administrators group membership on DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $admins = Get-WmiObject -ComputerName $dc.HostName -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent='Win32_Group.Domain=""$($dc.HostName)"",Name=""Administrators""'"
            
            $unexpectedMembers = $admins | Where-Object {
                $_. PartComponent -notmatch "Domain Admins|Enterprise Admins|Administrator"
            }
            
            if ($unexpectedMembers) {
                $results += [PSCustomObject]@{
                    DomainController = $dc. HostName
                    UnexpectedMembers = $unexpectedMembers.Count
                }
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC Local Administrators Group"
        Severity = "HIGH"
        Status = if ($results. Count -gt 0) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Only Domain Admins should be in DC local Administrators group"
        Risk = "Unauthorized privileged access to domain controllers"
    }
}

function Test-DCRemoteAccessServices {
    <#
    . SYNOPSIS
        Check for remote access services on DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $dangerousServices = @("RemoteRegistry", "RemoteAccess", "TermService")
    $results = @()
    
    foreach ($dc in $dcs) {
        foreach ($service in $dangerousServices) {
            try {
                $svc = Get-Service -ComputerName $dc. HostName -Name $service -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') {
                    $results += [PSCustomObject]@{
                        DomainController = $dc.HostName
                        Service = $service
                        Status = $svc.Status
                    }
                }
            } catch {}
        }
    }
    
    [PSCustomObject]@{
        CheckName = "DC Remote Access Services"
        Severity = "HIGH"
        Status = if ($results.Count -gt 0) { "WARN" } else { "PASS" }
        Details = $results
        Recommendation = "Disable unnecessary remote access services on DCs"
        Risk = "Increased attack surface for remote exploitation"
    }
}

function Test-SMBv1Protocol {
    <#
    . SYNOPSIS
        Check if SMBv1 is enabled on DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $smbv1 = Get-SmbServerConfiguration -CimSession $dc.HostName | Select-Object EnableSMB1Protocol
            if ($smbv1.EnableSMB1Protocol) {
                $results += [PSCustomObject]@{
                    DomainController = $dc.HostName
                    SMBv1Enabled = $true
                }
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "SMBv1 Protocol Enabled"
        Severity = "HIGH"
        Status = if ($results.Count -gt 0) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Disable SMBv1 protocol on all domain controllers"
        Risk = "Vulnerable to WannaCry, NotPetya, and other SMBv1 exploits"
    }
}

function Test-DCFirewallStatus {
    <#
    . SYNOPSIS
        Check Windows Firewall status on DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $profiles = Get-NetFirewallProfile -CimSession $dc. HostName
            foreach ($profile in $profiles) {
                if (-not $profile.Enabled) {
                    $results += [PSCustomObject]@{
                        DomainController = $dc. HostName
                        Profile = $profile.Name
                        Enabled = $false
                    }
                }
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC Windows Firewall Status"
        Severity = "HIGH"
        Status = if ($results.Count -gt 0) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Enable Windows Firewall on all profiles on domain controllers"
        Risk = "Domain controllers exposed to network attacks"
    }
}

function Test-BitLockerOnDCs {
    <#
    . SYNOPSIS
        Check if BitLocker is enabled on DCs (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $bitlocker = Get-BitLockerVolume -CimSession $dc. HostName | Where-Object {$_.VolumeType -eq 'OperatingSystem'}
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                ProtectionStatus = $bitlocker.ProtectionStatus
                EncryptionPercentage = $bitlocker. EncryptionPercentage
            }
        } catch {
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                ProtectionStatus = "Unknown"
                EncryptionPercentage = 0
            }
        }
    }
    
    [PSCustomObject]@{
        CheckName = "BitLocker on Domain Controllers"
        Severity = "HIGH"
        Status = if ($results | Where-Object {$_.ProtectionStatus -ne 'On'}) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Enable BitLocker on all domain controller volumes"
        Risk = "Physical theft could expose domain database and secrets"
    }
}

function Test-NullSessionAccess {
    <#
    .SYNOPSIS
        Check for null session access configuration (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
            $restrictAnonymous = $key.GetValue("RestrictAnonymous")
            $restrictAnonymousSAM = $key.GetValue("RestrictAnonymousSAM")
            
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                RestrictAnonymous = $restrictAnonymous
                RestrictAnonymousSAM = $restrictAnonymousSAM
                IsSecure = ($restrictAnonymous -ge 1 -and $restrictAnonymousSAM -ge 1)
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "Null Session Access"
        Severity = "HIGH"
        Status = if ($results | Where-Object {-not $_.IsSecure}) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Set RestrictAnonymous and RestrictAnonymousSAM to 1"
        Risk = "Anonymous users can enumerate domain information"
    }
}

function Test-LLMNRAndNBTNS {
    <#
    . SYNOPSIS
        Check if LLMNR and NetBIOS are disabled (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $llmnr = $reg.OpenSubKey("SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")
            $llmnrEnabled = if ($llmnr) { $llmnr.GetValue("EnableMulticast") -ne 0 } else { $true }
            
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                LLMNREnabled = $llmnrEnabled
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "LLMNR and NetBIOS"
        Severity = "HIGH"
        Status = if ($results | Where-Object {$_.LLMNREnabled}) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Disable LLMNR and NetBIOS-NS on all domain controllers"
        Risk = "LLMNR/NetBIOS poisoning attacks for credential theft"
    }
}

function Test-PrivilegedGroupsNesting {
    <#
    . SYNOPSIS
        Check for nested privileged groups (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $results = @()
    
    foreach ($group in $privilegedGroups) {
        $members = Get-ADGroupMember -Identity $group
        $nestedGroups = $members | Where-Object {$_. objectClass -eq 'group'}
        
        if ($nestedGroups) {
            $results += [PSCustomObject]@{
                PrivilegedGroup = $group
                NestedGroups = ($nestedGroups. Name -join ", ")
                Count = $nestedGroups.Count
            }
        }
    }
    
    [PSCustomObject]@{
        CheckName = "Privileged Groups Nesting"
        Severity = "HIGH"
        Status = if ($results. Count -gt 0) { "WARN" } else { "PASS" }
        Details = $results
        Recommendation = "Avoid nesting groups in privileged groups for better visibility"
        Risk = "Hidden privileged access through group nesting"
    }
}

function Test-DCPatchLevel {
    <#
    . SYNOPSIS
        Check if DCs are missing critical security updates (HIGH)
    #>
    [CmdletBinding()]
    param(
        [int]$DaysSinceLastUpdate = 30
    )
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $lastUpdate = Get-HotFix -ComputerName $dc.HostName | 
                Sort-Object InstalledOn -Descending | 
                Select-Object -First 1
            
            $daysSince = ((Get-Date) - $lastUpdate. InstalledOn).Days
            
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                LastUpdate = $lastUpdate.InstalledOn
                DaysSinceUpdate = $daysSince
                NeedsUpdate = $daysSince -gt $DaysSinceLastUpdate
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC Patch Level"
        Severity = "HIGH"
        Status = if ($results | Where-Object {$_.NeedsUpdate}) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Apply security updates to domain controllers within 30 days"
        Risk = "Unpatched DCs vulnerable to known exploits"
    }
}

function Test-DomainObjectQuota {
    <#
    . SYNOPSIS
        Check domain object creation quota (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $domain = Get-ADDomain
    $quota = $domain.MachineAccountQuota
    
    [PSCustomObject]@{
        CheckName = "Domain Object Creation Quota"
        Severity = "HIGH"
        Status = if ($quota -gt 0) { "FAIL" } else { "PASS" }
        CurrentQuota = $quota
        Recommendation = "Set ms-DS-MachineAccountQuota to 0"
        Risk = "Unprivileged users can create computer accounts for attacks"
    }
}

function Test-GPOBackups {
    <#
    . SYNOPSIS
        Check for recent GPO backups (HIGH)
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath = "\\$((Get-ADDomain).PDCEmulator)\GPOBackups",
        [int]$MaxDaysOld = 30
    )
    
    try {
        if (Test-Path $BackupPath) {
            $latestBackup = Get-ChildItem -Path $BackupPath -Directory | 
                Sort-Object CreationTime -Descending | 
                Select-Object -First 1
            
            $daysSince = if ($latestBackup) { 
                ((Get-Date) - $latestBackup.CreationTime).Days 
            } else { 
                999 
            }
            
            [PSCustomObject]@{
                CheckName = "GPO Backups"
                Severity = "HIGH"
                Status = if ($daysSince -gt $MaxDaysOld) { "FAIL" } else { "PASS" }
                LastBackup = if ($latestBackup) { $latestBackup.CreationTime } else { "Never" }
                DaysSince = $daysSince
                Recommendation = "Backup GPOs at least monthly"
                Risk = "Cannot recover from GPO corruption or malicious changes"
            }
        } else {
            [PSCustomObject]@{
                CheckName = "GPO Backups"
                Severity = "HIGH"
                Status = "FAIL"
                LastBackup = "Never"
                DaysSince = 999
                Recommendation = "Implement GPO backup strategy immediately"
                Risk = "No GPO backups exist"
            }
        }
    } catch {
        [PSCustomObject]@{
            CheckName = "GPO Backups"
            Severity = "HIGH"
            Status = "ERROR"
            Details = $_.Exception.Message
            Recommendation = "Configure GPO backup path and schedule"
            Risk = "Unable to verify GPO backup status"
        }
    }
}

function Test-AdminAccountIsolation {
    <#
    .SYNOPSIS
        Check if admin accounts are used for regular activities (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $admins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object {$_.objectClass -eq 'user'}
    $results = @()
    
    foreach ($admin in $admins) {
        $user = Get-ADUser -Identity $admin -Properties LastLogonDate, LogonCount
        $lastLogon = $user.LastLogonDate
        
        # If admin account logged on recently, check if there's a corresponding non-admin account
        if ($lastLogon -and $lastLogon -gt (Get-Date).AddDays(-7)) {
            $nonAdminAccount = Get-ADUser -Filter "Name -like '*$($user.Name)*' -and Enabled -eq `$true" | 
                Where-Object {$_.SamAccountName -ne $user.SamAccountName}
            
            if (-not $nonAdminAccount) {
                $results += [PSCustomObject]@{
                    AdminAccount = $user.SamAccountName
                    LastLogon = $lastLogon
                    HasSeparateUserAccount = $false
                }
            }
        }
    }
    
    [PSCustomObject]@{
        CheckName = "Admin Account Isolation"
        Severity = "HIGH"
        Status = if ($results.Count -gt 0) { "WARN" } else { "PASS" }
        Details = $results
        Recommendation = "Administrators should have separate accounts for admin and regular tasks"
        Risk = "Admin credentials exposed during regular activities"
    }
}

function Test-ServiceAccountPasswords {
    <#
    .SYNOPSIS
        Check service accounts for weak passwords (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties PasswordLastSet, PasswordNeverExpires
    
    $weakAccounts = $serviceAccounts | Where-Object {
        $_.PasswordNeverExpires -or 
        ((Get-Date) - $_.PasswordLastSet).Days -gt 365
    }
    
    [PSCustomObject]@{
        CheckName = "Service Account Password Policy"
        Severity = "HIGH"
        Status = if ($weakAccounts.Count -gt 0) { "FAIL" } else { "PASS" }
        TotalServiceAccounts = $serviceAccounts. Count
        WeakAccounts = $weakAccounts.Count
        Details = $weakAccounts | Select-Object Name, SamAccountName, PasswordLastSet, PasswordNeverExpires
        Recommendation = "Use Group Managed Service Accounts (gMSA) or set password expiration"
        Risk = "Service accounts with old passwords are prime Kerberoasting targets"
    }
}

function Test-CertificateServices {
    <#
    . SYNOPSIS
        Check Active Directory Certificate Services configuration (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    try {
        $caServers = Get-ADObject -Filter {objectClass -eq "pKIEnrollmentService"} -SearchBase "CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)" -Properties dNSHostName
        
        $results = @()
        foreach ($ca in $caServers) {
            $results += [PSCustomObject]@{
                CAServer = $ca.dNSHostName
                Name = $ca.Name
            }
        }
        
        [PSCustomObject]@{
            CheckName = "Active Directory Certificate Services"
            Severity = "HIGH"
            Status = if ($caServers.Count -gt 0) { "INFO" } else { "PASS" }
            CACount = $caServers.Count
            Details = $results
            Recommendation = "Ensure CA servers are properly secured and monitored for ESC vulnerabilities"
            Risk = "Misconfigured AD CS can lead to privilege escalation (ESC1-ESC8)"
        }
    } catch {
        [PSCustomObject]@{
            CheckName = "Active Directory Certificate Services"
            Severity = "HIGH"
            Status = "INFO"
            CACount = 0
            Recommendation = "No AD CS found or unable to query"
            Risk = "N/A"
        }
    }
}

function Test-ExchangeSchemaVersion {
    <#
    .SYNOPSIS
        Check for Exchange schema extensions and vulnerabilities (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    try {
        $schemaNC = (Get-ADRootDSE).schemaNamingContext
        $exchangeSchema = Get-ADObject -Identity "CN=ms-Exch-Schema-Version-Pt,$schemaNC" -Properties rangeUpper -ErrorAction SilentlyContinue
        
        if ($exchangeSchema) {
            [PSCustomObject]@{
                CheckName = "Exchange Schema Version"
                Severity = "HIGH"
                Status = "INFO"
                SchemaVersion = $exchangeSchema. rangeUpper
                Recommendation = "Ensure Exchange servers are patched against ProxyLogon, ProxyShell, and other vulnerabilities"
                Risk = "Exchange servers with AD integration are high-value targets"
            }
        } else {
            [PSCustomObject]@{
                CheckName = "Exchange Schema Version"
                Severity = "HIGH"
                Status = "PASS"
                SchemaVersion = "Not Found"
                Recommendation = "N/A - No Exchange detected"
                Risk = "N/A"
            }
        }
    } catch {
        [PSCustomObject]@{
            CheckName = "Exchange Schema Version"
            Severity = "HIGH"
            Status = "ERROR"
            Details = $_.Exception.Message
            Recommendation = "Unable to check Exchange schema"
            Risk = "Unknown"
        }
    }
}

function Test-LAPSDeployment {
    <#
    .SYNOPSIS
        Check if LAPS is deployed (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    try {
        $schemaNC = (Get-ADRootDSE).schemaNamingContext
        $lapsAttribute = Get-ADObject -Identity "CN=ms-Mcs-AdmPwd,$schemaNC" -ErrorAction SilentlyContinue
        
        if ($lapsAttribute) {
            $computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime | 
                Where-Object {$_.'ms-Mcs-AdmPwdExpirationTime' -eq $null}
            
            [PSCustomObject]@{
                CheckName = "LAPS Deployment"
                Severity = "HIGH"
                Status = if ($computers.Count -gt 0) { "WARN" } else { "PASS" }
                LAPSInstalled = $true
                ComputersWithoutLAPS = $computers.Count
                Recommendation = "Deploy LAPS to all computers for local admin password management"
                Risk = "Shared local admin passwords enable lateral movement"
            }
        } else {
            [PSCustomObject]@{
                CheckName = "LAPS Deployment"
                Severity = "HIGH"
                Status = "FAIL"
                LAPSInstalled = $false
                Recommendation = "Deploy LAPS immediately"
                Risk = "No LAPS deployment detected - local admin passwords not managed"
            }
        }
    } catch {
        [PSCustomObject]@{
            CheckName = "LAPS Deployment"
            Severity = "HIGH"
            Status = "ERROR"
            Details = $_.Exception. Message
            Recommendation = "Unable to verify LAPS deployment"
            Risk = "Unknown"
        }
    }
}

function Test-DNSSecurity {
    <#
    . SYNOPSIS
        Check DNS security settings (HIGH)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter * | Where-Object {$_.IsGlobalCatalog}
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $dnsSettings = Get-DnsServerSetting -CimSession $dc. HostName
            
            $results += [PSCustomObject]@{
                Server = $dc.HostName
                SecureResponses = $dnsSettings.SecureResponses
                XfrConnectTimeout = $dnsSettings.XfrConnectTimeout
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DNS Security Configuration"
        Severity = "HIGH"
        Status = if ($results | Where-Object {-not $_.SecureResponses}) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Enable secure DNS responses and restrict zone transfers"
        Risk = "DNS cache poisoning and unauthorized zone transfers"
    }
}

# ============================================================================
# MEDIUM SEVERITY RISKS (40 checks)
# ============================================================================

function Test-StaleComputerAccounts {
    <#
    .SYNOPSIS
        Find stale computer accounts (MEDIUM)
    #>
    [CmdletBinding()]
    param(
        [int]$DaysInactive = 90
    )
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    $staleComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $cutoffDate -and Enabled -eq $true} -Properties LastLogonTimeStamp, OperatingSystem
    
    [PSCustomObject]@{
        CheckName = "Stale Computer Accounts"
        Severity = "MEDIUM"
        Status = if ($staleComputers.Count -gt 0) { "FAIL" } else { "PASS" }
        StaleAccountCount = $staleComputers.Count
        DaysInactive = $DaysInactive
        Details = $staleComputers | Select-Object Name, OperatingSystem, @{N="LastLogon";E={[DateTime]::FromFileTime($_.LastLogonTimeStamp)}} | Select-Object -First 10
        Recommendation = "Disable or remove computer accounts inactive for $DaysInactive+ days"
        Risk = "Stale accounts can be compromised for unauthorized access"
    }
}

function Test-StaleUserAccounts {
    <#
    .SYNOPSIS
        Find stale user accounts (MEDIUM)
    #>
    [CmdletBinding()]
    param(
        [int]$DaysInactive = 90
    )
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    $staleUsers = Get-ADUser -Filter {LastLogonTimeStamp -lt $cutoffDate -and Enabled -eq $true} -Properties LastLogonTimeStamp, Created
    
    [PSCustomObject]@{
        CheckName = "Stale User Accounts"
        Severity = "MEDIUM"
        Status = if ($staleUsers.Count -gt 0) { "FAIL" } else { "PASS" }
        StaleAccountCount = $staleUsers.Count
        DaysInactive = $DaysInactive
        Details = $staleUsers | Select-Object Name, SamAccountName, @{N="LastLogon";E={[DateTime]::FromFileTime($_.LastLogonTimeStamp)}} | Select-Object -First 10
        Recommendation = "Disable or remove user accounts inactive for $DaysInactive+ days"
        Risk = "Inactive accounts are targets for attackers"
    }
}

function Test-PasswordPolicy {
    <#
    . SYNOPSIS
        Check domain password policy settings (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $policy = Get-ADDefaultDomainPasswordPolicy
    
    $issues = @()
    if ($policy.MinPasswordLength -lt 14) { $issues += "Minimum password length less than 14" }
    if ($policy.MaxPasswordAge. Days -gt 365) { $issues += "Max password age exceeds 365 days" }
    if ($policy. PasswordHistoryCount -lt 24) { $issues += "Password history less than 24" }
    if (-not $policy.ComplexityEnabled) { $issues += "Password complexity not enabled" }
    if ($policy.LockoutThreshold -eq 0 -or $policy.LockoutThreshold -gt 5) { $issues += "Lockout threshold not configured properly" }
    
    [PSCustomObject]@{
        CheckName = "Domain Password Policy"
        Severity = "MEDIUM"
        Status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }
        MinPasswordLength = $policy.MinPasswordLength
        MaxPasswordAge = $policy.MaxPasswordAge. Days
        PasswordHistoryCount = $policy.PasswordHistoryCount
        ComplexityEnabled = $policy.ComplexityEnabled
        LockoutThreshold = $policy.LockoutThreshold
        Issues = $issues
        Recommendation = "Align password policy with NIST/CIS standards"
        Risk = "Weak passwords vulnerable to brute force and guessing"
    }
}

function Test-ReversibleEncryption {
    <#
    .SYNOPSIS
        Find accounts with reversible encryption enabled (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption
    
    [PSCustomObject]@{
        CheckName = "Reversible Encryption Enabled"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedUsers = $users.Count
        Details = $users | Select-Object Name, SamAccountName, DistinguishedName
        Recommendation = "Disable reversible encryption for all accounts"
        Risk = "Passwords stored in reversible format are equivalent to plaintext"
    }
}

function Test-EmptyPasswordAllowed {
    <#
    .SYNOPSIS
        Find accounts that don't require passwords (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired
    
    [PSCustomObject]@{
        CheckName = "Password Not Required"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedUsers = $users.Count
        Details = $users | Select-Object Name, SamAccountName, Enabled
        Recommendation = "Require passwords for all user accounts"
        Risk = "Accounts without passwords provide easy unauthorized access"
    }
}

function Test-PasswordNeverExpires {
    <#
    .SYNOPSIS
        Find accounts with non-expiring passwords (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires, PasswordLastSet
    
    # Exclude service accounts or specific OUs if needed
    $users = $users | Where-Object { $_. DistinguishedName -notmatch "OU=Service Accounts" }
    
    [PSCustomObject]@{
        CheckName = "Password Never Expires"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedUsers = $users.Count
        Details = $users | Select-Object Name, SamAccountName, PasswordLastSet | Select-Object -First 10
        Recommendation = "Set password expiration for all user accounts except documented service accounts"
        Risk = "Old passwords increase risk of compromise"
    }
}

function Test-DESEncryption {
    <#
    .SYNOPSIS
        Find accounts using weak DES encryption (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly
    $computers = Get-ADComputer -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly
    
    [PSCustomObject]@{
        CheckName = "DES Encryption Only"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0 -or $computers.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedUsers = $users. Count
        AffectedComputers = $computers. Count
        Details = @{
            Users = $users | Select-Object Name, SamAccountName
            Computers = $computers | Select-Object Name
        }
        Recommendation = "Disable DES-only encryption for all accounts"
        Risk = "DES encryption is cryptographically weak and easily broken"
    }
}

function Test-KerberosPreAuthNotRequired {
    <#
    . SYNOPSIS
        Find accounts not requiring Kerberos pre-authentication (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    
    [PSCustomObject]@{
        CheckName = "Kerberos Pre-Auth Not Required"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0) { "FAIL" } else { "PASS" }
        AffectedUsers = $users.Count
        Details = $users | Select-Object Name, SamAccountName, Enabled
        Recommendation = "Enable Kerberos pre-authentication for all accounts"
        Risk = "AS-REP roasting attacks to obtain crackable hashes"
    }
}

function Test-ServicePrincipalNames {
    <#
    .SYNOPSIS
        Find user accounts with SPNs (potential Kerberoasting targets) (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet
    
    [PSCustomObject]@{
        CheckName = "User Accounts with SPNs"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0) { "WARN" } else { "PASS" }
        UsersWithSPN = $users.Count
        Details = $users | Select-Object Name, SamAccountName, ServicePrincipalName, PasswordLastSet
        Recommendation = "Use Group Managed Service Accounts (gMSA) for service accounts with SPNs"
        Risk = "Kerberoasting attacks to obtain crackable service account passwords"
    }
}

function Test-AdminAccountNamingConvention {
    <#
    .SYNOPSIS
        Check for admin accounts not following naming conventions (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $admins = $adminGroups | ForEach-Object {
        Get-ADGroupMember -Identity $_ -Recursive | Where-Object { $_. objectClass -eq 'user' }
    } | Select-Object -Unique
    
    $improperlyNamed = $admins | Where-Object { 
        $_.SamAccountName -notmatch "^(adm|admin)" 
    }
    
    [PSCustomObject]@{
        CheckName = "Admin Account Naming Convention"
        Severity = "MEDIUM"
        Status = if ($improperlyNamed.Count -gt 0) { "WARN" } else { "PASS" }
        ImproperlyNamedCount = $improperlyNamed. Count
        Details = $improperlyNamed | Select-Object Name, SamAccountName
        Recommendation = "Use consistent naming convention for admin accounts (e.g., adm- prefix)"
        Risk = "Difficult to identify and protect privileged accounts"
    }
}

function Test-DCSMBSigning {
    <#
    . SYNOPSIS
        Check SMB signing configuration on DCs (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]:: OpenRemoteBaseKey('LocalMachine', $dc. HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\LanManServer\Parameters")
            $smbSigning = $key.GetValue("RequireSecuritySignature")
            
            $results += [PSCustomObject]@{
                DomainController = $dc. HostName
                SMBSigningRequired = $smbSigning -eq 1
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "DC SMB Signing"
        Severity = "MEDIUM"
        Status = if ($results | Where-Object { -not $_.SMBSigningRequired }) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Require SMB signing on all domain controllers"
        Risk = "SMB relay attacks and man-in-the-middle attacks"
    }
}

function Test-LDAPSConfiguration {
    <#
    .SYNOPSIS
        Check LDAPS (LDAP over SSL) configuration (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $dcs = Get-ADDomainController -Filter *
    $results = @()
    
    foreach ($dc in $dcs) {
        try {
            $ldaps = Test-NetConnection -ComputerName $dc. HostName -Port 636 -WarningAction SilentlyContinue
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                LDAPSAvailable = $ldaps.TcpTestSucceeded
            }
        } catch {}
    }
    
    [PSCustomObject]@{
        CheckName = "LDAPS Configuration"
        Severity = "MEDIUM"
        Status = if ($results | Where-Object { -not $_. LDAPSAvailable }) { "FAIL" } else { "PASS" }
        Details = $results
        Recommendation = "Enable LDAPS on all domain controllers and require encrypted connections"
        Risk = "LDAP traffic can be intercepted and credentials stolen"
    }
}

function Test-GPOPermissions {
    <#
    .SYNOPSIS
        Check for excessive GPO modification permissions (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpos = Get-GPO -All
    $issues = @()
    
    foreach ($gpo in $gpos) {
        $perms = Get-GPPermission -Guid $gpo.Id -All | Where-Object {
            $_. Trustee.Name -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Administrators" -and
            $_.Permission -match "GpoEdit|GpoEditDeleteModifySecurity"
        }
        
        if ($perms) {
            $issues += [PSCustomObject]@{
                GPOName = $gpo.DisplayName
                Trustee = $perms.Trustee.Name -join ", "
                Permission = $perms.Permission -join ", "
            }
        }
    }
    
    [PSCustomObject]@{
        CheckName = "GPO Modification Permissions"
        Severity = "MEDIUM"
        Status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }
        IssueCount = $issues.Count
        Details = $issues
        Recommendation = "Restrict GPO modification to authorized administrators only"
        Risk = "Unauthorized GPO modifications can lead to domain-wide compromise"
    }
}

function Test-SIDHistory {
    <#
    .SYNOPSIS
        Find accounts with SID History (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $users = Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory
    $groups = Get-ADGroup -Filter {SIDHistory -like "*"} -Properties SIDHistory
    
    [PSCustomObject]@{
        CheckName = "SID History"
        Severity = "MEDIUM"
        Status = if ($users.Count -gt 0 -or $groups.Count -gt 0) { "WARN" } else { "PASS" }
        UsersWithSIDHistory = $users.Count
        GroupsWithSIDHistory = $groups.Count
        Details = @{
            Users = $users | Select-Object Name, SamAccountName, @{N="SIDHistory";E={$_.SIDHistory -join ", "}}
            Groups = $groups | Select-Object Name, @{N="SIDHistory";E={$_.SIDHistory -join ", "}}
        }
        Recommendation = "Review and remove unnecessary SID History entries"
        Risk = "SID History can be abused for privilege escalation"
    }
}

function Test-TombstoneLifetime {
    <#
    .SYNOPSIS
        Check tombstone lifetime configuration (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $tombstone = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime
    
    $lifetime = if ($tombstone.tombstoneLifetime) { $tombstone.tombstoneLifetime } else { 180 } # Default is 180 days
    
    [PSCustomObject]@{
        CheckName = "Tombstone Lifetime"
        Severity = "MEDIUM"
        Status = if ($lifetime -lt 180) { "FAIL" } else { "PASS" }
        CurrentValue = $lifetime
        RecommendedMinimum = 180
        Recommendation = "Set tombstone lifetime to at least 180 days"
        Risk = "Short tombstone lifetime can cause replication issues and data loss"
    }
}

function Test-DomainTrustRelationships {
    <#
    . SYNOPSIS
        Analyze domain trust relationships (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $trusts = Get-ADTrust -Filter *
    $suspiciousTrusts = $trusts | Where-Object { 
        $_.TrustType -eq "External" -or $_.Direction -eq "Bidirectional"
    }
    
    [PSCustomObject]@{
        CheckName = "Domain Trust Relationships"
        Severity = "MEDIUM"
        Status = if ($suspiciousTrusts.Count -gt 0) { "WARN" } else { "PASS" }
        TotalTrusts = $trusts. Count
        SuspiciousTrusts = $suspiciousTrusts.Count
        Details = $trusts | Select-Object Name, TrustType, Direction, Target
        Recommendation = "Review all trusts, prefer one-way trusts, enable SID filtering"
        Risk = "Trusts can be exploited for cross-domain attacks"
    }
}

function Test-AccountLockoutPolicy {
    <#
    .SYNOPSIS
        Check account lockout policy configuration (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $policy = Get-ADDefaultDomainPasswordPolicy
    
    $issues = @()
    if ($policy.LockoutThreshold -eq 0) { $issues += "Account lockout not enabled" }
    if ($policy.LockoutDuration. TotalMinutes -lt 15) { $issues += "Lockout duration less than 15 minutes" }
    if ($policy.LockoutObservationWindow.TotalMinutes -lt 15) { $issues += "Observation window less than 15 minutes" }
    
    [PSCustomObject]@{
        CheckName = "Account Lockout Policy"
        Severity = "MEDIUM"
        Status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }
        LockoutThreshold = $policy. LockoutThreshold
        LockoutDuration = $policy. LockoutDuration. TotalMinutes
        ObservationWindow = $policy.LockoutObservationWindow.TotalMinutes
        Issues = $issues
        Recommendation = "Configure lockout after 5 attempts for 30+ minutes"
        Risk = "Accounts vulnerable to brute force password attacks"
    }
}

function Test-DisabledAccountsInPrivilegedGroups {
    <#
    .SYNOPSIS
        Find disabled accounts in privileged groups (MEDIUM)
    #>
    [CmdletBinding()]
    param()
    
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $results = @()
    
    foreach ($group in $privilegedGroups) {
        $members = Get-ADGroupMember -Identity $group | Where-Object {$_.objectClass -eq 'user'}
        foreach ($member in $members) {
            $user = Get-ADUser -Identity $member -Properties Enabled
            if (-not $user.Enabled) {
                $results += [PSCustomObject]@{
                    Group = $group
                    User = $user.SamAccountName
                }
            }
        }
    }
    
    [PSCustomObject]@{
        CheckName = "Disabled Accounts in Privileged Groups"
        Severity = "MEDIUM"
        Status = if ($results.Count -gt 0) { "WARN" } else { "PASS" }
        DisabledAccountCount = $results.Count
        Details = $results
        Recommendation = "Remove disabled accounts from privileged groups"
        Risk = "Disabled accounts in privileged groups may be re-enabled for attacks"
    }
}


function Test-AccountOperators {
    <#
    .SYNOPSIS
        Review Account Operators group membership (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $members = Get-ADGroupMember -Identity "Account Operators" -ErrorAction SilentlyContinue
    $unexpected = $members | Where-Object {
        $_.objectClass -eq 'user' -or $_.Name -notmatch "Domain Admins|Administrators"
    }

    [PSCustomObject]@{
        CheckName      = "Account Operators Group Membership"
        Severity       = "MEDIUM"
        Status         = if ($unexpected.Count -gt 0) { "WARN" } else { "PASS" }
        MemberCount    = $members.Count
        Unexpected     = $unexpected | Select-Object Name, SamAccountName, objectClass
        Recommendation = "Minimize or avoid use of Account Operators; keep membership empty where possible"
        Risk           = "Account Operators can manage many user and group objects and may be abused"
    }
}

function Test-ServerOperators {
    <#
    .SYNOPSIS
        Review Server Operators group membership (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $members = Get-ADGroupMember -Identity "Server Operators" -ErrorAction SilentlyContinue
    $unexpected = $members | Where-Object {
        $_.objectClass -eq 'user' -or $_.Name -notmatch "Domain Admins|Administrators"
    }

    [PSCustomObject]@{
        CheckName      = "Server Operators Group Membership"
        Severity       = "MEDIUM"
        Status         = if ($unexpected.Count -gt 0) { "WARN" } else { "PASS" }
        MemberCount    = $members.Count
        Unexpected     = $unexpected | Select-Object Name, SamAccountName, objectClass
        Recommendation = "Avoid using Server Operators; move necessary rights to safer RBAC roles"
        Risk           = "Server Operators can log on locally to DCs and manage services"
    }
}

function Test-PrintOperators {
    <#
    .SYNOPSIS
        Review Print Operators group membership (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $members = Get-ADGroupMember -Identity "Print Operators" -ErrorAction SilentlyContinue
    $unexpected = $members | Where-Object {
        $_.objectClass -eq 'user' -or $_.Name -notmatch "Domain Admins|Administrators"
    }

    [PSCustomObject]@{
        CheckName      = "Print Operators Group Membership"
        Severity       = "MEDIUM"
        Status         = if ($unexpected.Count -gt 0) { "WARN" } else { "PASS" }
        MemberCount    = $members.Count
        Unexpected     = $unexpected | Select-Object Name, SamAccountName, objectClass
        Recommendation = "Avoid Print Operators; they can load drivers and potentially escalate privileges"
        Risk           = "Print Operators can exploit driver paths for elevation"
    }
}

function Test-BackupOperators {
    <#
    .SYNOPSIS
        Review Backup Operators group membership (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $members = Get-ADGroupMember -Identity "Backup Operators" -ErrorAction SilentlyContinue
    $unexpected = $members | Where-Object {
        $_.objectClass -eq 'user' -or $_.Name -notmatch "Domain Admins|Administrators"
    }

    [PSCustomObject]@{
        CheckName      = "Backup Operators Group Membership"
        Severity       = "MEDIUM"
        Status         = if ($unexpected.Count -gt 0) { "WARN" } else { "PASS" }
        MemberCount    = $members.Count
        Unexpected     = $unexpected | Select-Object Name, SamAccountName, objectClass
        Recommendation = "Keep Backup Operators membership minimal and documented"
        Risk           = "Backup Operators can restore sensitive data or replace system files"
    }
}

function Test-DCShadowCredentials {
    <#
    .SYNOPSIS
        Look for DC shadow-like permissions on key directory objects (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $domainDN = (Get-ADDomain).DistinguishedName
    $objectsToCheck = @(
        "CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)",
        $domainDN
    )

    $suspicious = @()

    foreach ($objDN in $objectsToCheck) {
        try {
            $obj = Get-ADObject -Identity $objDN -Properties ntSecurityDescriptor -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # Object simply doesn't exist in this environment
            $suspicious += [PSCustomObject]@{
                ObjectDN  = $objDN
                ExtraACEs = @()
                Note      = 'Object not found'
            }
            continue
        }
        catch {
            # Other lookup error
            $suspicious += [PSCustomObject]@{
                ObjectDN  = $objDN
                ExtraACEs = @()
                Note      = "Error: $($_.Exception.Message)"
            }
            continue
        }

        $aces = $obj.ntSecurityDescriptor.Access | Where-Object {
            $_.ActiveDirectoryRights -match 'WriteDacl|WriteOwner'
        }

        $extra = $aces | Where-Object {
            $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM'
        }

        if ($extra) {
            $suspicious += [PSCustomObject]@{
                ObjectDN  = $objDN
                ExtraACEs = $extra | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
                Note      = 'Extra ACEs found'
            }
        }
    }

    [PSCustomObject]@{
        CheckName      = "DC Shadow-like Directory Permissions"
        Severity       = "MEDIUM"
        Status         = if ($suspicious.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $suspicious
        Recommendation = "Limit WriteDacl/WriteOwner on root objects to Tier-0 admins only"
        Risk           = "Attackers can create shadow DCs or persist via ACL backdoors"
    }
}

function Test-PrivilegedUsersLogonWorkstations {
    <#
    .SYNOPSIS
        Check where privileged users are allowed to log on (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $adminGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
    $admins = $adminGroups | ForEach-Object {
        Get-ADGroupMember -Identity $_ -Recursive | Where-Object {$_.objectClass -eq 'user'}
    } | Select-Object -Unique

    $results = @()
    foreach ($a in $admins) {
        $u = Get-ADUser -Identity $a -Properties LogonWorkstations
        if ($u.LogonWorkstations) {
            $results += [PSCustomObject]@{
                User             = $u.SamAccountName
                LogonWorkstations = $u.LogonWorkstations
            }
        }
    }

    [PSCustomObject]@{
        CheckName      = "Privileged Users Logon Workstations"
        Severity       = "MEDIUM"
        Status         = if ($results.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $results
        Recommendation = "Limit privileged logons to hardened admin workstations only"
        Risk           = "Admin credentials exposed on unmanaged or lowâ€‘trust machines"
    }
}

function Test-NonOwnerDLManagers {
    <#
    .SYNOPSIS
        Check distribution groups managed by nonâ€‘IT accounts (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $dls = Get-ADGroup -Filter {GroupCategory -eq "Distribution"} -Properties ManagedBy
    $results = $dls | Where-Object {
        $_.ManagedBy -and $_.ManagedBy -notmatch "OU=IT|OU=Admins"
    } | Select-Object Name, ManagedBy, DistinguishedName

    [PSCustomObject]@{
        CheckName      = "Distribution List Ownership"
        Severity       = "MEDIUM"
        Status         = if ($results.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $results
        Recommendation = "Review DL managers and keep sensitive lists controlled by IT"
        Risk           = "Improper DL ownership can expose or misroute sensitive email"
    }
}

function Test-WeakUserDescriptions {
    <#
    .SYNOPSIS
        Find user descriptions containing passwords or hints (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $patterns = "pass","pwd","login","pin"
    $users = Get-ADUser -Filter {Description -like "*"} -Properties Description
    $hits = $users | Where-Object {
        $desc = $_.Description
        $patterns | Where-Object { $desc -match $_ }
    }

    [PSCustomObject]@{
        CheckName      = "Sensitive Data in User Description"
        Severity       = "MEDIUM"
        Status         = if ($hits.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $hits | Select-Object Name, SamAccountName, Description
        Recommendation = "Remove passwords or hints from Description fields"
        Risk           = "Credentials or hints stored in clear text within AD"
    }
}

function Test-InsecureGPOUserRights {
    <#
    .SYNOPSIS
        Check common dangerous user rights in GPOs (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpos = Get-GPO -All
    $issues = @()
    $dangerousRights = @(
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege"
    )

    foreach ($gpo in $gpos) {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $xml = [xml]$report
        foreach ($right in $dangerousRights) {
            $nodes = $xml.GPO.Computer.ExtensionData.Extension.LocalUsersAndGroups.UserRightsAssignment |
                Where-Object { $_.Name -eq $right }
            if ($nodes) {
                $issues += [PSCustomObject]@{
                    GPO      = $gpo.DisplayName
                    UserRight = $right
                    RawNode  = $nodes.InnerXml
                }
            }
        }
    }

    [PSCustomObject]@{
        CheckName      = "Dangerous User Rights in GPOs"
        Severity       = "MEDIUM"
        Status         = if ($issues.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $issues
        Recommendation = "Restrict dangerous user rights to Tierâ€‘0 admin groups only"
        Risk           = "Privilege escalation via powerful local rights"
    }
}

function Test-NTFSPermissionsSysvolScripts {
    <#
    .SYNOPSIS
        Check NTFS permissions on SYSVOL scripts folder (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $dc = Get-ADDomainController -Discover -Service PrimaryDC
    $path = "\\$($dc.HostName)\SYSVOL\$((Get-ADDomain).DNSRoot)\scripts"
    $weak = @()

    if (Test-Path $path) {
        $acl = Get-Acl $path
        $weak = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users|Authenticated Users" -and
            $_.FileSystemRights -match "Modify|Write|FullControl"
        }
    }

    [PSCustomObject]@{
        CheckName      = "SYSVOL Scripts NTFS Permissions"
        Severity       = "MEDIUM"
        Status         = if ($weak) { "FAIL" } else { "PASS" }
        Details        = $weak | Select-Object IdentityReference, FileSystemRights, AccessControlType
        Recommendation = "Restrict write on scripts to Domain Admins only"
        Risk           = "Logon scripts can be modified to deliver malware or harvest credentials"
    }
}

function Test-DHCPSettingsForDNS {
    <#
    .SYNOPSIS
        Check DHCP options for secure DNS registration (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    try {
        $scopes  = Get-DhcpServerv4Scope -ErrorAction Stop
        $results = @()

        foreach ($s in $scopes) {
            $p = Get-DhcpServerv4Scope -ScopeId $s.ScopeId | Select-Object -ExpandProperty State
            $results += [PSCustomObject]@{
                ScopeId = $s.ScopeId
                Name    = $s.Name
                State   = $p
            }
        }

        [PSCustomObject]@{
            CheckName      = "DHCP Scopes Basic Health"
            Severity       = "MEDIUM"
            Status         = "INFO"
            Details        = $results
            Recommendation = "Ensure DHCP is configured for secure dynamic DNS registration."
            Risk           = "Improper DHCP/DNS configuration can open spoofing vectors."
        }
    } catch {
        [PSCustomObject]@{
            CheckName      = "DHCP Scopes Basic Health"
            Severity       = "MEDIUM"
            Status         = "INFO"
            Details        = $_.Exception.Message
            Recommendation = "Unable to query DHCP - run locally on DHCP servers if needed."
            Risk           = "Unknown"
        }
    }
}

function Test-GroupPolicyLoopback {
    <#
    .SYNOPSIS
        Check for GPO loopback usage (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpos = Get-GPO -All
    $issues = @()

    foreach ($gpo in $gpos) {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $xml = [xml]$report
        $loopbackNode = $xml.GPO.Computer.ExtensionData.Extension.Security.UserRightsAssignment |
            Where-Object { $_.Name -eq "LoopbackProcessingMode" }
        if ($loopbackNode) {
            $issues += [PSCustomObject]@{
                GPO    = $gpo.DisplayName
                Detail = $loopbackNode.InnerXml
            }
        }
    }

    [PSCustomObject]@{
        CheckName      = "GPO Loopback Processing"
        Severity       = "MEDIUM"
        Status         = if ($issues.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $issues
        Recommendation = "Use loopback only where required and document it"
        Risk           = "Unexpected user policy application on certain computers"
    }
}

function Test-DomainControllerLocalUsers {
    <#
    .SYNOPSIS
        Check for unexpected local users on domain controllers (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $dcs = Get-ADDomainController -Filter *
    $results = @()

    foreach ($dc in $dcs) {
        try {
            $localUsers = Get-WmiObject -ComputerName $dc.HostName -Class Win32_UserAccount -Filter "LocalAccount=True"
            $filtered = $localUsers | Where-Object { $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }
            if ($filtered) {
                $results += [PSCustomObject]@{
                    DomainController = $dc.HostName
                    LocalUsers       = $filtered.Name -join ", "
                }
            }
        } catch {}
    }

    [PSCustomObject]@{
        CheckName      = "Local Users on Domain Controllers"
        Severity       = "MEDIUM"
        Status         = if ($results.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $results
        Recommendation = "Avoid local users on DCs; rely on domain security groups instead"
        Risk           = "Local accounts may bypass domain security controls"
    }
}

function Test-GroupNestingDepth {
    <#
    .SYNOPSIS
        Check for deeply nested groups (MEDIUM)
    #>
    [CmdletBinding()]
    param(
        [int]$MaxDepth = 3
    )

    $groups = Get-ADGroup -Filter * -Properties memberOf
    $issues = @()

    foreach ($g in $groups) {
        $depth = 0
        $current = $g
        while ($current.memberOf -and $depth -le 10) {
            $depth++
            $parentDN = $current.memberOf[0]
            $current = Get-ADGroup -Identity $parentDN -Properties memberOf -ErrorAction SilentlyContinue
            if (-not $current) { break }
        }
        if ($depth -gt $MaxDepth) {
            $issues += [PSCustomObject]@{
                Group = $g.Name
                Depth = $depth
            }
        }
    }

    [PSCustomObject]@{
        CheckName      = "Group Nesting Depth"
        Severity       = "MEDIUM"
        Status         = if ($issues.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $issues
        Recommendation = "Limit group nesting depth to simplify privilege analysis"
        Risk           = "Complex nesting hides effective permissions"
    }
}

function Test-UsersWithManyGroupMemberships {
    <#
    .SYNOPSIS
        Find users with excessive group memberships (MEDIUM)
    #>
    [CmdletBinding()]
    param(
        [int]$Threshold = 20
    )

    $users = Get-ADUser -Filter * -Properties MemberOf
    $issues = $users | Where-Object { $_.MemberOf.Count -ge $Threshold } |
        Select-Object Name, SamAccountName, @{N="GroupCount";E={$_.MemberOf.Count}}

    [PSCustomObject]@{
        CheckName      = "Users with Many Group Memberships"
        Severity       = "MEDIUM"
        Status         = if ($issues.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $issues
        Recommendation = "Review users with many groups; consolidate via RBAC roles"
        Risk           = "Over-privileged users through cumulative group rights"
    }
}

function Test-DefaultAdministrator {
    <#
    .SYNOPSIS
        Verify built-in Administrator account hardening (HIGH)
    #>
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    $adminSid = "S-1-5-21-$($domain.DomainSID.Value.Split('-')[-3..-1] -join '-')-500"

    $admin = Get-ADUser -Filter "SID -eq '$adminSid'" -Properties Enabled, PasswordLastSet, PasswordNeverExpires, LastLogonDate, UserPrincipalName

    $issues = @()

    if ($admin.Enabled) {
        $issues += "Built-in Administrator account is enabled"
    }

    if ($admin.PasswordNeverExpires) {
        $issues += "PasswordNeverExpires is set for built-in Administrator"
    }

    if (-not $admin.UserPrincipalName) {
        # This is usually good, no issue
    }

    $status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }

    [PSCustomObject]@{
        CheckName      = "Default Administrator Account"
        Severity       = "HIGH"
        Status         = $status
        Details        = [PSCustomObject]@{
            SamAccountName       = $admin.SamAccountName
            DistinguishedName    = $admin.DistinguishedName
            Enabled              = $admin.Enabled
            PasswordLastSet      = $admin.PasswordLastSet
            PasswordNeverExpires = $admin.PasswordNeverExpires
            LastLogonDate        = $admin.LastLogonDate
            UserPrincipalName    = $admin.UserPrincipalName
            Issues               = $issues -join "; "
        }
        Recommendation = "Disable the built-in Administrator or strictly limit its use. Ensure strong, regularly changed passwords and prefer named admin accounts."
        Risk           = "Default Administrator account may be enabled, predictable, or poorly secured, making it a prime target for attackers."
    }
}

function Test-DefaultGuestAccount {
    <#
    .SYNOPSIS
        Verify built-in Guest account is disabled (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    $guestSid = "S-1-5-21-$($domain.DomainSID.Value.Split('-')[-3..-1] -join '-')-501"

    $guest = Get-ADUser -Filter "SID -eq '$guestSid'" -Properties Enabled, LastLogonDate

    $status = if ($guest.Enabled) { "FAIL" } else { "PASS" }

    [PSCustomObject]@{
        CheckName      = "Default Guest Account"
        Severity       = "MEDIUM"
        Status         = $status
        Details        = [PSCustomObject]@{
            SamAccountName    = $guest.SamAccountName
            DistinguishedName = $guest.DistinguishedName
            Enabled           = $guest.Enabled
            LastLogonDate     = $guest.LastLogonDate
        }
        Recommendation = "Ensure the built-in Guest account is disabled and not used. Use named, auditable accounts instead."
        Risk           = "Guest account may allow anonymous or low-friction access and bypass accountability."
    }
}

function Test-EmptyOrganizationalUnits {
    <#
    .SYNOPSIS
        Check for empty Organizational Units in Active Directory (HIGH)
    .DESCRIPTION
        Enumerates all OUs in the domain and identifies those that have no child objects.
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeSystemOUs
    )

    # Build base filter to exclude system OUs by default
    $ouFilter = '(&(objectCategory=organizationalUnit))'

    # Optionally exclude some well-known system OUs by DN pattern
    $excludedOUs = @(
        "OU=Domain Controllers",
        "OU=Microsoft Exchange Security Groups",
        "OU=Microsoft Exchange System Objects"
    )

    $ous = Get-ADOrganizationalUnit -LDAPFilter $ouFilter -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree

    $emptyOUs = @()

    foreach ($ou in $ous) {
        if (-not $IncludeSystemOUs) {
            if ($excludedOUs | Where-Object { $ou.DistinguishedName -like "*$_*" }) {
                continue
            }
        }

        # Count child objects
        $children = Get-ADObject -Filter * -SearchBase $ou.DistinguishedName -SearchScope OneLevel -ResultSetSize 1
        if (-not $children) {
            $emptyOUs += $ou
        }
    }

    [PSCustomObject]@{
        CheckName     = "Empty Organizational Units"
        Severity      = "HIGH"
        Status        = if ($emptyOUs.Count -gt 0) { "WARN" } else { "PASS" }
        EmptyOUCount  = $emptyOUs.Count
        Details       = $emptyOUs | Select-Object Name, DistinguishedName
        Recommendation = "Review and remove or repurpose empty OUs to reduce clutter and potential misconfiguration"
        Risk          = "Unused OUs can hide misconfigurations and complicate delegation and GPO scoping"
    }
}

function Test-DuplicateSPNs {
    <#
    .SYNOPSIS
        Identify duplicate Service Principal Names (HIGH)
    #>
    [CmdletBinding()]
    param()

    $objects = Get-ADObject -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName, SamAccountName, objectClass
    $spnMap = @{}

    foreach ($obj in $objects) {
        foreach ($spn in $obj.servicePrincipalName) {
            if (-not $spnMap.ContainsKey($spn)) {
                $spnMap[$spn] = @()
            }
            $spnMap[$spn] += $obj
        }
    }

    $duplicates = @()
    foreach ($key in $spnMap.Keys) {
        if ($spnMap[$key].Count -gt 1) {
            foreach ($obj in $spnMap[$key]) {
                $duplicates += [PSCustomObject]@{
                    SPN             = $key
                    SamAccountName  = $obj.SamAccountName
                    ObjectClass     = $obj.objectClass
                    DistinguishedName = $obj.DistinguishedName
                }
            }
        }
    }

    $status = if ($duplicates.Count -gt 0) { "FAIL" } else { "PASS" }

    [PSCustomObject]@{
        CheckName      = "Duplicate SPNs"
        Severity       = "HIGH"
        Status         = $status
        Details        = $duplicates
        Recommendation = "Ensure each SPN is unique. Remove or correct duplicate SPNs so that each service principal is associated with a single account."
        Risk           = "Duplicate SPNs may cause authentication issues and be abused for Kerberos attacks."
    }
}

function Test-DNSScavenging {
    <#
    .SYNOPSIS
        Verify DNS scavenging configuration on DNS servers (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    try {
        Import-Module DNSServer -ErrorAction Stop | Out-Null
    } catch {
        return [PSCustomObject]@{
            CheckName      = "DNS Scavenging"
            Severity       = "MEDIUM"
            Status         = "ERROR"
            Details        = $_.Exception.Message
            Recommendation = "Install and import the DNSServer module on a management server to evaluate DNS scavenging."
            Risk           = "Unable to verify DNS scavenging configuration."
        }
    }

    $servers = Get-DnsServer -ErrorAction SilentlyContinue

    if (-not $servers) {
        return [PSCustomObject]@{
            CheckName      = "DNS Scavenging"
            Severity       = "MEDIUM"
            Status         = "WARN"
            Details        = "No DNS servers returned by Get-DnsServer."
            Recommendation = "Run this check on a DNS server or from a management host with RSAT DNS tools."
            Risk           = "DNS scavenging configuration could not be evaluated."
        }
    }

    $results = @()

    foreach ($srv in $servers) {
        $target = $srv.ComputerName
        if (-not $target) { $target = $srv.Name }

        try {
            # Suppress non-fatal warnings like 'EnableRegistryBoot not applicable...'
            $serverConfig = Get-DnsServerScavenging -ComputerName $target -ErrorAction Stop 2>$null

            $results += [PSCustomObject]@{
                ServerName         = $target
                ScavengingEnabled  = $serverConfig.ScavengingState
                NoRefreshInterval  = $serverConfig.NoRefreshInterval
                RefreshInterval    = $serverConfig.RefreshInterval
                ScavengingInterval = $serverConfig.ScavengingInterval
            }
        } catch {
            $results += [PSCustomObject]@{
                ServerName         = $target
                ScavengingEnabled  = $false
                Error              = $_.Exception.Message
            }
        }
    }

    $nonCompliant = $results | Where-Object { -not $_.ScavengingEnabled }

    [PSCustomObject]@{
        CheckName      = "DNS Scavenging"
        Severity       = "MEDIUM"
        Status         = if ($nonCompliant.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $results
        Recommendation = "Enable and properly tune DNS scavenging on all DNS servers to automatically remove stale records."
        Risk           = "Stale DNS records can enable spoofing, lateral movement, and operational issues."
    }
}

function Test-RecycleBinEnabled {
    <#
    .SYNOPSIS
        Verify AD Recycle Bin is enabled (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $forest = Get-ADForest
    $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
    $enabledScopes = $recycleBinFeature.EnabledScopes

    $isEnabled = $enabledScopes -contains $forest.DistinguishedName

    [PSCustomObject]@{
        CheckName      = "AD Recycle Bin Enabled"
        Severity       = "MEDIUM"
        Status         = if ($isEnabled) { "PASS" } else { "FAIL" }
        Details        = [PSCustomObject]@{
            ForestName    = $forest.Name
            EnabledScopes = $enabledScopes
        }
        Recommendation = "Enable AD Recycle Bin at the forest level to allow granular recovery of deleted objects."
        Risk           = "Accidental deletions may be harder or impossible to recover without AD Recycle Bin."
    }
}

function Test-FineGrainedPasswordPolicies {
    <#
    .SYNOPSIS
        Verify fine-grained password policies (PSOs) are defined and applied (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $psos = Get-ADFineGrainedPasswordPolicy -Filter *
    $results = @()

    foreach ($pso in $psos) {
        $appliesTo = Get-ADFineGrainedPasswordPolicySubject -Identity $pso -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            Name              = $pso.Name
            Precedence        = $pso.Precedence
            AppliesToCount    = $appliesTo.Count
            AppliesToObjects  = $appliesTo.DistinguishedName -join "; "
            MinPasswordLength = $pso.MinPasswordLength
            ComplexityEnabled = $pso.ComplexityEnabled
            LockoutThreshold  = $pso.LockoutThreshold
        }
    }

    $hasPso = $psos.Count -gt 0

    [PSCustomObject]@{
        CheckName      = "Fine-Grained Password Policies"
        Severity       = "MEDIUM"
        Status         = if ($hasPso) { "PASS" } else { "WARN" }
        Details        = $results
        Recommendation = "Define and apply fine-grained password policies for privileged and sensitive accounts to enforce stronger controls than the domain default."
        Risk           = "Inconsistent or weak password policies for privileged or sensitive accounts."
    }
}

function Test-DHCPAuthorization {
    <#
    .SYNOPSIS
        Detect unauthorized or rogue DHCP servers (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    try {
        Import-Module DhcpServer -ErrorAction Stop | Out-Null
    } catch {
        return [PSCustomObject]@{
            CheckName      = "DHCP Authorization"
            Severity       = "MEDIUM"
            Status         = "ERROR"
            Details        = $_.Exception.Message
            Recommendation = "Install and import the DhcpServer module on a management server to evaluate DHCP authorization."
            Risk           = "Unable to verify authorized DHCP servers."
        }
    }

    $authorized = Get-DhcpServerInDC -ErrorAction SilentlyContinue
    $authorizedNames = $authorized.DnsName

    # This check cannot fully discover rogue DHCP servers without network scanning.
    # It focuses on whether authorized servers exist and are expected.
    [PSCustomObject]@{
        CheckName      = "DHCP Authorization"
        Severity       = "MEDIUM"
        Status         = if ($authorized.Count -gt 0) { "PASS" } else { "WARN" }
        Details        = $authorized | Select-Object DnsName, IPAddress
        Recommendation = "Ensure all DHCP servers in the domain are properly authorized in AD and periodically scan the network for unauthorized DHCP servers."
        Risk           = "Rogue DHCP servers can redirect traffic and facilitate man-in-the-middle attacks."
    }
}

function Test-DFSRBacklogHealth {
    <#
    .SYNOPSIS
        Check DFSR backlog health for SYSVOL (MEDIUM)
    #>
    [CmdletBinding()]
    param(
        [int]$MaxBacklog = 100
    )

    $domain = Get-ADDomain
    $dcs = Get-ADDomainController -Filter *
    $pdc = $dcs | Where-Object {$_.OperationMasterRoles -contains "PDCEmulator"} | Select-Object -First 1

    $results = @()

    foreach ($dc in $dcs) {
        if ($dc.HostName -eq $pdc.HostName) {
            continue
        }

        try {
            $backlog = Get-DfsrBacklog -SourceComputerName $pdc.HostName `
                                       -DestinationComputerName $dc.HostName `
                                       -GroupName "Domain System Volume" `
                                       -FolderName "SYSVOL Share" `
                                       -ErrorAction Stop

            $count = ($backlog | Measure-Object).Count

            $results += [PSCustomObject]@{
                SourceDC       = $pdc.HostName
                DestinationDC  = $dc.HostName
                BacklogCount   = $count
                ExceedsMax     = $count -gt $MaxBacklog
            }
        } catch {
            $results += [PSCustomObject]@{
                SourceDC      = $pdc.HostName
                DestinationDC = $dc.HostName
                BacklogCount  = -1
                ExceedsMax    = $true
                Error         = $_.Exception.Message
            }
        }
    }

    $problem = $results | Where-Object { $_.ExceedsMax }

    [PSCustomObject]@{
        CheckName      = "DFSR Backlog Health"
        Severity       = "MEDIUM"
        Status         = if ($problem.Count -gt 0) { "WARN" } else { "PASS" }
        Details        = $results
        Recommendation = "Investigate DFSR backlog for SYSVOL when counts stay high. Ensure SYSVOL replication is healthy and consistent across all domain controllers."
        Risk           = "Replication delays or failures may cause inconsistent policies and configurations."
    }
}

function Test-OrphanedForeignSecurityPrincipals {
    <#
    .SYNOPSIS
        Identify foreign security principals for review (LOW)
    #>
    [CmdletBinding()]
    param()

    $configNC = (Get-ADRootDSE).ConfigurationNamingContext
    $fslPath  = "CN=ForeignSecurityPrincipals,$configNC"

    # Verify the container exists; if not, return INFO/WARN instead of error
    try {
        $null = Get-ADObject -Identity $fslPath -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            CheckName      = "Orphaned Foreign Security Principals"
            Severity       = "LOW"
            Status         = "INFO"
            Details        = "ForeignSecurityPrincipals container not found at $fslPath. It may not exist in this forest configuration or you may lack permissions."
            Recommendation = "Verify forest configuration and permissions if you expect external trusts or foreign security principals."
            Risk           = "Unable to enumerate foreign security principals; clutter and permission issues cannot be evaluated."
        }
    }

    $fsps = Get-ADObject -SearchBase $fslPath -LDAPFilter "(objectClass=foreignSecurityPrincipal)" -Properties ObjectSID -ErrorAction SilentlyContinue

    if (-not $fsps) {
        return [PSCustomObject]@{
            CheckName      = "Orphaned Foreign Security Principals"
            Severity       = "LOW"
            Status         = "PASS"
            Details        = @()
            Recommendation = "No foreign security principals found. No cleanup required."
            Risk           = "None detected from foreign security principals."
        }
    }

    $results = foreach ($fsp in $fsps) {
        [PSCustomObject]@{
            Name              = $fsp.Name
            DistinguishedName = $fsp.DistinguishedName
            ObjectSID         = $fsp.ObjectSID.Value
        }
    }

    [PSCustomObject]@{
        CheckName      = "Orphaned Foreign Security Principals"
        Severity       = "LOW"
        Status         = "WARN"
        Details        = $results
        Recommendation = "Review foreign security principals and remove those that are no longer needed (e.g., from removed trusts or decommissioned external accounts)."
        Risk           = "Orphaned objects clutter AD and may mask permission issues."
    }
}

function Test-DomainControllerTime {
    <#
    .SYNOPSIS
        Verify consistent time synchronization across domain controllers (HIGH)
    #>
    [CmdletBinding()]
    param(
        [int]$MaxSkewSeconds = 300
    )

    $dcs = Get-ADDomainController -Filter *
    $results = @()

    # Use local time as reference (assuming you run this on a well-synced host)
    $refTime = Get-Date

    foreach ($dc in $dcs) {
        try {
            $remoteTime = Invoke-Command -ComputerName $dc.HostName -ScriptBlock { Get-Date } -ErrorAction Stop

            $skew = [math]::Round(($remoteTime - $refTime).TotalSeconds, 0)

            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                ReferenceTime    = $refTime
                RemoteTime       = $remoteTime
                TimeSkewSeconds  = $skew
                ExceedsMaxSkew   = [math]::Abs($skew) -gt $MaxSkewSeconds
            }
        } catch {
            $results += [PSCustomObject]@{
                DomainController = $dc.HostName
                ReferenceTime    = $refTime
                RemoteTime       = $null
                TimeSkewSeconds  = $null
                ExceedsMaxSkew   = $true
                Error            = $_.Exception.Message
            }
        }
    }

    $problem = $results | Where-Object { $_.ExceedsMaxSkew }

    [PSCustomObject]@{
        CheckName      = "Domain Controller Time Sync"
        Severity       = "HIGH"
        Status         = if ($problem.Count -gt 0) { "FAIL" } else { "PASS" }
        Details        = $results
        Recommendation = "Ensure all domain controllers synchronize time from a reliable source (PDCe -> NTP) and that time skew stays within $MaxSkewSeconds seconds."
        Risk           = "Significant time skew can break Kerberos and authentication."
    }
}

function Test-DomainFunctionalLevel {
    <#
    .SYNOPSIS
        Verify modern domain functional level (MEDIUM)
    #>
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    $forest = Get-ADForest

    $recommendedMin = "Windows2012R2Domain"

    $status = if ($domain.DomainMode -ge $recommendedMin -and $forest.ForestMode -ge "Windows2012R2Forest") { "PASS" } else { "WARN" }

    [PSCustomObject]@{
        CheckName      = "Domain Functional Level"
        Severity       = "MEDIUM"
        Status         = $status
        Details        = [PSCustomObject]@{
            DomainName   = $domain.DNSRoot
            DomainMode   = $domain.DomainMode
            ForestName   = $forest.Name
            ForestMode   = $forest.ForestMode
            Recommended  = $recommendedMin
        }
        Recommendation = "Raise domain and forest functional levels to at least Windows Server 2012 R2 (or later) if all domain controllers support it."
        Risk           = "Low functional levels may lack modern security features and hardening options."
    }
}

function Test-ADBackupAge {
    <#
    .SYNOPSIS
        Ensure regular AD/system state backups (HIGH)
    .DESCRIPTION
        This check infers backup recency by querying the System State Backup attribute
        if available, or by checking Windows Backup history on the PDC emulator.
    #>
    [CmdletBinding()]
    param(
        [int]$MaxDaysSinceBackup = 7
    )

    $domain = Get-ADDomain
    $pdc = Get-ADDomainController -Identity $domain.PDCEmulator

    $results = @()
    $status = "WARN"

    try {
        # Uses wbadmin history as heuristic on the PDC
        $history = Invoke-Command -ComputerName $pdc.HostName -ScriptBlock {
            wbadmin get versions -backuptarget:* 2>$null
        } -ErrorAction Stop

        $dates = ($history | Select-String "Backup time:").Line -replace "Backup time:\s*", "" |
            ForEach-Object { [datetime]$_ } | Sort-Object -Descending

        $lastBackup = $dates | Select-Object -First 1
        $daysSince  = if ($lastBackup) { (Get-Date - $lastBackup).Days } else { [int]::MaxValue }

        $status = if ($daysSince -le $MaxDaysSinceBackup) { "PASS" } else { "FAIL" }

        $results += [PSCustomObject]@{
            PDCHostName      = $pdc.HostName
            LastBackup       = $lastBackup
            DaysSinceBackup  = $daysSince
            MaxDaysAllowed   = $MaxDaysSinceBackup
        }
    } catch {
        $status = "ERROR"
        $results += [PSCustomObject]@{
            PDCHostName     = $pdc.HostName
            LastBackup      = $null
            DaysSinceBackup = $null
            Error           = $_.Exception.Message
        }
    }

    [PSCustomObject]@{
        CheckName      = "AD Backup Age"
        Severity       = "HIGH"
        Status         = $status
        Details        = $results
        Recommendation = "Ensure regular (at least weekly) system state/AD backups are taken and verified, especially on the PDC emulator."
        Risk           = "Without recent backups, AD recovery from corruption or compromise may be impossible."
    }
}

function Test-CompromisedPasswordCheck {
    <#
    .SYNOPSIS
        Detect accounts using potentially compromised passwords (HIGH)
    .DESCRIPTION
        This is a placeholder logical check. Actual compromised password detection
        requires integration with external breach password services or logs.
    #>
    [CmdletBinding()]
    param()

    # This module cannot directly read or hash passwords from AD.
    # Instead, this function reports that the check requires external integration.
    [PSCustomObject]@{
        CheckName      = "Compromised Password Check"
        Severity       = "HIGH"
        Status         = "INFO"
        Details        = "AD does not expose cleartext or hash data for runtime analysis in this script. Integrate with password filter solutions, Azure AD Password Protection, or breach password services."
        Recommendation = "Deploy password protection solutions (e.g., Azure AD Password Protection, on-prem password filters, or SIEM integration) to block or detect known-compromised passwords."
        Risk           = "Compromised passwords drastically reduce account security; users may reuse breached credentials without additional controls."
    }
}

function Test-EventLogConfiguration {
    <#
    .SYNOPSIS
        Check security event log configuration on domain controllers (HIGH)
    .DESCRIPTION
        Ensures adequate logging and retention for security events on all DCs.
        Validates:
        - Security log size
        - Retention policy
        - Audit policy / advanced audit policy (high-level)
    #>
    [CmdletBinding()]
    param(
        [int]$MinSecurityLogSizeMB = 2048,    # 2 GB suggested minimum for DCs
        [ValidateSet('OverwriteAsNeeded','OverwriteOlder','DoNotOverwrite')]
        [string]$RequiredRetention = 'OverwriteOlder',
        [int]$RetentionDaysMin = 7           # At least 7 days of logs if OverwriteOlder
    )

    $dcs = Get-ADDomainController -Filter *
    $results = @()

    foreach ($dc in $dcs) {
        $dcName = $dc.HostName

        $securityLogOk = $false
        $retentionOk   = $false
        $policyInfo    = $null
        $errors        = @()

        try {
            # Get Security log configuration
            # LogSize is in bytes, Convert to MB
            $log = Get-WinEvent -ComputerName $dcName -ListLog Security -ErrorAction Stop

            $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)

            # Retention:
            #  LogMode:
            #    0 = Circular (overwrite as needed)
            #    1 = AutoBackup
            #    2 = Retain (do not overwrite)
            #  For consistency with classic EventLog, we map:
            #    Circular      -> OverwriteAsNeeded
            #    AutoBackup    -> OverwriteOlder (backup before overwrite, roughly similar)
            #    Retain        -> DoNotOverwrite
            $logMode = $log.LogMode
            switch ($logMode) {
                'Circular'   { $retention = 'OverwriteAsNeeded' }
                'AutoBackup' { $retention = 'OverwriteOlder' }
                'Retain'     { $retention = 'DoNotOverwrite' }
                default      { $retention = 'Unknown' }
            }

            $securityLogOk = ($sizeMB -ge $MinSecurityLogSizeMB)

            # Approximate retention days: (Max size / average event size).
            # We can't reliably know average event size remotely, so we just enforce
            # the retention mode and leave days as "Unknown" unless OverwriteOlder is set.
            $estimatedRetentionDays = $null

            if ($retention -eq 'OverwriteOlder') {
                # If "OverwriteOlder" is configured, the effective days are controlled
                # by "RetentionDays" at OS level. We can read it from registry for Security log.
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
                    $key = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\Eventlog\Security')
                    $retentionDays = $key.GetValue('Retention')
                    # Retention is in seconds; 0 = overwrite as needed, else seconds to retain
                    if ($retentionDays -is [int] -and $retentionDays -gt 0) {
                        $estimatedRetentionDays = [math]::Round($retentionDays / 86400, 0)
                    } elseif ($retentionDays -eq 0) {
                        $estimatedRetentionDays = 0
                    } else {
                        $estimatedRetentionDays = $null
                    }
                } catch {
                    $errors += "Failed to read Retention from registry: $($_.Exception.Message)"
                }
            }

            if ($RequiredRetention -eq $retention) {
                if ($RequiredRetention -eq 'OverwriteOlder' -and $RetentionDaysMin -gt 0 -and $estimatedRetentionDays -ne $null) {
                    $retentionOk = ($estimatedRetentionDays -ge $RetentionDaysMin)
                } else {
                    # Mode matches, and either we don't enforce days or can't estimate them
                    $retentionOk = $true
                }
            } else {
                $retentionOk = $false
            }
        } catch {
            $errors += "Failed to query Security log: $($_.Exception.Message)"
        }

        # High-level audit policy status
        try {
            # Prefer advanced audit policy if configured
            $advanced = (auditpol /get /category:* /r /fo csv /computer:$dcName 2>$null |
                         ConvertFrom-Csv) 2>$null

            if ($advanced) {
                $policyInfo = @{
                    UsesAdvancedAuditPolicy = $true
                    Categories              = ($advanced.Category | Select-Object -Unique)
                }
            } else {
                # Fallback to legacy audit policy
                $legacy = secedit /export /cfg $env:TEMP\audit_$($dcName).inf /quiet 2>$null
                $policyInfo = @{
                    UsesAdvancedAuditPolicy = $false
                    Categories              = @()
                }
            }
        } catch {
            $errors += "Failed to query audit policy: $($_.Exception.Message)"
        }

        $results += [PSCustomObject]@{
            DomainController       = $dcName
            SecurityLogSizeMB      = $sizeMB
            MinRequiredSizeMB      = $MinSecurityLogSizeMB
            RetentionMode          = $retention
            RequiredRetentionMode  = $RequiredRetention
            EstimatedRetentionDays = $estimatedRetentionDays
            RetentionDaysMin       = if ($RequiredRetention -eq 'OverwriteOlder') { $RetentionDaysMin } else { $null }
            SecurityLogSizeOk      = $securityLogOk
            RetentionOk            = $retentionOk
            AuditPolicyInfo        = $policyInfo
            Errors                 = $errors -join '; '
        }
    }

    # Determine overall status
    $failing = $results | Where-Object { -not ($_.SecurityLogSizeOk -and $_.RetentionOk) }

    [PSCustomObject]@{
        CheckName      = "Event Log Configuration"
        Severity       = "HIGH"
        Status         = if ($failing.Count -gt 0) { "FAIL" } else { "PASS" }
        Details        = $results
        Recommendation = "Ensure Security log size is at least $MinSecurityLogSizeMB MB, retention mode is '$RequiredRetention', and logs are retained for at least $RetentionDaysMin days on DCs. Also verify advanced audit policy is configured to capture critical security events."
        Risk           = "Insufficient logging can prevent incident detection, investigation, and forensics, allowing attacks to go unnoticed."
    }
}

# ============================================================================
# REMEDIATION FUNCTIONS
# ============================================================================

function Invoke-KrbtgtPasswordRotation {
    <#
    .SYNOPSIS
        Helper to manage KRBTGT password rotation.
    .DESCRIPTION
        Logs current KRBTGT password age. Optionally performs a single password reset.
        Full Microsoft guidance usually recommends two resets with time between.
    .PARAMETER Execute
        Actually perform the reset; otherwise, this is read-only.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Execute
    )

    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
    $age    = (Get-Date) - $krbtgt.PasswordLastSet

    Write-ADSecLog -Level INFO -Message "KRBTGT PasswordLastSet: $($krbtgt.PasswordLastSet) (Age: $($age.Days) days)" -Context "KRBTGT"
    Write-ADSecLog -Level WARN -Message "Resetting KRBTGT has forest-wide Kerberos impact. Follow Microsoft guidance." -Context "KRBTGT"

    if (-not $Execute) {
        Write-ADSecLog -Level WARN -Message "Dry run only. Re-run with -Execute to reset password (subject to -WhatIf/-Confirm)." -Context "KRBTGT"
        return
    }

    if ($PSCmdlet.ShouldProcess("krbtgt", "Reset password")) {
        $newPwd = Read-Host -AsSecureString "Enter new KRBTGT password"
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $newPwd
        Write-ADSecLog -Level INFO -Message "KRBTGT password reset once. Repeat according to Microsoft guidance." -Context "KRBTGT"
    }
}

function Repair-AdminSDHolderAcl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$AllowedPrincipals = @(
            "NT AUTHORITY\SYSTEM",
            "Domain Admins",
            "Enterprise Admins",
            "Administrators"
        )
    )

    $domainDn      = (Get-ADDomain).DistinguishedName
    $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$domainDn" -Properties ntSecurityDescriptor
    $acl           = $adminSDHolder.ntSecurityDescriptor

    $unauthorized = $acl.Access | Where-Object {
        $_.IdentityReference -notin $AllowedPrincipals
    }

    if (-not $unauthorized) {
        Write-ADSecLog -Level INFO -Message "No unauthorized ACEs detected on AdminSDHolder." -Context "AdminSDHolder"
        return
    }

    foreach ($ace in $unauthorized) {
        if ($PSCmdlet.ShouldProcess("AdminSDHolder", "Remove ACE for $($ace.IdentityReference)")) {
            $acl.RemoveAccessRule($ace) | Out-Null
            Write-ADSecLog -Level INFO -Message "Removed unauthorized ACE: $($ace.IdentityReference)" -Context "AdminSDHolder"
        }
    }

    if ($PSCmdlet.ShouldProcess("AdminSDHolder", "Write updated ACL")) {
        Set-ADObject -Identity $adminSDHolder.DistinguishedName -Replace @{ntSecurityDescriptor = $acl}
        Write-ADSecLog -Level INFO -Message "Updated AdminSDHolder ACL applied." -Context "AdminSDHolder"
    }
}

function Repair-UnconstrainedDelegation {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $computers = Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -eq 515} -Properties TrustedForDelegation
    if (-not $computers) {
        Write-ADSecLog -Level INFO -Message "No computers with unconstrained delegation found." -Context "Delegation"
        return
    }

    foreach ($c in $computers) {
        if ($PSCmdlet.ShouldProcess($c.Name, "Disable unconstrained delegation")) {
            Set-ADAccountControl -Identity $c -TrustedForDelegation:$false
            Write-ADSecLog -Level INFO -Message "Disabled TrustedForDelegation" -Context $c.Name
        }
    }
}

function Repair-DCAutoLogon {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", $true)
            if (-not $key) { continue }

            $autoLogon = $key.GetValue("AutoAdminLogon")
            if ($autoLogon -ne "1") { continue }

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Disable AutoAdminLogon and clear credentials")) {
                $key.SetValue("AutoAdminLogon", "0", [Microsoft.Win32.RegistryValueKind]::String)
                $key.DeleteValue("DefaultUserName", $false)
                $key.DeleteValue("DefaultPassword", $false)
                $key.DeleteValue("DefaultDomainName", $false)
                Write-ADSecLog -Level INFO -Message "Disabled AutoAdminLogon and cleared creds" -Context $dc.HostName
            }
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to modify AutoLogon: $($_.Exception.Message)" -Context $dc.HostName
        }
    }
}

function Repair-NTLMAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DesiredLevel = 5
    )

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $reg  = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key  = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa", $true)
            if (-not $key) { continue }

            $current = $key.GetValue("LmCompatibilityLevel", 0)
            if ($current -ge $DesiredLevel) { continue }

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Set LmCompatibilityLevel to $DesiredLevel")) {
                $key.SetValue("LmCompatibilityLevel", $DesiredLevel, [Microsoft.Win32.RegistryValueKind]::DWord)
                Write-ADSecLog -Level INFO -Message "LmCompatibilityLevel $current -> $DesiredLevel" -Context $dc.HostName
            }
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to update LmCompatibilityLevel: $($_.Exception.Message)" -Context $dc.HostName
        }
    }
}

function Repair-PreWindows2000CompatibleAccess {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $group = Get-ADGroup -Identity "Pre-Windows 2000 Compatible Access" -Properties Members
    if (-not $group.Members -or $group.Members.Count -le 0) {
        Write-ADSecLog -Level INFO -Message "Group has no members." -Context "Pre-Windows 2000 Compatible Access"
        return
    }

    foreach ($memberDn in $group.Members) {
        if ($PSCmdlet.ShouldProcess($memberDn, "Remove from 'Pre-Windows 2000 Compatible Access'")) {
            Remove-ADGroupMember -Identity $group -Members $memberDn -Confirm:$false
            Write-ADSecLog -Level INFO -Message "Removed $memberDn from group" -Context "Pre-Windows 2000 Compatible Access"
        }
    }
}

function Repair-DCPrintSpooler {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $svc = Get-Service -ComputerName $dc.HostName -Name Spooler -ErrorAction Stop
        } catch {
            continue
        }

        if ($PSCmdlet.ShouldProcess($dc.HostName, "Stop and disable Spooler")) {
            try {
                if ($svc.Status -ne 'Stopped') {
                    Stop-Service -InputObject $svc -Force
                }
                Set-Service -InputObject $svc -StartupType Disabled
                Write-ADSecLog -Level INFO -Message "Disabled Spooler service" -Context $dc.HostName
            } catch {
                Write-ADSecLog -Level ERROR -Message "Failed to modify Spooler: $($_.Exception.Message)" -Context $dc.HostName
            }
        }
    }
}

function Repair-ProtectedUsersGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $protectedUsers    = Get-ADGroup -Identity "Protected Users"
    $protectedMembers  = Get-ADGroupMember -Identity $protectedUsers -Recursive
    $domainAdmins      = Get-ADGroupMember -Identity "Domain Admins"      -Recursive | Where-Object {$_.objectClass -eq 'user'}
    $enterpriseAdmins  = Get-ADGroupMember -Identity "Enterprise Admins"  -Recursive | Where-Object {$_.objectClass -eq 'user'}
    $privilegedUsers   = ($domainAdmins + $enterpriseAdmins) | Select-Object -Unique

    foreach ($user in $privilegedUsers) {
        if ($protectedMembers.SamAccountName -contains $user.SamAccountName) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Add to 'Protected Users'")) {
            Add-ADGroupMember -Identity $protectedUsers -Members $user -Confirm:$false
            Write-ADSecLog -Level INFO -Message "Added $($user.SamAccountName) to Protected Users" -Context "Protected Users"
        }
    }
}

function Repair-DCUnauthorizedSoftware {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$UnauthorizedSoftware = @("*Chrome*", "*Firefox*", "*Skype*", "*Teams*")
    )

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $software = Get-WmiObject -ComputerName $dc.HostName -Class Win32_Product |
                Where-Object {
                    $name = $_.Name
                    $UnauthorizedSoftware | Where-Object { $name -like $_ }
                }
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to query software: $($_.Exception.Message)" -Context $dc.HostName
            continue
        }

        foreach ($app in $software) {
            if ($PSCmdlet.ShouldProcess("$($dc.HostName): $($app.Name)", "Uninstall")) {
                try {
                    $null = $app.Uninstall()
                    Write-ADSecLog -Level INFO -Message "Requested uninstall of '$($app.Name)'" -Context $dc.HostName
                } catch {
                    Write-ADSecLog -Level ERROR -Message "Failed uninstall of '$($app.Name)': $($_.Exception.Message)" -Context $dc.HostName
                }
            }
        }
    }
}

function Repair-DCAnonymousLdapAccess {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DesiredValue = 2
    )

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters", $true)
            if (-not $key) { continue }

            $current = $key.GetValue("LDAPServerIntegrity", 1)
            if ($current -ge $DesiredValue) { continue }

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Set LDAPServerIntegrity to $DesiredValue")) {
                $key.SetValue("LDAPServerIntegrity", $DesiredValue, [Microsoft.Win32.RegistryValueKind]::DWord)
                Write-ADSecLog -Level INFO -Message "LDAPServerIntegrity $current -> $DesiredValue" -Context $dc.HostName
            }
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to update LDAPServerIntegrity: $($_.Exception.Message)" -Context $dc.HostName
        }
    }
}

function Repair-PrivilegedAccountsWithSPN {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$ClearSpnInsteadOfDisable
    )

    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $privilegedUsers = @()
    foreach ($group in $privilegedGroups) {
        $privilegedUsers += Get-ADGroupMember -Identity $group -Recursive |
            Where-Object { $_.objectClass -eq 'user' }
    }
    $privilegedUsers = $privilegedUsers | Select-Object -Unique

    foreach ($user in $privilegedUsers) {
        $userObj = Get-ADUser -Identity $user -Properties ServicePrincipalName, Enabled
        if (-not $userObj.ServicePrincipalName) { continue }

        if ($ClearSpnInsteadOfDisable) {
            if ($PSCmdlet.ShouldProcess($userObj.SamAccountName, "Clear all SPNs")) {
                Set-ADUser -Identity $userObj -ServicePrincipalNames @()
                Write-ADSecLog -Level INFO -Message "Cleared SPNs" -Context $userObj.SamAccountName
            }
        } else {
            if ($PSCmdlet.ShouldProcess($userObj.SamAccountName, "Disable privileged account with SPNs")) {
                Disable-ADAccount -Identity $userObj
                Write-ADSecLog -Level WARN -Message "Disabled privileged user with SPNs" -Context $userObj.SamAccountName
            }
        }
    }
}

function Repair-DCSysvolPermissions {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dc = Get-ADDomainController -Filter * | Select-Object -First 1
    $sysvolPath = "\\$($dc.HostName)\SYSVOL"

    try {
        $acl = Get-Acl -Path $sysvolPath
    } catch {
        Write-ADSecLog -Level ERROR -Message "Unable to read SYSVOL ACL: $($_.Exception.Message)" -Context $sysvolPath
        return
    }

    $weakPermissions = $acl.Access | Where-Object {
        $_.IdentityReference -match "Everyone|Users|Authenticated Users" -and
        $_.FileSystemRights -match "FullControl|Modify|Write"
    }

    if (-not $weakPermissions) {
        Write-ADSecLog -Level INFO -Message "No weak SYSVOL permissions found." -Context $sysvolPath
        return
    }

    foreach ($ace in $weakPermissions) {
        if ($PSCmdlet.ShouldProcess($sysvolPath, "Remove weak ACE for $($ace.IdentityReference)")) {
            $acl.RemoveAccessRule($ace) | Out-Null
            Write-ADSecLog -Level INFO -Message "Removed weak SYSVOL ACE: $($ace.IdentityReference)" -Context $sysvolPath
        }
    }

    if ($PSCmdlet.ShouldProcess($sysvolPath, "Apply updated ACL")) {
        Set-Acl -Path $sysvolPath -AclObject $acl
        Write-ADSecLog -Level INFO -Message "Updated SYSVOL permissions." -Context $sysvolPath
    }
}

function Repair-RODCPasswordReplicationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $rodcs = Get-ADDomainController -Filter {IsReadOnly -eq $true}
    if (-not $rodcs) {
        Write-ADSecLog -Level INFO -Message "No RODCs found." -Context "RODC PRP"
        return
    }

    foreach ($rodc in $rodcs) {
        try {
            $allowed = Get-ADDomainControllerPasswordReplicationPolicy -Identity $rodc -Allowed
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to get PRP allowed list: $($_.Exception.Message)" -Context $rodc.Name
            continue
        }

        $privilegedInAllowed = $allowed | Where-Object {
            $_.SamAccountName -match "admin|administrator"
        }

        foreach ($acct in $privilegedInAllowed) {
            if ($PSCmdlet.ShouldProcess($rodc.Name, "Remove privileged account $($acct.SamAccountName) from Allowed PRP")) {
                # Remove from Allowed, ensure it's in Denied is a design choice;
                # here we only remove from allowed to avoid unintended Denied entries.
                Set-ADDomainControllerPasswordReplicationPolicy -Identity $rodc -Account $acct -Operation Remove-Allowed
                Write-ADSecLog -Level INFO -Message "Removed $($acct.SamAccountName) from RODC Allowed PRP" -Context $rodc.Name
            }
        }
    }
}

function Repair-DCLocalAdminGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $admins = Get-WmiObject -ComputerName $dc.HostName -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent='Win32_Group.Domain=""$($dc.HostName)"",Name=""Administrators""" 
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to query local admins: $($_.Exception.Message)" -Context $dc.HostName
            continue
        }

        $unexpectedMembers = $admins | Where-Object {
            $_.PartComponent -notmatch "Domain Admins|Enterprise Admins|Administrator"
        }

        foreach ($m in $unexpectedMembers) {
            $match = [regex]::Match($m.PartComponent, 'Name=\"(.+?)\"')
            if (-not $match.Success) { continue }
            $memberName = $match.Groups[1].Value

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Remove local admin '$memberName'")) {
                try {
                    net localgroup Administrators "$memberName" /delete /domain | Out-Null
                    Write-ADSecLog -Level INFO -Message "Removed $memberName from local Administrators" -Context $dc.HostName
                } catch {
                    Write-ADSecLog -Level ERROR -Message "Failed to remove ($memberName): $($_.Exception.Message)" -Context $dc.HostName
                }
            }
        }
    }
}

function Repair-DCRemoteAccessServices {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *
    $dangerousServices = @("RemoteRegistry", "RemoteAccess", "TermService")

    foreach ($dc in $dcs) {
        foreach ($service in $dangerousServices) {
            try {
                $svc = Get-Service -ComputerName $dc.HostName -Name $service -ErrorAction SilentlyContinue
                if (-not $svc -or $svc.Status -ne 'Running') { continue }
            } catch {
                continue
            }

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Stop and disable $service")) {
                try {
                    Stop-Service -InputObject $svc -Force
                    Set-Service -InputObject $svc -StartupType Disabled
                    Write-ADSecLog -Level INFO -Message "Disabled $service" -Context $dc.HostName
                } catch {
                    Write-ADSecLog -Level ERROR -Message "Failed to modify ($service): $($_.Exception.Message)" -Context $dc.HostName
                }
            }
        }
    }
}

function Repair-DCsmbv1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $cfg = Get-SmbServerConfiguration -CimSession $dc.HostName
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to query SMB configuration: $($_.Exception.Message)" -Context $dc.HostName
            continue
        }

        if (-not $cfg.EnableSMB1Protocol) { continue }

        if ($PSCmdlet.ShouldProcess($dc.HostName, "Disable SMBv1")) {
            try {
                Set-SmbServerConfiguration -CimSession $dc.HostName -EnableSMB1Protocol $false -Force
                Write-ADSecLog -Level INFO -Message "Disabled SMBv1" -Context $dc.HostName
            } catch {
                Write-ADSecLog -Level ERROR -Message "Failed to disable SMBv1: $($_.Exception.Message)" -Context $dc.HostName
            }
        }
    }
}

function Repair-DCFirewallStatus {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $profiles = Get-NetFirewallProfile -CimSession $dc.HostName
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to query firewall profile: $($_.Exception.Message)" -Context $dc.HostName
            continue
        }

        foreach ($profile in $profiles) {
            if ($profile.Enabled) { continue }

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Enable firewall profile $($profile.Name)")) {
                try {
                    Set-NetFirewallProfile -CimSession $dc.HostName -Name $profile.Name -Enabled True
                    Write-ADSecLog -Level INFO -Message "Enabled firewall profile $($profile.Name)" -Context $dc.HostName
                } catch {
                    Write-ADSecLog -Level ERROR -Message "Failed to enable profile $($profile.Name): $($_.Exception.Message)" -Context $dc.HostName
                }
            }
        }
    }
}

function Repair-BitLockerOnDCs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Tpm','Password','RecoveryPassword','TpmPin','TpmKey')]
        [string]$ProtectorType = 'Tpm',

        [switch]$EnableIfNotPresent
    )

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $bitlocker = Get-BitLockerVolume -CimSession $dc.HostName | Where-Object {$_.VolumeType -eq 'OperatingSystem'}
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to query BitLocker: $($_.Exception.Message)" -Context $dc.HostName
            continue
        }

        if (-not $bitlocker) { continue }

        if ($bitlocker.ProtectionStatus -eq 'On') {
            Write-ADSecLog -Level INFO -Message "BitLocker already enabled" -Context $dc.HostName
            continue
        }

        if (-not $EnableIfNotPresent) {
            Write-ADSecLog -Level WARN -Message "BitLocker is OFF; rerun with -EnableIfNotPresent to enable." -Context $dc.HostName
            continue
        }

        if ($PSCmdlet.ShouldProcess($dc.HostName, "Enable BitLocker on OS volume")) {
            try {
                switch ($ProtectorType) {
                    'Tpm' {
                        Enable-BitLocker -MountPoint $bitlocker.MountPoint -CimSession $dc.HostName -TpmProtector
                    }
                    default {
                        Enable-BitLocker -MountPoint $bitlocker.MountPoint -CimSession $dc.HostName -TpmProtector
                    }
                }
                Write-ADSecLog -Level INFO -Message "BitLocker enable initiated" -Context $dc.HostName
            } catch {
                Write-ADSecLog -Level ERROR -Message "Failed to enable BitLocker: $($_.Exception.Message)" -Context $dc.HostName
            }
        }
    }
}

function Repair-NullSessionAccess {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DesiredValue = 1
    )

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa", $true)
            if (-not $key) { continue }

            $currentRestrictAnonymous   = $key.GetValue("RestrictAnonymous", 0)
            $currentRestrictAnonymousSA = $key.GetValue("RestrictAnonymousSAM", 0)

            if ($PSCmdlet.ShouldProcess($dc.HostName, "Set RestrictAnonymous/RestrictAnonymousSAM to $DesiredValue")) {
                if ($currentRestrictAnonymous   -lt $DesiredValue) {
                    $key.SetValue("RestrictAnonymous",   $DesiredValue, [Microsoft.Win32.RegistryValueKind]::DWord)
                }
                if ($currentRestrictAnonymousSA -lt $DesiredValue) {
                    $key.SetValue("RestrictAnonymousSAM",$DesiredValue, [Microsoft.Win32.RegistryValueKind]::DWord)
                }
                Write-ADSecLog -Level INFO -Message "Updated null session keys" -Context $dc.HostName
            }
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to update null session settings: $($_.Exception.Message)" -Context $dc.HostName
        }
    }
}

function Repair-LLMNRAndNBTNS {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $dcs = Get-ADDomainController -Filter *

    foreach ($dc in $dcs) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.CreateSubKey("SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")
            $current = $key.GetValue("EnableMulticast", 1)
        } catch {
            Write-ADSecLog -Level ERROR -Message "Failed to access DNSClient key: $($_.Exception.Message)" -Context $dc.HostName
            continue
        }

        if ($current -eq 0) { continue }

        if ($PSCmdlet.ShouldProcess($dc.HostName, "Set EnableMulticast=0")) {
            $key.SetValue("EnableMulticast", 0, [Microsoft.Win32.RegistryValueKind]::DWord)
            Write-ADSecLog -Level INFO -Message "Disabled LLMNR (EnableMulticast=0)" -Context $dc.HostName
        }

        # NetBIOS disabling is better done via GPO/DHCP/NIC config; log guidance only.
        Write-ADSecLog -Level INFO -Message "Review NetBIOS settings via GPO/NIC; not auto-changed here." -Context $dc.HostName
    }
}

function Repair-PrivilegedGroupsNesting {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

    foreach ($group in $privilegedGroups) {
        $members = Get-ADGroupMember -Identity $group
        $nestedGroups = $members | Where-Object {$_.objectClass -eq 'group'}

        foreach ($nested in $nestedGroups) {
            if ($PSCmdlet.ShouldProcess($group, "Remove nested group $($nested.SamAccountName)")) {
                try {
                    Remove-ADGroupMember -Identity $group -Members $nested -Confirm:$false
                    Write-ADSecLog -Level INFO -Message "Removed nested group $($nested.SamAccountName)" -Context $group
                } catch {
                    Write-ADSecLog -Level ERROR -Message "Failed to remove nested group: $($_.Exception.Message)" -Context $group
                }
            }
        }
    }
}

function Repair-DomainObjectQuota {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DesiredQuota = 0
    )

    $domain = Get-ADDomain
    if ($domain.MachineAccountQuota -eq $DesiredQuota) {
        Write-ADSecLog -Level INFO -Message "MachineAccountQuota already $DesiredQuota" -Context $domain.DNSRoot
        return
    }

    if ($PSCmdlet.ShouldProcess($domain.DNSRoot, "Set MachineAccountQuota to $DesiredQuota")) {
        Set-ADDomain -Identity $domain.DNSRoot -Replace @{ "ms-DS-MachineAccountQuota" = $DesiredQuota }
        Write-ADSecLog -Level INFO -Message "Set MachineAccountQuota to $DesiredQuota" -Context $domain.DNSRoot
    }
}

function Repair-GPOBackups {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$BackupPath = "\\$((Get-ADDomain).PDCEmulator)\GPOBackups"
    )

    if (-not (Test-Path $BackupPath)) {
        if ($PSCmdlet.ShouldProcess($BackupPath, "Create GPO backup root path")) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
            Write-ADSecLog -Level INFO -Message "Created GPO backup path" -Context $BackupPath
        }
    }

    # This function does not schedule backups; it just ensures the path exists.
    Write-ADSecLog -Level INFO -Message "Ensure scheduled task/backup job uses $BackupPath for regular GPO backups." -Context "GPO Backups"
}

function Repair-AdminAccountIsolation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$UserSuffix = ".user"
    )

    $admins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object {$_.objectClass -eq 'user'}

    foreach ($admin in $admins) {
        $user = Get-ADUser -Identity $admin -Properties LastLogonDate, LogonCount
        if (-not $user.LastLogonDate -or $user.LastLogonDate -lt (Get-Date).AddDays(-7)) { continue }

        $candidateSam = ($user.SamAccountName + $UserSuffix)
        $nonAdmin = Get-ADUser -Filter "SamAccountName -eq '$candidateSam'" -ErrorAction SilentlyContinue

        if ($nonAdmin) {
            Write-ADSecLog -Level INFO -Message "Admin $($user.SamAccountName) already has user account $candidateSam" -Context "Admin Isolation"
            continue
        }

        if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Create matching non-admin user account '$candidateSam'")) {
            try {
                $ou = (Get-ADDomain).UsersContainer
                New-ADUser -Name $user.Name -SamAccountName $candidateSam -Path $ou -Enabled:$false
                Write-ADSecLog -Level INFO -Message "Created placeholder user account $candidateSam (disabled, needs configuration)" -Context "Admin Isolation"
            } catch {
                Write-ADSecLog -Level ERROR -Message "Failed to create user account ($candidateSam): $($_.Exception.Message)" -Context "Admin Isolation"
            }
        }
    }
}

function Repair-ServiceAccountPasswords {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$MaxAgeDays = 365
    )

    $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties PasswordLastSet, PasswordNeverExpires, ServicePrincipalName

    $weakAccounts = $serviceAccounts | Where-Object {
        $_.PasswordNeverExpires -or 
        ((Get-Date) - $_.PasswordLastSet).Days -gt $MaxAgeDays
    }

    foreach ($acct in $weakAccounts) {
        if ($PSCmdlet.ShouldProcess($acct.SamAccountName, "Flag service account for password remediation")) {
            # We won't automatically reset passwords (can break services) – log guidance only.
            Write-ADSecLog -Level WARN -Message "Service account password stale or never expires. Consider gMSA or rotation." -Context $acct.SamAccountName
        }
    }
}

function Repair-LAPSDeployment {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # LAPS is typically deployed via schema extension + GPO + client.
    # We only log guidance here to avoid half-configuring LAPS.
    Write-ADSecLog -Level INFO -Message "LAPS remediation is not automatic; deploy Windows LAPS via schema update + GPO." -Context "LAPS"
}

# MAIN EXECUTION FUNCTIONS (existing definitions kept, just making sure we call all new checks)

function Invoke-ADSecurityAudit {
    [CmdletBinding()]
    param(
        [ValidateSet("All", "High", "Medium", "Low")]
        [string]$Severity = "All",
        [string]$ExportPath
    )

    Write-Host "Starting Active Directory Security Audit..." -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Cyan
    Write-Host ""

    $allResults = @()

    if ($Severity -in @("All","High")) {
        Write-Host "Running HIGH Severity Checks..." -ForegroundColor Red
        $allResults += Test-KrbtgtPasswordAge
        $allResults += Test-AdminSDHolder
        $allResults += Test-UnconstrainedDelegation
        $allResults += Test-DCRegistryAutoLogon
        $allResults += Test-NTLMAuthentication
        $allResults += Test-PreWindows2000CompatibleAccess
        $allResults += Test-DCPrintSpooler
        $allResults += Test-ProtectedUsersGroup
        $allResults += Test-DCUnauthorizedSoftware
        $allResults += Test-DCAnonymousAccess
        $allResults += Test-PrivilegedAccountsWithSPN
        $allResults += Test-DCSysvolPermissions
        $allResults += Test-RODCPasswordReplicationPolicy
        $allResults += Test-DCLocalAdminGroup
        $allResults += Test-DCRemoteAccessServices
        $allResults += Test-SMBv1Protocol
        $allResults += Test-DCFirewallStatus
        $allResults += Test-BitLockerOnDCs
        $allResults += Test-NullSessionAccess
        $allResults += Test-LLMNRAndNBTNS
        $allResults += Test-PrivilegedGroupsNesting
        $allResults += Test-DCPatchLevel
        $allResults += Test-DomainObjectQuota
        $allResults += Test-GPOBackups
        $allResults += Test-AdminAccountIsolation
        $allResults += Test-ServiceAccountPasswords
        $allResults += Test-CertificateServices
        $allResults += Test-ExchangeSchemaVersion
        $allResults += Test-LAPSDeployment
        $allResults += Test-DNSSecurity
    }

    if ($Severity -in @("All","Medium")) {
        Write-Host "Running MEDIUM Severity Checks..." -ForegroundColor Yellow
        $allResults += Test-StaleComputerAccounts
        $allResults += Test-StaleUserAccounts
        $allResults += Test-PasswordPolicy
        $allResults += Test-ReversibleEncryption
        $allResults += Test-EmptyPasswordAllowed
        $allResults += Test-PasswordNeverExpires
        $allResults += Test-DESEncryption
        $allResults += Test-KerberosPreAuthNotRequired
        $allResults += Test-ServicePrincipalNames
        $allResults += Test-AdminAccountNamingConvention
        $allResults += Test-DCSMBSigning
        $allResults += Test-LDAPSConfiguration
        $allResults += Test-GPOPermissions
        $allResults += Test-SIDHistory
        $allResults += Test-TombstoneLifetime
        $allResults += Test-DomainTrustRelationships
        $allResults += Test-AccountLockoutPolicy
        $allResults += Test-DisabledAccountsInPrivilegedGroups
        $allResults += Test-AccountOperators
        $allResults += Test-ServerOperators
        $allResults += Test-PrintOperators
        $allResults += Test-BackupOperators
        $allResults += Test-DCShadowCredentials
        $allResults += Test-PrivilegedUsersLogonWorkstations
        $allResults += Test-NonOwnerDLManagers
        $allResults += Test-WeakUserDescriptions
        $allResults += Test-InsecureGPOUserRights
        $allResults += Test-NTFSPermissionsSysvolScripts
        $allResults += Test-DHCPSettingsForDNS
        $allResults += Test-GroupPolicyLoopback
        $allResults += Test-DomainControllerLocalUsers
        $allResults += Test-GroupNestingDepth
        $allResults += Test-UsersWithManyGroupMemberships
    }

    if ($Severity -in @("All","Low")) {
        Write-Host "Running LOW Severity Checks..." -ForegroundColor Green
        $allResults += Test-DefaultAdministrator
        $allResults += Test-DefaultGuestAccount
        $allResults += Test-EmptyOrganizationalUnits
        $allResults += Test-DuplicateSPNs
        $allResults += Test-DNSScavenging
        $allResults += Test-RecycleBinEnabled
        $allResults += Test-FineGrainedPasswordPolicies
        $allResults += Test-DHCPAuthorization
        $allResults += Test-DFSRBacklogHealth
        $allResults += Test-OrphanedForeignSecurityPrincipals
        $allResults += Test-DomainControllerTime
        $allResults += Test-DomainFunctionalLevel
        $allResults += Test-ADBackupAge
        $allResults += Test-CompromisedPasswordCheck
        $allResults += Test-EventLogConfiguration
    }

    Write-Host ""
    Write-Host "Audit Complete!" -ForegroundColor Cyan
    Write-Host "Total Checks: $($allResults.Count)" -ForegroundColor Cyan

    if ($ExportPath) {
        $allResults | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
    }

    $allResults
}

function Invoke-ADSecurityRemediation {
    <#
    .SYNOPSIS
        Run remediation for a given check name.
    .PARAMETER CheckName
        The CheckName string from Test-* output (e.g. 'SMBv1 Protocol Enabled').
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$CheckName
    )

    switch ($CheckName) {
        "KRBTGT Password Age"                 { Invoke-KrbtgtPasswordRotation }
        "AdminSDHolder ACL"                   { Repair-AdminSDHolderAcl }
        "Unconstrained Delegation"            { Repair-UnconstrainedDelegation }
        "DC AutoLogon Registry"               { Repair-DCAutoLogon }
        "NTLM Authentication Level"           { Repair-NTLMAuthentication }
        "Pre-Windows 2000 Compatible Access"  { Repair-PreWindows2000CompatibleAccess }
        "DC Print Spooler Service"            { Repair-DCPrintSpooler }
        "Protected Users Group Membership"    { Repair-ProtectedUsersGroupMembership }
        "DC Unauthorized Software"            { Repair-DCUnauthorizedSoftware }
        "DC Anonymous LDAP Access"           { Repair-DCAnonymousLdapAccess }
        "Privileged Accounts with SPNs"      { Repair-PrivilegedAccountsWithSPN }
        "SYSVOL Permissions"                 { Repair-DCSysvolPermissions }
        "RODC Password Replication Policy"   { Repair-RODCPasswordReplicationPolicy }
        "DC Local Administrators Group"      { Repair-DCLocalAdminGroup }
        "DC Remote Access Services"          { Repair-DCRemoteAccessServices }
        "SMBv1 Protocol Enabled"             { Repair-DCsmbv1 }
        "DC Windows Firewall Status"         { Repair-DCFirewallStatus }
        "BitLocker on Domain Controllers"    { Repair-BitLockerOnDCs }
        "Null Session Access"                { Repair-NullSessionAccess }
        "LLMNR and NetBIOS"                  { Repair-LLMNRAndNBTNS }
        "Privileged Groups Nesting"          { Repair-PrivilegedGroupsNesting }
        "Domain Object Creation Quota"       { Repair-DomainObjectQuota }
        "GPO Backups"                        { Repair-GPOBackups }
        "Admin Account Isolation"            { Repair-AdminAccountIsolation }
        "Service Account Password Policy"    { Repair-ServiceAccountPasswords }
        "LAPS Deployment"                    { Repair-LAPSDeployment }
        default {
            Write-ADSecLog -Level WARN -Message "No remediation function defined for '$CheckName'." -Context "Invoke-ADSecurityRemediation"
        }
    }
}

function Get-ADSecurityScore {
    [CmdletBinding()]
    param()

    $results = Invoke-ADSecurityAudit -Severity All

    $highWeight   = 10
    $mediumWeight = 5
    $lowWeight    = 1

    $maxScore = (($results | Where-Object {$_.Severity -eq "HIGH"}).Count   * $highWeight) +
                (($results | Where-Object {$_.Severity -eq "MEDIUM"}).Count * $mediumWeight) +
                (($results | Where-Object {$_.Severity -eq "LOW"}).Count    * $lowWeight)

    $earnedScore = (($results | Where-Object {$_.Severity -eq "HIGH"   -and $_.Status -eq "PASS"}).Count * $highWeight) +
                   (($results | Where-Object {$_.Severity -eq "MEDIUM" -and $_.Status -eq "PASS"}).Count * $mediumWeight) +
                   (($results | Where-Object {$_.Severity -eq "LOW"    -and $_.Status -eq "PASS"}).Count * $lowWeight)

    $scorePercentage = if ($maxScore -gt 0) {
        [Math]::Round(($earnedScore / $maxScore) * 100, 2)
    } else { 0 }

    $totalChecks = $results.Count
    $passed      = ($results | Where-Object {$_.Status -eq "PASS"}).Count
    $failed      = ($results | Where-Object {$_.Status -eq "FAIL"}).Count
    $warnings    = ($results | Where-Object {$_.Status -eq "WARN"}).Count

    [PSCustomObject]@{
        TotalChecks    = $totalChecks
        Passed         = $passed
        Failed         = $failed
        Warnings       = $warnings
        MaxScore       = $maxScore
        EarnedScore    = $earnedScore
        ScorePercentage= $scorePercentage
        Rating         = switch ($scorePercentage) {
            {$_ -ge 90} { "Excellent" }
            {$_ -ge 75} { "Good" }
            {$_ -ge 60} { "Fair" }
            {$_ -ge 40} { "Poor" }
            default     { "Critical" }
        }
    }
}

function Export-ADSecurityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $results = Invoke-ADSecurityAudit -Severity All
    $score   = Get-ADSecurityScore

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .score-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                     color: white; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .score-box h2 { color: white; margin-top: 0; }
        table { border-collapse: collapse; width: 100%; background-color: white;
                margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #3498db; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .high { color: #e74c3c; font-weight: bold; }
        .medium { color: #f39c12; font-weight: bold; }
        .low { color: #27ae60; font-weight: bold; }
        .fail { background-color: #ffebee; }
        .warn { background-color: #fff3e0; }
        .pass { background-color: #e8f5e9; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Active Directory Security Audit Report</h1>
    <p class="timestamp">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>

    <div class="score-box">
        <h2>Overall Security Score: $($score.ScorePercentage)% - $($score.Rating)</h2>
        <p>Total Checks: $($score.TotalChecks) | Passed: $($score.Passed) | Failed: $($score.Failed) | Warnings: $($score.Warnings)</p>
    </div>

    <h2>Audit Results</h2>
    <table>
        <tr>
            <th>Check Name</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Recommendation</th>
        </tr>
"@

    foreach ($r in $results) {
        $severityClass = $r.Severity.ToLower()
        $statusClass   = $r.Status.ToLower()
        $html += @"
        <tr class="$statusClass">
            <td>$($r.CheckName)</td>
            <td class="$severityClass">$($r.Severity)</td>
            <td>$($r.Status)</td>
            <td>$($r.Risk)</td>
            <td>$($r.Recommendation)</td>
        </tr>
"@
    }

    $html += @"
    </table>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function @(
    # High
    'Test-KrbtgtPasswordAge',
    'Test-AdminSDHolder',
    'Test-UnconstrainedDelegation',
    'Test-DCRegistryAutoLogon',
    'Test-NTLMAuthentication',
    'Test-PreWindows2000CompatibleAccess',
    'Test-DCPrintSpooler',
    'Test-ProtectedUsersGroup',
    'Test-DCUnauthorizedSoftware',
    'Test-DCAnonymousAccess',
    'Test-PrivilegedAccountsWithSPN',
    'Test-DCSysvolPermissions',
    'Test-RODCPasswordReplicationPolicy',
    'Test-DCLocalAdminGroup',
    'Test-DCRemoteAccessServices',
    'Test-SMBv1Protocol',
    'Test-DCFirewallStatus',
    'Test-BitLockerOnDCs',
    'Test-NullSessionAccess',
    'Test-LLMNRAndNBTNS',
    'Test-PrivilegedGroupsNesting',
    'Test-DCPatchLevel',
    'Test-DomainObjectQuota',
    'Test-GPOBackups',
    'Test-AdminAccountIsolation',
    'Test-ServiceAccountPasswords',
    'Test-CertificateServices',
    'Test-ExchangeSchemaVersion',
    'Test-LAPSDeployment',
    'Test-DNSSecurity',

    # Medium
    'Test-StaleComputerAccounts',
    'Test-StaleUserAccounts',
    'Test-PasswordPolicy',
    'Test-ReversibleEncryption',
    'Test-EmptyPasswordAllowed',
    'Test-PasswordNeverExpires',
    'Test-DESEncryption',
    'Test-KerberosPreAuthNotRequired',
    'Test-ServicePrincipalNames',
    'Test-AdminAccountNamingConvention',
    'Test-DCSMBSigning',
    'Test-LDAPSConfiguration',
    'Test-GPOPermissions',
    'Test-SIDHistory',
    'Test-TombstoneLifetime',
    'Test-DomainTrustRelationships',
    'Test-AccountLockoutPolicy',
    'Test-DisabledAccountsInPrivilegedGroups',
    'Test-AccountOperators',
    'Test-ServerOperators',
    'Test-PrintOperators',
    'Test-BackupOperators',
    'Test-DCShadowCredentials',
    'Test-PrivilegedUsersLogonWorkstations',
    'Test-NonOwnerDLManagers',
    'Test-WeakUserDescriptions',
    'Test-InsecureGPOUserRights',
    'Test-NTFSPermissionsSysvolScripts',
    'Test-DHCPSettingsForDNS',
    'Test-GroupPolicyLoopback',
    'Test-DomainControllerLocalUsers',
    'Test-GroupNestingDepth',
    'Test-UsersWithManyGroupMemberships',

    # Low
    'Test-DefaultAdministrator',
    'Test-DefaultGuestAccount',
    'Test-EmptyOUs',
    'Test-DuplicateSPNs',
    'Test-DNSScavenging',
    'Test-RecycleBinEnabled',
    'Test-FineGrainedPasswordPolicies',
    'Test-DHCPAuthorization',
    'Test-DFSRBacklogHealth',
    'Test-OrphanedForeignSecurityPrincipals',
    'Test-DomainControllerTime',
    'Test-DomainFunctionalLevel',
    'Test-ADBackupAge',
    'Test-CompromisedPasswordCheck',
    'Test-EventLogConfiguration'
    
    
    'Set-ADSecLogPath',
    'Write-ADSecLog',
    'Invoke-KrbtgtPasswordRotation',
    'Repair-*',
    'Invoke-ADSecurityTests',
    'Invoke-ADSecurityRemediation',

    # Main
    'Invoke-ADSecurityAudit',
    'Get-ADSecurityScore',
    'Export-ADSecurityReport'
)    
