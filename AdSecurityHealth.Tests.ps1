#requires -Version 5.1
# AdSecurityHealth.Tests.ps1
# Pester unit tests for ADSecurityHealth module

BeforeAll {
    # Import the module
    Import-Module "$PSScriptRoot\AdSecurityHealth.psm1" -Force
}

Describe "Helper Functions" {
    Context "Write-ADSHVerbose" {
        It "Should accept a message parameter" {
            { Write-ADSHVerbose -Message "Test message" -Verbose } | Should -Not -Throw
        }
        
        It "Should not accept null or empty message" {
            { Write-ADSHVerbose -Message "" } | Should -Throw
            { Write-ADSHVerbose -Message $null } | Should -Throw
        }
    }
    
    Context "Get-ADSHConfig" {
        It "Should return a configuration object" {
            $config = Get-ADSHConfig
            $config | Should -Not -BeNullOrEmpty
        }
        
        It "Should have required properties" {
            $config = Get-ADSHConfig
            $config.StaleDays | Should -Not -BeNullOrEmpty
            $config.SensitiveGroups | Should -Not -BeNullOrEmpty
            $config.CriticalServices | Should -Not -BeNullOrEmpty
        }
        
        It "Should return defaults if config file not found" {
            $config = Get-ADSHConfig -Path "C:\NonExistent\config.json"
            $config.StaleDays | Should -Be 90
        }
        
        It "Should handle invalid JSON gracefully" {
            $tempFile = New-TemporaryFile
            "Invalid JSON content" | Out-File -FilePath $tempFile.FullName
            $config = Get-ADSHConfig -Path $tempFile.FullName
            $config.StaleDays | Should -Be 90
            Remove-Item $tempFile.FullName -Force
        }
    }
    
    Context "New-ADSHFinding" {
        It "Should create a finding object with required parameters" {
            $finding = New-ADSHFinding -Category "Test" -Id "TEST-001" -Severity "High" -Title "Test Finding"
            $finding | Should -Not -BeNullOrEmpty
            $finding.Category | Should -Be "Test"
            $finding.Id | Should -Be "TEST-001"
            $finding.Severity | Should -Be "High"
            $finding.Title | Should -Be "Test Finding"
        }
        
        It "Should include a timestamp" {
            $finding = New-ADSHFinding -Category "Test" -Id "TEST-001" -Severity "High" -Title "Test Finding"
            $finding.Timestamp | Should -Not -BeNullOrEmpty
            { [DateTime]::Parse($finding.Timestamp) } | Should -Not -Throw
        }
        
        It "Should validate severity values" {
            { New-ADSHFinding -Category "Test" -Id "TEST-001" -Severity "Invalid" -Title "Test" } | Should -Throw
        }
        
        It "Should accept valid severity values" {
            $severities = @('Info', 'Low', 'Medium', 'High', 'Critical')
            foreach ($sev in $severities) {
                { New-ADSHFinding -Category "Test" -Id "TEST-001" -Severity $sev -Title "Test" } | Should -Not -Throw
            }
        }
        
        It "Should accept optional parameters" {
            $finding = New-ADSHFinding -Category "Test" -Id "TEST-001" -Severity "High" -Title "Test Finding" `
                -Description "Test description" -Evidence @{test="data"} -Remediation "Fix it"
            $finding.Description | Should -Be "Test description"
            $finding.Remediation | Should -Be "Fix it"
            $finding.Evidence | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Parameter Validation" {
    Context "Get-StaleAccounts" {
        It "Should accept valid StaleDays values" {
            Mock Get-ADUser { return @() }
            Mock Get-ADSHConfig { return @{ StaleDays = 90 } }
            { Get-StaleAccounts -StaleDays 30 } | Should -Not -Throw
            { Get-StaleAccounts -StaleDays 365 } | Should -Not -Throw
        }
    }
    
    Context "Get-DNSHealth" {
        It "Should accept valid TimeoutSeconds values" {
            Mock Get-ADDomainController { return @() }
            Mock Get-ADSHConfig { return @{ DNSDcDiagTimeoutSeconds = 180 } }
            { Get-DNSHealth -TimeoutSeconds 60 } | Should -Not -Throw
            { Get-DNSHealth -TimeoutSeconds 300 } | Should -Not -Throw
        }
    }
    
    Context "Get-SecurityEventLogConfig" {
        It "Should accept valid MinSizeMB values" {
            Mock Get-ADDomainController { return @() }
            Mock Get-ADSHConfig { return @{ EventLogMinSizeMB = 2048 } }
            { Get-SecurityEventLogConfig -MinSizeMB 1024 } | Should -Not -Throw
            { Get-SecurityEventLogConfig -MinSizeMB 10240 } | Should -Not -Throw
        }
    }
}

Describe "Error Handling" {
    Context "Functions should handle AD connectivity failures" {
        It "Get-StaleAccounts should handle AD query failures gracefully" {
            Mock Get-ADUser { throw "AD not available" }
            Mock Get-ADSHConfig { return @{ StaleDays = 90 } }
            
            $result = Get-StaleAccounts
            $result | Should -Not -BeNullOrEmpty
            $result.Severity | Should -Be "Info"
            $result.Title | Should -Match "failed"
        }
        
        It "Get-PasswordPolicyAudit should handle AD query failures gracefully" {
            Mock Get-ADDefaultDomainPasswordPolicy { throw "AD not available" }
            
            $result = Get-PasswordPolicyAudit
            $result | Should -Not -BeNullOrEmpty
            $result.Severity | Should -Be "Info"
            $result.Title | Should -Match "failed"
        }
        
        It "Get-FSMORoleHolders should handle AD query failures gracefully" {
            Mock Get-ADDomain { throw "AD not available" }
            
            $result = Get-FSMORoleHolders
            $result | Should -Not -BeNullOrEmpty
            $result.Severity | Should -Be "Info"
            $result.Title | Should -Match "failed"
        }
    }
    
    Context "Functions should handle missing groups gracefully" {
        It "Get-PrivilegedGroupMembership should handle non-existent groups" {
            Mock Get-ADSHConfig { return @{ SensitiveGroups = @('NonExistentGroup') } }
            Mock Get-ADGroup { throw "Group not found" }
            
            $result = Get-PrivilegedGroupMembership
            $result | Should -Not -BeNullOrEmpty
            $result.Title | Should -Match "not found"
        }
        
        It "Get-PreWin2000AccessRisks should handle missing group" {
            Mock Get-ADGroup { throw "Group not found" }
            
            $result = Get-PreWin2000AccessRisks
            $result | Should -Not -BeNullOrEmpty
            $result.Severity | Should -Be "Info"
            $result.Title | Should -Match "not found"
        }
    }
}

Describe "Module Structure" {
    Context "Module exports" {
        It "Should export expected functions" {
            $expectedFunctions = @(
                'Initialize-ADSHEnvironment',
                'Get-ADSHConfig',
                'New-ADSHFinding',
                'Write-ADSHVerbose',
                'Get-PrivilegedGroupMembership',
                'Get-StaleAccounts',
                'Get-PasswordPolicyAudit',
                'Get-AccountsPasswordNeverExpires',
                'Get-AccountsReversibleEncryption',
                'Get-KerberosDelegationIssues',
                'Get-AdminSDHolderProtectedAccounts',
                'Get-ExcessivePermissionsDelegations',
                'Get-DCReplicationStatus',
                'Get-DNSHealth',
                'Get-SYSVOLReplicationStatus',
                'Get-FSMORoleHolders',
                'Get-DCServiceStatus',
                'Get-ADDatabaseStats',
                'Get-TrustRelationships',
                'Get-GPOReview',
                'Get-PreWin2000AccessRisks',
                'Get-SPNAudit',
                'Get-AuditPolicyVerification',
                'Get-SecurityEventLogConfig',
                'Invoke-ADSecurityHealthCheck'
            )
            
            $module = Get-Module -Name AdSecurityHealth
            foreach ($func in $expectedFunctions) {
                $module.ExportedCommands.Keys | Should -Contain $func
            }
        }
    }
    
    Context "Function documentation" {
        It "All functions should have comment-based help" {
            $functions = @(
                'Initialize-ADSHEnvironment',
                'Get-ADSHConfig',
                'New-ADSHFinding',
                'Write-ADSHVerbose',
                'Invoke-ADSecurityHealthCheck'
            )
            
            foreach ($func in $functions) {
                $help = Get-Help $func
                $help.Synopsis | Should -Not -BeNullOrEmpty
                $help.Description | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe "Integration Tests" {
    Context "Invoke-ADSecurityHealthCheck" {
        It "Should execute without throwing errors when mocked" {
            # Mock all AD cmdlets to prevent actual AD queries
            Mock Initialize-ADSHEnvironment { }
            Mock Get-PrivilegedGroupMembership { return @() }
            Mock Get-StaleAccounts { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-PasswordPolicyAudit { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AccountsPasswordNeverExpires { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AccountsReversibleEncryption { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-KerberosDelegationIssues { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AdminSDHolderProtectedAccounts { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-ExcessivePermissionsDelegations { return @() }
            Mock Get-DCReplicationStatus { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-DNSHealth { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-SYSVOLReplicationStatus { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-FSMORoleHolders { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-DCServiceStatus { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-ADDatabaseStats { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-TrustRelationships { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-GPOReview { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-PreWin2000AccessRisks { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-SPNAudit { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AuditPolicyVerification { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-SecurityEventLogConfig { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            
            { Invoke-ADSecurityHealthCheck } | Should -Not -Throw
        }
        
        It "Should return an array of findings" {
            Mock Initialize-ADSHEnvironment { }
            Mock Get-PrivilegedGroupMembership { return @() }
            Mock Get-StaleAccounts { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-PasswordPolicyAudit { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AccountsPasswordNeverExpires { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AccountsReversibleEncryption { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-KerberosDelegationIssues { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AdminSDHolderProtectedAccounts { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-ExcessivePermissionsDelegations { return @() }
            Mock Get-DCReplicationStatus { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-DNSHealth { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-SYSVOLReplicationStatus { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-FSMORoleHolders { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-DCServiceStatus { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-ADDatabaseStats { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-TrustRelationships { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-GPOReview { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-PreWin2000AccessRisks { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-SPNAudit { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-AuditPolicyVerification { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            Mock Get-SecurityEventLogConfig { return New-ADSHFinding -Category "Test" -Id "TEST" -Severity "Info" -Title "Test" }
            
            $result = Invoke-ADSecurityHealthCheck
            $result | Should -Not -BeNullOrEmpty
            $result.GetType().BaseType.Name | Should -Be "Array"
        }
    }
}
