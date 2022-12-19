$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
. "$RootPath\Helpers\Firewall.ps1"
[AuditTest] @{
    Id   = "1.1.7"
    Task = "(L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["ClearTextPassword"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status  = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if ($setPolicy -ne 0) {
            return @{
                Message = "'ClearTextPassword' currently set to: $setPolicy. Expected: 0"
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.38"
    Task = "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSecurityPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSecurityPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSecurityPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status  = "False"
                Message = $message
            }
        }
        
        return @{
            Status  = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.5.2"
    Task = "(L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController", "BackupDomainController" }
    )
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters" `
                -Name "LDAPServerIntegrity" `
            | Select-Object -ExpandProperty "LDAPServerIntegrity"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.11.4"
    Task = "(L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "SupportedEncryptionTypes" `
            | Select-Object -ExpandProperty "SupportedEncryptionTypes"
        
            if (($regValue -ne 2147483644) -and ($regValue -ne 2147483640)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 2147483644 or x == 2147483640"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.11.5"
    Task = "(L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "NoLMHash" `
            | Select-Object -ExpandProperty "NoLMHash"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "7.9 A"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled (RC4 40/128)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" `
                -Name "Enabled" `
            | Select-Object -ExpandProperty "Enabled"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "7.9 B"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled (RC4 56/128)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" `
                -Name "Enabled" `
            | Select-Object -ExpandProperty "Enabled"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "7.9 C"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled (RC4 64/128)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" `
                -Name "Enabled" `
            | Select-Object -ExpandProperty "Enabled"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "7.9 D"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled (RC4 128/128)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" `
                -Name "Enabled" `
            | Select-Object -ExpandProperty "Enabled"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "9.1.7"
    Task = "(L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"      
        $key = "LogDroppedPackets"
        $expectedValue = 1;
        $profileType = "Domain"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id   = "9.1.8"
    Task = "(L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"      
        $key = "LogSuccessfulConnections"
        $expectedValue = 1;
        $profileType = "Domain"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}



[AuditTest] @{
    Id   = "18.3.3"
    Task = "(L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
                -Name "Start" `
            | Select-Object -ExpandProperty "Start"
        
            if ($regValue -ne 4) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 4"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "18.3.3"
    Task = "(L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                -Name "SMB1" `
            | Select-Object -ExpandProperty "SMB1"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}



[AuditTest] @{
    Id   = "18.3.6"
    Task = "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
                -Name "UseLogonCredential" `
            | Select-Object -ExpandProperty "UseLogonCredential"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}

[AuditTest] @{
    Id   = "18.6.2"
    Task = "(L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
                -Name "NoWarningNoElevationOnInstall" `
            | Select-Object -ExpandProperty "NoWarningNoElevationOnInstall"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "18.6.3"
    Task = "(L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
                -Name "UpdatePromptSettings" `
            | Select-Object -ExpandProperty "UpdatePromptSettings"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "18.9.47.9.2"
    Task = "(L1) Ensure 'Turn off real-time protection' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableRealtimeMonitoring" `
            | Select-Object -ExpandProperty "DisableRealtimeMonitoring"
        
            if ($regValue -eq 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 A"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Office communication application  from creating child processes)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "26190899-1602-49e8-8b27-eb1d0a1ce869"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "26190899-1602-49e8-8b27-eb1d0a1ce869"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 B"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured  (Block Office applications from creating  executable content)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "3b576869-a4ec-4529-8536-b80a7769e899"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "3b576869-a4ec-4529-8536-b80a7769e899"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 C"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block execution of potentially obfuscated scripts)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" 

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" 

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 D"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Block Office applications from injecting code into other processes' is configured"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 E"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured  (Block Adobe Reader from creating child processes)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 F"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured  (Block Win32 API calls from Office macro)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 G"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block credential stealing from the Windows local security authority subsystem (lsass.exe))"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 H"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block untrusted and unsigned processes that run from USB)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 I"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured  (Block executable content from email client and webmail)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 J"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block JavaScript or VBScript from launching downloaded executable content)"
    Test = {
       try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "d3e037e1-3eb8-44c8-a917-57927947596d"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "d3e037e1-3eb8-44c8-a917-57927947596d"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 K"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Office applications from creating child processes)"
    Test = {
        try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "18.9.47.5.1.2 L"
    Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block persistence through WMI event subscription)"
    Test = {
            try {
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                return @{
                    Message = "ASR rules require Windows Defender Antivirus to be enabled."
                    Status = "False"
                }
            }                     
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "e6db77e5-3df2-4cf1-b95a-636979351e5b"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "e6db77e5-3df2-4cf1-b95a-636979351e5b"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if($asrTest2){
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                    | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id   = "18.9.58.3.10.1"
    Task = "(L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxIdleTime" `
            | Select-Object -ExpandProperty "MaxIdleTime"
        
            if (($regValue -gt 900000 -or $regValue -eq 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x <= 900000 and x != 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "18.9.58.3.10.2"
    Task = "(L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxDisconnectionTime" `
            | Select-Object -ExpandProperty "MaxDisconnectionTime"
        
            if ($regValue -ne 60000) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 60000"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}