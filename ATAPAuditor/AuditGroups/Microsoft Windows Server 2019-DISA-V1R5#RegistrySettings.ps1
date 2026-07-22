[AuditTest] @{
    Id = "V-92961"
    Task = "Windows Server 2019 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "InactivityTimeoutSecs" `
                | Select-Object -ExpandProperty "InactivityTimeoutSecs"
        
            if (($regValue -gt 900 -or $regValue -eq 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x <= 900 and x != 0"
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
    Id = "V-92971"
    Task = "Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fEncryptRPCTraffic" `
                | Select-Object -ExpandProperty "fEncryptRPCTraffic"
        
            if ($regValue -ne 1) {
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
    Id = "V-92973"
    Task = "Windows Server 2019 Remote Desktop Services must be configured with the client connection encryption set to High Level."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MinEncryptionLevel" `
                | Select-Object -ExpandProperty "MinEncryptionLevel"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id = "V-93045"
    Task = "Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone systems."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RestrictRemoteSAM" `
                | Select-Object -ExpandProperty "RestrictRemoteSAM"
        
            if ($regValue -ne "O:BAG:BAD:(A;;RC;;;BA)") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: O:BAG:BAD:(A;;RC;;;BA)"
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
    Id = "V-93147"
    Task = "Windows Server 2019 required legal notice must be configured to display before console logon."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "LegalNoticeText" `
                | Select-Object -ExpandProperty "LegalNoticeText"
        
            if ($regValue -ne "See message text below") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: See message text below"
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
    Id = "V-93149"
    Task = "Windows Server 2019 title for legal banner dialog box must be configured with the appropriate text."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "LegalNoticeCaption" `
                | Select-Object -ExpandProperty "LegalNoticeCaption"
        
            if ($regValue -ne "See message title options below") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: See message title options below"
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
    Id = "V-93151"
    Task = "Windows Server 2019 must force audit policy subcategory settings to override audit policy category settings."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "SCENoApplyLegacyAuditPolicy" `
                | Select-Object -ExpandProperty "SCENoApplyLegacyAuditPolicy"
        
            if ($regValue -ne 1) {
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
    Id = "V-93173"
    Task = "Windows Server 2019 command line data must be included in process creation events."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
                -Name "ProcessCreationIncludeCmdLine_Enabled" `
                | Select-Object -ExpandProperty "ProcessCreationIncludeCmdLine_Enabled"
        
            if ($regValue -ne 1) {
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
    Id = "V-93175"
    Task = "Windows Server 2019 PowerShell script block logging must be enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                -Name "EnableScriptBlockLogging" `
                | Select-Object -ExpandProperty "EnableScriptBlockLogging"
        
            if ($regValue -ne 1) {
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
    Id = "V-93177"
    Task = "Windows Server 2019 Application event log size must be configured to 32768 KB or greater."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
                -Name "MaxSize" `
                | Select-Object -ExpandProperty "MaxSize"
        
            if (($regValue -lt 32768)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x >= 32768"
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
    Id = "V-93179"
    Task = "Windows Server 2019 Security event log size must be configured to 196608 KB or greater."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
                -Name "MaxSize" `
                | Select-Object -ExpandProperty "MaxSize"
        
            if (($regValue -lt 196608)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x >= 196608"
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
    Id = "V-93181"
    Task = "Windows Server 2019 System event log size must be configured to 32768 KB or greater."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
                -Name "MaxSize" `
                | Select-Object -ExpandProperty "MaxSize"
        
            if (($regValue -lt 32768)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x >= 32768"
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
    Id = "V-93199"
    Task = "Windows Server 2019 must prevent users from changing installation options."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                -Name "EnableUserControl" `
                | Select-Object -ExpandProperty "EnableUserControl"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93201"
    Task = "Windows Server 2019 must disable the Windows Installer Always install with elevated privileges option."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                -Name "AlwaysInstallElevated" `
                | Select-Object -ExpandProperty "AlwaysInstallElevated"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93233"
    Task = "Windows Server 2019 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
                -Name "DisableIPSourceRouting" `
                | Select-Object -ExpandProperty "DisableIPSourceRouting"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2"
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
    Id = "V-93235"
    Task = "Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
                -Name "DisableIPSourceRouting" `
                | Select-Object -ExpandProperty "DisableIPSourceRouting"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2"
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
    Id = "V-93237"
    Task = "Windows Server 2019 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
                -Name "EnableICMPRedirect" `
                | Select-Object -ExpandProperty "EnableICMPRedirect"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93239"
    Task = "Windows Server 2019 insecure logons to an SMB server must be disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "AllowInsecureGuestAuth" `
                | Select-Object -ExpandProperty "AllowInsecureGuestAuth"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93243"
    Task = "Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
                -Name "AllowProtectedCreds" `
                | Select-Object -ExpandProperty "AllowProtectedCreds"
        
            if ($regValue -ne 1) {
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
    Id = "V-93249"
    Task = "Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
                -Name "DriverLoadPolicy" `
                | Select-Object -ExpandProperty "DriverLoadPolicy"
        
            if (($regValue -ne 1) -and ($regValue -ne 3) -and ($regValue -ne 8)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 1 or x == 3 or x == 8"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93251"
    Task = "Windows Server 2019 group policy objects must be reprocessed even if they have not changed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" `
                -Name "NoGPOListChanges" `
                | Select-Object -ExpandProperty "NoGPOListChanges"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93253"
    Task = "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (on battery)."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
                -Name "DCSettingIndex" `
                | Select-Object -ExpandProperty "DCSettingIndex"
        
            if ($regValue -ne 1) {
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
    Id = "V-93255"
    Task = "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (plugged in)."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
                -Name "ACSettingIndex" `
                | Select-Object -ExpandProperty "ACSettingIndex"
        
            if ($regValue -ne 1) {
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
    Id = "V-93261"
    Task = "Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
                -Name "NoHeapTerminationOnCorruption" `
                | Select-Object -ExpandProperty "NoHeapTerminationOnCorruption"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93263"
    Task = "Windows Server 2019 File Explorer shell protocol must run in protected mode."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "PreXPSP2ShellProtocolBehavior" `
                | Select-Object -ExpandProperty "PreXPSP2ShellProtocolBehavior"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93265"
    Task = "Windows Server 2019 must prevent attachments from being downloaded from RSS feeds."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" `
                -Name "DisableEnclosureDownload" `
                | Select-Object -ExpandProperty "DisableEnclosureDownload"
        
            if ($regValue -ne 1) {
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
    Id = "V-93267"
    Task = "Windows Server 2019 users must be notified if a web-based program attempts to install software."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                -Name "SafeForScripting" `
                | Select-Object -ExpandProperty "SafeForScripting"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93269"
    Task = "Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "DisableAutomaticRestartSignOn" `
                | Select-Object -ExpandProperty "DisableAutomaticRestartSignOn"
        
            if ($regValue -ne 1) {
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
    Id = "V-93273"
    Task = "Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller"}
    )
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RefusePasswordChange" `
                | Select-Object -ExpandProperty "RefusePasswordChange"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93279"
    Task = "Windows Server 2019 must prevent local accounts with blank passwords from being used from the network."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "LimitBlankPasswordUse" `
                | Select-Object -ExpandProperty "LimitBlankPasswordUse"
        
            if ($regValue -ne 1) {
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
    Id = "V-93285"
    Task = "Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "MaximumPasswordAge" `
                | Select-Object -ExpandProperty "MaximumPasswordAge"
        
            if (($regValue -gt 30 -or $regValue -eq 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x <= 30 and x != 0"
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
    Id = "V-93291"
    Task = "Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RestrictAnonymousSAM" `
                | Select-Object -ExpandProperty "RestrictAnonymousSAM"
        
            if ($regValue -ne 1) {
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
    Id = "V-93293"
    Task = "Windows Server 2019 must be configured to prevent anonymous users from having the same permissions as the Everyone group."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "EveryoneIncludesAnonymous" `
                | Select-Object -ExpandProperty "EveryoneIncludesAnonymous"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93295"
    Task = "Windows Server 2019 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" `
                -Name "UseMachineId" `
                | Select-Object -ExpandProperty "UseMachineId"
        
            if ($regValue -ne 1) {
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
    Id = "V-93297"
    Task = "Windows Server 2019 must prevent NTLM from falling back to a Null session."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
                -Name "allownullsessionfallback" `
                | Select-Object -ExpandProperty "allownullsessionfallback"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93299"
    Task = "Windows Server 2019 must prevent PKU2U authentication using online identities."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\pku2u" `
                -Name "AllowOnlineID" `
                | Select-Object -ExpandProperty "AllowOnlineID"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93301"
    Task = "Windows Server 2019 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "LmCompatibilityLevel" `
                | Select-Object -ExpandProperty "LmCompatibilityLevel"
        
            if ($regValue -ne 5) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 5"
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
    Id = "V-93303"
    Task = "Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" `
                -Name "LDAPClientIntegrity" `
                | Select-Object -ExpandProperty "LDAPClientIntegrity"
        
            if ($regValue -ne 1) {
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
    Id = "V-93305"
    Task = "Windows Server 2019 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "NTLMMinClientSec" `
                | Select-Object -ExpandProperty "NTLMMinClientSec"
        
            if ($regValue -ne 537395200) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 537395200"
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
    Id = "V-93307"
    Task = "Windows Server 2019 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "NTLMMinServerSec" `
                | Select-Object -ExpandProperty "NTLMMinServerSec"
        
            if ($regValue -ne 537395200) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 537395200"
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
    Id = "V-93309"
    Task = "Windows Server 2019 default permissions of global system objects must be strengthened."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" `
                -Name "ProtectionMode" `
                | Select-Object -ExpandProperty "ProtectionMode"
        
            if ($regValue -ne 1) {
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
    Id = "V-93311"
    Task = "Windows Server 2019 must preserve zone information when saving attachments."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
                -Name "SaveZoneInformation" `
                | Select-Object -ExpandProperty "SaveZoneInformation"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93373"
    Task = "Windows Server 2019 Autoplay must be turned off for non-volume devices."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
                -Name "NoAutoplayfornonVolume" `
                | Select-Object -ExpandProperty "NoAutoplayfornonVolume"
        
            if ($regValue -ne 1) {
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
    Id = "V-93375"
    Task = "Windows Server 2019 default AutoRun behavior must be configured to prevent AutoRun commands."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoAutorun" `
                | Select-Object -ExpandProperty "NoAutorun"
        
            if ($regValue -ne 1) {
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
    Id = "V-93377"
    Task = "Windows Server 2019 AutoPlay must be disabled for all drives."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" `
                -Name "NoDriveTypeAutoRun" `
                | Select-Object -ExpandProperty "NoDriveTypeAutoRun"
        
            if ($regValue -ne 255) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 255"
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
    Id = "V-93393"
    Task = "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                -Name "SMB1" `
                | Select-Object -ExpandProperty "SMB1"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93395"
    Task = "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
                -Name "Start" `
                | Select-Object -ExpandProperty "Start"
        
            if ($regValue -ne 4) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 4"
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
    Id = "V-93399"
    Task = "Windows Server 2019 must prevent the display of slide shows on the lock screen."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
                -Name "NoLockScreenSlideshow" `
                | Select-Object -ExpandProperty "NoLockScreenSlideshow"
        
            if ($regValue -ne 1) {
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
    Id = "V-93401"
    Task = "Windows Server 2019 must have WDigest Authentication disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" `
                -Name "UseLogonCredential" `
                | Select-Object -ExpandProperty "UseLogonCredential"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93403"
    Task = "Windows Server 2019 downloading print driver packages over HTTP must be turned off."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
                -Name "DisableWebPnPDownload" `
                | Select-Object -ExpandProperty "DisableWebPnPDownload"
        
            if ($regValue -ne 1) {
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
    Id = "V-93405"
    Task = "Windows Server 2019 printing over HTTP must be turned off."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
                -Name "DisableHTTPPrinting" `
                | Select-Object -ExpandProperty "DisableHTTPPrinting"
        
            if ($regValue -ne 1) {
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
    Id = "V-93407"
    Task = "Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "DontDisplayNetworkSelectionUI" `
                | Select-Object -ExpandProperty "DontDisplayNetworkSelectionUI"
        
            if ($regValue -ne 1) {
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
    Id = "V-93409"
    Task = "Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."
    Test = {
        try {
            $status = get-service -name pcasvc -ErrorAction Stop
            if($status.Status -ne "Stopped"){
                return @{
                    Message = "Compliant - AppCompat Service is disabled (no inventory data will be collected)."
                    Status = "True"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" `
                -Name "DisableInventory" `
                | Select-Object -ExpandProperty "DisableInventory"
        
            if ($regValue -ne 1) {
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
        catch [System.SystemException]{
            return @{
                Message = "Service not found!"
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93411"
    Task = "Windows Server 2019 Windows Defender SmartScreen must be enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "EnableSmartScreen" `
                | Select-Object -ExpandProperty "EnableSmartScreen"
        
            if ($regValue -ne 1) {
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
    Id = "V-93413"
    Task = "Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" `
                -Name "AllowBasicAuthInClear" `
                | Select-Object -ExpandProperty "AllowBasicAuthInClear"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "V-93415"
    Task = "Windows Server 2019 must prevent Indexing of encrypted files."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
                -Name "AllowIndexingEncryptedStoresOrItems" `
                | Select-Object -ExpandProperty "AllowIndexingEncryptedStoresOrItems"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93419"
    Task = "Windows Server 2019 local users on domain-joined member servers must not be enumerated."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "EnumerateLocalUsers" `
                | Select-Object -ExpandProperty "EnumerateLocalUsers"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93425"
    Task = "Windows Server 2019 must not save passwords in the Remote Desktop Client."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "DisablePasswordSaving" `
                | Select-Object -ExpandProperty "DisablePasswordSaving"
        
            if ($regValue -ne 1) {
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
    Id = "V-93427"
    Task = "Windows Server 2019 Remote Desktop Services must always prompt a client for passwords upon connection."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fPromptForPassword" `
                | Select-Object -ExpandProperty "fPromptForPassword"
        
            if ($regValue -ne 1) {
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
    Id = "V-93429"
    Task = "Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "DisableRunAs" `
                | Select-Object -ExpandProperty "DisableRunAs"
        
            if ($regValue -ne 1) {
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
    Id = "V-93431"
    Task = "Windows Server 2019 User Account Control approval mode for the built-in Administrator must be enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "FilterAdministratorToken" `
                | Select-Object -ExpandProperty "FilterAdministratorToken"
        
            if ($regValue -ne 1) {
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
    Id = "V-93433"
    Task = "Windows Server 2019 User Account Control must automatically deny standard user requests for elevation."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorUser" `
                | Select-Object -ExpandProperty "ConsentPromptBehaviorUser"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93435"
    Task = "Windows Server 2019 User Account Control must run all administrators in Admin Approval Mode, enabling UAC."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableLUA" `
                | Select-Object -ExpandProperty "EnableLUA"
        
            if ($regValue -ne 1) {
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
    Id = "V-93453"
    Task = "Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server" }
    )
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                -Name "RestrictRemoteClients" `
                | Select-Object -ExpandProperty "RestrictRemoteClients"
        
            if ($regValue -ne 1) {
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
    Id = "V-93455"
    Task = "Windows Server 2019 computer account password must not be prevented from being reset."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "DisablePasswordChange" `
                | Select-Object -ExpandProperty "DisablePasswordChange"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93467"
    Task = "Windows Server 2019 must be configured to prevent the storage of the LAN Manager hash of passwords."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "NoLMHash" `
                | Select-Object -ExpandProperty "NoLMHash"
        
            if ($regValue -ne 1) {
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
    Id = "V-93469"
    Task = "Windows Server 2019 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "EnablePlainTextPassword" `
                | Select-Object -ExpandProperty "EnablePlainTextPassword"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93493"
    Task = "Windows Server 2019 users must be required to enter a password to access private keys stored on the computer."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" `
                -Name "ForceKeyProtection" `
                | Select-Object -ExpandProperty "ForceKeyProtection"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2"
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
    Id = "V-93495"
    Task = "Windows Server 2019 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "SupportedEncryptionTypes" `
                | Select-Object -ExpandProperty "SupportedEncryptionTypes"
        
            if ($regValue -ne 2147483640) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2147483640"
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
    Id = "V-93499"
    Task = "Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowUnencryptedTraffic" `
                | Select-Object -ExpandProperty "AllowUnencryptedTraffic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93501"
    Task = "Windows Server 2019 Windows Remote Management (WinRM) service must not allow unencrypted traffic."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "AllowUnencryptedTraffic" `
                | Select-Object -ExpandProperty "AllowUnencryptedTraffic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93503"
    Task = "Windows Server 2019 Windows Remote Management (WinRM) client must not use Basic authentication."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowBasic" `
                | Select-Object -ExpandProperty "AllowBasic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93505"
    Task = "Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowDigest" `
                | Select-Object -ExpandProperty "AllowDigest"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93507"
    Task = "Windows Server 2019 Windows Remote Management (WinRM) service must not use Basic authentication."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "AllowBasic" `
                | Select-Object -ExpandProperty "AllowBasic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93511"
    Task = "Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
            if ($regValue -ne 1) {
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
    Id = "V-93517"
    Task = "Windows Server 2019 administrator accounts must not be enumerated during elevation."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
                -Name "EnumerateAdministrators" `
                | Select-Object -ExpandProperty "EnumerateAdministrators"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93519"
    Task = "Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "LocalAccountTokenFilterPolicy" `
                | Select-Object -ExpandProperty "LocalAccountTokenFilterPolicy"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93521"
    Task = "Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableUIADesktopToggle" `
                | Select-Object -ExpandProperty "EnableUIADesktopToggle"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
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
    Id = "V-93525"
    Task = "Windows Server 2019 User Account Control must be configured to detect application installations and prompt for elevation."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableInstallerDetection" `
                | Select-Object -ExpandProperty "EnableInstallerDetection"
        
            if ($regValue -ne 1) {
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
    Id = "V-93527"
    Task = "Windows Server 2019 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableSecureUIAPaths" `
                | Select-Object -ExpandProperty "EnableSecureUIAPaths"
        
            if ($regValue -ne 1) {
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
    Id = "V-93529"
    Task = "Windows Server 2019 User Account Control (UAC) must virtualize file and registry write failures to per-user locations."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableVirtualization" `
                | Select-Object -ExpandProperty "EnableVirtualization"
        
            if ($regValue -ne 1) {
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
    Id = "V-93533"
    Task = "Windows Server 2019 Remote Desktop Services must prevent drive redirection."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableCdm" `
                | Select-Object -ExpandProperty "fDisableCdm"
        
            if ($regValue -ne 1) {
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
    Id = "V-93537"
    Task = "Windows Server 2019 must not allow anonymous enumeration of shares."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RestrictAnonymous" `
                | Select-Object -ExpandProperty "RestrictAnonymous"
        
            if ($regValue -ne 1) {
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
    Id = "V-93539"
    Task = "Windows Server 2019 must restrict anonymous access to Named Pipes and Shares."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "RestrictNullSessAccess" `
                | Select-Object -ExpandProperty "RestrictNullSessAccess"
        
            if ($regValue -ne 1) {
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
    Id = "V-93541"
    Task = "Windows Server 2019 must be configured to ignore NetBIOS name release requests except from WINS servers."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" `
                -Name "NoNameReleaseOnDemand" `
                | Select-Object -ExpandProperty "NoNameReleaseOnDemand"
        
            if ($regValue -ne 1) {
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
    Id = "V-93545"
    Task = "Windows Server 2019 domain controllers must require LDAP access signing."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller"}
    )
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
                -Name "LDAPServerIntegrity" `
                | Select-Object -ExpandProperty "LDAPServerIntegrity"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2"
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
    Id = "V-93547"
    Task = "Windows Server 2019 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RequireSignOrSeal" `
                | Select-Object -ExpandProperty "RequireSignOrSeal"
        
            if ($regValue -ne 1) {
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
    Id = "V-93549"
    Task = "Windows Server 2019 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "SealSecureChannel" `
                | Select-Object -ExpandProperty "SealSecureChannel"
        
            if ($regValue -ne 1) {
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
    Id = "V-93551"
    Task = "Windows Server 2019 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "SignSecureChannel" `
                | Select-Object -ExpandProperty "SignSecureChannel"
        
            if ($regValue -ne 1) {
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
    Id = "V-93553"
    Task = "Windows Server 2019 must be configured to require a strong session key."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RequireStrongKey" `
                | Select-Object -ExpandProperty "RequireStrongKey"
        
            if ($regValue -ne 1) {
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
    Id = "V-93555"
    Task = "Windows Server 2019 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."
    Test = {
        try {
            if((Get-SmbClientConfiguration).RequireSecuritySignature -ne $True){
                return @{
                    Message = "RequireSecuritySignature is not set to True"
                    Status = "False"
                }
            }
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        catch {
            try{
                $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "RequireSecuritySignature" `
                | Select-Object -ExpandProperty "RequireSecuritySignature"
                
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
                        Status = "False"
                    }
                }
                return @{
                    Message = "Compliant"
                    Status = "True"
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
        }
    }
}
[AuditTest] @{
    Id = "V-93557"
    Task = "Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled."
    Test = {
        try {
            if((Get-SmbClientConfiguration).EnableSecuritySignature -ne $True){
                return @{
                    Message = "EnableSecuritySignature is not set to True"
                    Status = "False"
                }
            }
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        catch {
            try{
                $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "EnableSecuritySignature" `
                | Select-Object -ExpandProperty "EnableSecuritySignature"
                
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
                        Status = "False"
                    }
                }
                return @{
                    Message = "Compliant"
                    Status = "True"
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
        }
    }
}
[AuditTest] @{
    Id = "V-93559"
    Task = "Windows Server 2019 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."
    Test = {
        try {
            if((Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature -ne $True){
                return @{
                    Message = "RequireSecuritySignature is not set to True"
                    Status = "False"
                }
            }
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        catch {
                       try{
                $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "RequireSecuritySignature" `
                | Select-Object -ExpandProperty "RequireSecuritySignature"
                
                return @{
                    Message = "Registry value is '$regValue'. Get-SMBServerConfiguration failed, resorted to checking registry, which might not be 100% accurate. See <a href=`"https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing#policy-locations-for-smb-signing`" target='_blank'>here</a> and <a href=`"https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-insider/ba-p/3831704`" target='_blank'>here</a>"
                    Status = "Warning"
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
        }
    }
}
[AuditTest] @{
    Id = "V-93561"
    Task = "Windows Server 2019 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."
    Test = {
        try {
            if((Get-SmbServerConfiguration -ErrorAction Stop).EnableSecuritySignature -ne $True){
                return @{
                    Message = "EnableSecuritySignature is not set to True"
                    Status = "False"
                }
            }
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        catch {
            try{
                $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "EnableSecuritySignature" `
                | Select-Object -ExpandProperty "EnableSecuritySignature"
                
                return @{
                    Message = "Registry value is '$regValue'. Get-SMBServerConfiguration failed, resorted to checking registry, which might not be 100% accurate. See <a href=`"https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing#policy-locations-for-smb-signing`" target='_blank'>here</a> and <a href=`"https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-insider/ba-p/3831704`" target='_blank'>here</a>"
                    Status = "Warning"
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
        }
    }
}
[AuditTest] @{
    Id = "V-93563"
    Task = "Windows Server 2019 Explorer Data Execution Prevention must be enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
                -Name "NoDataExecutionPrevention" `
                | Select-Object -ExpandProperty "NoDataExecutionPrevention"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
