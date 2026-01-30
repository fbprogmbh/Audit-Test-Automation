$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$avstatus = CheckForActiveAV
$windefrunning = CheckWindefRunning
. "$RootPath\Helpers\Firewall.ps1"
[AuditTest] @{
    Id   = "Registry-001"
    Task = "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" `
                -Name "AutoConnectAllowedOEM" `
            | Select-Object -ExpandProperty "AutoConnectAllowedOEM"
        
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
    Id   = "Registry-002"
    Task = "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
                -Name "EnumerateAdministrators" `
            | Select-Object -ExpandProperty "EnumerateAdministrators"
        
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
    Id   = "Registry-003"
    Task = "Ensure 'Turn off Autoplay' is set to 'All drives'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoDriveTypeAutoRun" `
            | Select-Object -ExpandProperty "NoDriveTypeAutoRun"
        
            if ($regValue -ne 255) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 255"
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
    Id   = "Registry-004"
    Task = "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoWebServices" `
            | Select-Object -ExpandProperty "NoWebServices"
        
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
    Id   = "Registry-005"
    Task = "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoAutorun" `
            | Select-Object -ExpandProperty "NoAutorun"
        
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
    Id   = "Registry-006"
    Task = "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "MSAOptional" `
            | Select-Object -ExpandProperty "MSAOptional"
        
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
    Id   = "Registry-007"
    Task = "Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "DisableAutomaticRestartSignOn" `
            | Select-Object -ExpandProperty "DisableAutomaticRestartSignOn"
        
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
    Id   = "Registry-008"
    Task = "Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "LocalAccountTokenFilterPolicy" `
            | Select-Object -ExpandProperty "LocalAccountTokenFilterPolicy"
        
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
    Id   = "Registry-009"
    Task = "Ensure 'Enable MPR notifications for the system' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableMPR" `
            | Select-Object -ExpandProperty "EnableMPR"
        
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
    Id   = "Registry-010"
    Task = "Ensure 'Encryption Oracle Remediation' is set to 'Force Updated Clients'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" `
                -Name "AllowEncryptionOracle" `
            | Select-Object -ExpandProperty "AllowEncryptionOracle"
        
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
    Id   = "Registry-011"
    Task = "Ensure 'Configure enhanced anti-spoofing' set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" `
                -Name "EnhancedAntiSpoofing" `
            | Select-Object -ExpandProperty "EnhancedAntiSpoofing"
        
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
    Id   = "Registry-012"
    Task = "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds" `
                -Name "DisableEnclosureDownload" `
            | Select-Object -ExpandProperty "DisableEnclosureDownload"
        
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
    Id   = "Registry-013"
    Task = "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
                -Name "DCSettingIndex" `
            | Select-Object -ExpandProperty "DCSettingIndex"
        
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
    Id   = "Registry-014"
    Task = "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
                -Name "ACSettingIndex" `
            | Select-Object -ExpandProperty "ACSettingIndex"
        
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
    Id   = "Registry-015"
    Task = "Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Force Deny'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" `
                -Name "LetAppsActivateWithVoiceAboveLock" `
            | Select-Object -ExpandProperty "LetAppsActivateWithVoiceAboveLock"
        
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
    Id   = "Registry-016"
    Task = "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableWindowsConsumerFeatures" `
            | Select-Object -ExpandProperty "DisableWindowsConsumerFeatures"
        
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
    Id   = "Registry-017"
    Task = "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation" `
                -Name "AllowProtectedCreds" `
            | Select-Object -ExpandProperty "AllowProtectedCreds"
        
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
    Id   = "Registry-018"
    Task = "Ensure 'Specify the maximum log file size (KB)' is set to '32768' (Application)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application" `
                -Name "MaxSize" `
            | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 32768) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 32768"
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
    Id   = "Registry-019"
    Task = "Ensure 'Specify the maximum log file size (KB)' is set to '196608' (Security)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security" `
                -Name "MaxSize" `
            | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 196608) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 196608"
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
    Id   = "Registry-020"
    Task = "Ensure 'Specify the maximum log file size (KB)' is set to '32768' (System)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System" `
                -Name "MaxSize" `
            | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 32768) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 32768"
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
    Id   = "Registry-021"
    Task = "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" `
                -Name "NoAutoplayfornonVolume" `
            | Select-Object -ExpandProperty "NoAutoplayfornonVolume"
        
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
    Id   = "Registry-022"
    Task = "Ensure 'Windows Game Recording and Broadcasting' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameDVR" `
                -Name "AllowGameDVR" `
            | Select-Object -ExpandProperty "AllowGameDVR"
        
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
    Id   = "Registry-023"
    Task = "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" `
                -Name "NoGPOListChanges" `
            | Select-Object -ExpandProperty "NoGPOListChanges"
        
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
    Id   = "Registry-024"
    Task = "Ensure 'Configure registry policy processing' is set to '0'. (NoBackgroundPolicy)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" `
                -Name "NoBackgroundPolicy" `
            | Select-Object -ExpandProperty "NoBackgroundPolicy"
        
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
    Id   = "Registry-025"
    Task = "Ensure 'Always install with elevated privileges' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" `
                -Name "AlwaysInstallElevated" `
            | Select-Object -ExpandProperty "AlwaysInstallElevated"
        
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
    Id   = "Registry-026"
    Task = "Ensure 'Allow user control over installs' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" `
                -Name "EnableUserControl" `
            | Select-Object -ExpandProperty "EnableUserControl"
        
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
    Id   = "Registry-027"
    Task = "Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Block all'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection" `
                -Name "DeviceEnumerationPolicy" `
            | Select-Object -ExpandProperty "DeviceEnumerationPolicy"
        
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
    Id   = "Registry-028"
    Task = "Ensure 'Enable insecure guest logons' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "AllowInsecureGuestAuth" `
            | Select-Object -ExpandProperty "AllowInsecureGuestAuth"
        
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
    Id   = "Registry-029"
    Task = "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections" `
                -Name "NC_ShowSharedAccessUI" `
            | Select-Object -ExpandProperty "NC_ShowSharedAccessUI"
        
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
    Id   = "Registry-030"
    Task = "Set registry value '\\*\SYSVOL' to RequireMutualAuthentication=1, RequireIntegrity=1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
                -Name "\\*\SYSVOL" `
            | Select-Object -ExpandProperty "\\*\SYSVOL"
        
            if ( -not($regValue -match "RequireMutualAuthentication=1" -and $regValue -match "RequireIntegrity=1")) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: RequireMutualAuthentication=1, RequireIntegrity=1"
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
    Id   = "Registry-031"
    Task = "Set registry value '\\*\NETLOGON' to RequireMutualAuthentication=1, RequireIntegrity=1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
                -Name "\\*\NETLOGON" `
            | Select-Object -ExpandProperty "\\*\NETLOGON"
        
            if ( -not($regValue -match "RequireMutualAuthentication=1" -and $regValue -match "RequireIntegrity=1")) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: RequireMutualAuthentication=1, RequireIntegrity=1"
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
    Id   = "Registry-032"
    Task = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" `
                -Name "NoLockScreenCamera" `
            | Select-Object -ExpandProperty "NoLockScreenCamera"
        
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
    Id   = "Registry-033"
    Task = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" `
                -Name "NoLockScreenSlideshow" `
            | Select-Object -ExpandProperty "NoLockScreenSlideshow"
        
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
    Id   = "Registry-034"
    Task = "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                -Name "EnableScriptBlockLogging" `
            | Select-Object -ExpandProperty "EnableScriptBlockLogging"
        
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
    Id   = "Registry-035"
    Task = "Ensure 'Turn on PowerShell Script Block Logging' is not set."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                -Name "EnableScriptBlockInvocationLogging" `
            | Select-Object -ExpandProperty "EnableScriptBlockInvocationLogging"
        
            return @{
                Message = "Registry value found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status  = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status  = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "Registry-036"
    Task = "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "AllowDomainPINLogon" `
            | Select-Object -ExpandProperty "AllowDomainPINLogon"
        
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
    Id   = "Registry-037"
    Task = "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "EnumerateLocalUsers" `
            | Select-Object -ExpandProperty "EnumerateLocalUsers"
        
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
    Id   = "Registry-038"
    Task = "Ensure 'Configure Windows SmartScreen' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "EnableSmartScreen" `
            | Select-Object -ExpandProperty "EnableSmartScreen"
        
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
    Id   = "Registry-039"
    Task = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Block'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "ShellSmartScreenLevel" `
            | Select-Object -ExpandProperty "ShellSmartScreenLevel"
        
            if ($regValue -ne "Block") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: Block"
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
    Id   = "Registry-040"
    Task = "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "AllowCustomSSPsAPs" `
            | Select-Object -ExpandProperty "AllowCustomSSPsAPs"
        
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
    Id   = "Registry-041"
    Task = "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
                -Name "fBlockNonDomain" `
            | Select-Object -ExpandProperty "fBlockNonDomain"
        
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
    Id   = "Registry-042"
    Task = "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" `
                -Name "AllowIndexingEncryptedStoresOrItems" `
            | Select-Object -ExpandProperty "AllowIndexingEncryptedStoresOrItems"
        
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
    Id   = "Registry-043"
    Task = "Ensure 'Disallow Digest authentication' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowDigest" `
            | Select-Object -ExpandProperty "AllowDigest"
        
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
    Id   = "Registry-044"
    Task = "Ensure 'Allow unencrypted traffic' is set to 'Disabled'. (Client)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowUnencryptedTraffic" `
            | Select-Object -ExpandProperty "AllowUnencryptedTraffic"
        
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
    Id   = "Registry-045"
    Task = "Ensure 'Allow Basic authentication' is set to 'Disabled'. (Client)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowBasic" `
            | Select-Object -ExpandProperty "AllowBasic"
        
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
    Id   = "Registry-046"
    Task = "Ensure 'Allow unencrypted traffic' is set to 'Disabled'. (Service)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "AllowUnencryptedTraffic" `
            | Select-Object -ExpandProperty "AllowUnencryptedTraffic"
        
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
    Id   = "Registry-047"
    Task = "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'. (Service)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "DisableRunAs" `
            | Select-Object -ExpandProperty "DisableRunAs"
        
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
    Id   = "Registry-048"
    Task = "Ensure 'Allow Basic authentication' is set to 'Disabled'. (Service)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "AllowBasic" `
            | Select-Object -ExpandProperty "AllowBasic"
        
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
    Id   = "Registry-049"
    Task = "Ensure 'Notify Malicious' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "NotifyMalicious" `
            | Select-Object -ExpandProperty "NotifyMalicious"
        
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
    Id   = "Registry-050"
    Task = "Ensure 'Notify Password Reuse' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "NotifyPasswordReuse" `
            | Select-Object -ExpandProperty "NotifyPasswordReuse"
        
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
    Id   = "Registry-051"
    Task = "Ensure 'Notify Unsafe App' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "NotifyUnsafeApp" `
            | Select-Object -ExpandProperty "NotifyUnsafeApp"
        
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
    Id   = "Registry-052"
    Task = "Ensure 'Service Enabled' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "ServiceEnabled" `
            | Select-Object -ExpandProperty "ServiceEnabled"
        
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
    Id   = "Registry-053"
    Task = "Ensure 'Turn off multicast name resolution' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" `
                -Name "EnableMulticast" `
            | Select-Object -ExpandProperty "EnableMulticast"
        
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
    Id   = "Registry-054"
    Task = "Set registry value 'EnableNetBIOS' to 2."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" `
                -Name "EnableNetBIOS" `
            | Select-Object -ExpandProperty "EnableNetBIOS"
        
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
    Id   = "Registry-055"
    Task = "Ensure 'Turn off downloading of print drivers over HTTP' set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" `
                -Name "DisableWebPnPDownload" `
            | Select-Object -ExpandProperty "DisableWebPnPDownload"
        
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
    Id   = "Registry-056"
    Task = "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" `
                -Name "RedirectionGuardPolicy" `
            | Select-Object -ExpandProperty "RedirectionGuardPolicy"
        
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
    Id   = "Registry-057"
    Task = "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
                -Name "CopyFilesPolicy" `
            | Select-Object -ExpandProperty "CopyFilesPolicy"
        
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
    Id   = "Registry-058"
    Task = "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
                -Name "RestrictDriverInstallationToAdministrators" `
            | Select-Object -ExpandProperty "RestrictDriverInstallationToAdministrators"
        
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
    Id   = "Registry-059"
    Task = "Set registry value 'RpcUseNamedPipeProtocol' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcUseNamedPipeProtocol" `
            | Select-Object -ExpandProperty "RpcUseNamedPipeProtocol"
        
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
    Id   = "Registry-060"
    Task = "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcAuthentication" `
            | Select-Object -ExpandProperty "RpcAuthentication"
        
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
    Id   = "Registry-061"
    Task = "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcProtocols" `
            | Select-Object -ExpandProperty "RpcProtocols"
        
            if ($regValue -ne 5) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 5"
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
    Id   = "Registry-062"
    Task = "Set registry value 'ForceKerberosForRpc' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "ForceKerberosForRpc" `
            | Select-Object -ExpandProperty "ForceKerberosForRpc"
        
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
    Id   = "Registry-063"
    Task = "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcTcpPort" `
            | Select-Object -ExpandProperty "RpcTcpPort"
        
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
    Id   = "Registry-064"
    Task = "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Authenticated'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" `
                -Name "RestrictRemoteClients" `
            | Select-Object -ExpandProperty "RestrictRemoteClients"
        
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
    Id   = "Registry-065"
    Task = "Solicited Remote Assistance - Set method for sending email invitations to 'Simple MAPI'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fUseMailto" `
            | Select-Object -ExpandProperty "fUseMailto"
        
            return @{
                Message = "Registry value found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status  = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status  = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "Registry-066"
    Task = "Solicited Remote Assistance must not be allowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fAllowToGetHelp" `
            | Select-Object -ExpandProperty "fAllowToGetHelp"
        
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
    Id   = "Registry-067"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (fAllowFullControl)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fAllowFullControl" `
            | Select-Object -ExpandProperty "fAllowFullControl"
        
            return @{
                Message = "Registry value found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status  = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status  = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "Registry-068"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (MaxTicketExpiry)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxTicketExpiry" `
            | Select-Object -ExpandProperty "MaxTicketExpiry"
        
            return @{
                Message = "Registry value found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status  = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status  = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "Registry-069"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (MaxTicketExpiryUnits)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxTicketExpiryUnits" `
            | Select-Object -ExpandProperty "MaxTicketExpiryUnits"
        
            return @{
                Message = "Registry value found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Compliant. Registry value not found."
                Status  = "True"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Compliant. Registry key not found."
                Status  = "True"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "Registry-070"
    Task = "Ensure 'Set client connection encryption level' is set to 'High Level'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MinEncryptionLevel" `
            | Select-Object -ExpandProperty "MinEncryptionLevel"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-071"
    Task = "Ensure 'Always prompt for password upon connection' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fPromptForPassword" `
            | Select-Object -ExpandProperty "fPromptForPassword"
        
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
    Id   = "Registry-072"
    Task = "Ensure 'Do not allow drive redirection' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableCdm" `
            | Select-Object -ExpandProperty "fDisableCdm"
        
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
    Id   = "Registry-073"
    Task = "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "DisablePasswordSaving" `
            | Select-Object -ExpandProperty "DisablePasswordSaving"
        
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
    Id   = "Registry-074"
    Task = "Ensure 'Require secure RPC communication' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fEncryptRPCTraffic" `
            | Select-Object -ExpandProperty "fEncryptRPCTraffic"
        
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
    Id   = "Registry-076"
    Task = "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "DefaultOutboundAction" `
            | Select-Object -ExpandProperty "DefaultOutboundAction"
        
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
    Id   = "Registry-077"
    Task = "Ensure 'Windows Defender Firewall: Prohibit notifications' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "DisableNotifications" `
            | Select-Object -ExpandProperty "DisableNotifications"
        
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
    Id   = "Registry-078"
    Task = "Ensure 'Windows Defender Firewall: Protect all network connections' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "EnableFirewall" `
            | Select-Object -ExpandProperty "EnableFirewall"
        
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
    Id   = "Registry-079"
    Task = "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "DefaultInboundAction" `
            | Select-Object -ExpandProperty "DefaultInboundAction"
        
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
    Id   = "Registry-080"
    Task = "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
                -Name "LogDroppedPackets" `
            | Select-Object -ExpandProperty "LogDroppedPackets"
        
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
    Id   = "Registry-081"
    Task = "Ensure 'Windows Defender Firewall: Allow logging' is set to '16384' (LogFileSize)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
                -Name "LogFileSize" `
            | Select-Object -ExpandProperty "LogFileSize"
        
            if ($regValue -ne 16384) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 16384"
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
    Id   = "Registry-082"
    Task = "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
                -Name "LogSuccessfulConnections" `
            | Select-Object -ExpandProperty "LogSuccessfulConnections"
        
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
    Id   = "Registry-083"
    Task = "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "EnableFirewall" `
            | Select-Object -ExpandProperty "EnableFirewall"
        
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
    Id   = "Registry-084"
    Task = "Private: Set registry value 'DisableNotifications' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "DisableNotifications" `
            | Select-Object -ExpandProperty "DisableNotifications"
        
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
    Id   = "Registry-085"
    Task = "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "DefaultInboundAction" `
            | Select-Object -ExpandProperty "DefaultInboundAction"
        
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
    Id   = "Registry-086"
    Task = "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "DefaultOutboundAction" `
            | Select-Object -ExpandProperty "DefaultOutboundAction"
        
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
    Id   = "Registry-087"
    Task = "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
                -Name "LogSuccessfulConnections" `
            | Select-Object -ExpandProperty "LogSuccessfulConnections"
        
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
    Id   = "Registry-088"
    Task = "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
                -Name "LogDroppedPackets" `
            | Select-Object -ExpandProperty "LogDroppedPackets"
        
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
    Id   = "Registry-089"
    Task = "Set registry value 'LogFileSize' to 16384."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
                -Name "LogFileSize" `
            | Select-Object -ExpandProperty "LogFileSize"
        
            if ($regValue -ne 16384) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 16384"
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
    Id   = "Registry-090"
    Task = "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "DefaultOutboundAction" `
            | Select-Object -ExpandProperty "DefaultOutboundAction"
        
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
    Id   = "Registry-091"
    Task = "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "EnableFirewall" `
            | Select-Object -ExpandProperty "EnableFirewall"
        
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
    Id   = "Registry-092"
    Task = "Public: Set registry value 'DisableNotifications' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "DisableNotifications" `
            | Select-Object -ExpandProperty "DisableNotifications"
        
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
    Id   = "Registry-093"
    Task = "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "AllowLocalIPsecPolicyMerge" `
            | Select-Object -ExpandProperty "AllowLocalIPsecPolicyMerge"
        
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
    Id   = "Registry-094"
    Task = "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "AllowLocalPolicyMerge" `
            | Select-Object -ExpandProperty "AllowLocalPolicyMerge"
        
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
    Id   = "Registry-095"
    Task = "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "DefaultInboundAction" `
            | Select-Object -ExpandProperty "DefaultInboundAction"
        
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
    Id   = "Registry-096"
    Task = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' set to '16,384'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
                -Name "LogFileSize" `
            | Select-Object -ExpandProperty "LogFileSize"
        
            if ($regValue -ne 16384) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 16384"
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
    Id   = "Registry-097"
    Task = "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
                -Name "LogDroppedPackets" `
            | Select-Object -ExpandProperty "LogDroppedPackets"
        
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
    Id   = "Registry-098"
    Task = "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
                -Name "LogSuccessfulConnections" `
            | Select-Object -ExpandProperty "LogSuccessfulConnections"
        
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
    Id   = "Registry-099"
    Task = "Ensure 'Allow Windows Ink Workspace' is set to 'On, but disallow access above lock'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace" `
                -Name "AllowWindowsInkWorkspace" `
            | Select-Object -ExpandProperty "AllowWindowsInkWorkspace"
        
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
    Id   = "Registry-100"
    Task = "Ensure 'Enable local admin password management' set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" `
                -Name "AdmPwdEnabled" `
            | Select-Object -ExpandProperty "AdmPwdEnabled"
        
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
    Id   = "Registry-101"
    Task = "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RunAsPPL" `
            | Select-Object -ExpandProperty "RunAsPPL"
        
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
    Id   = "Registry-102"
    Task = "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print" `
                -Name "RpcAuthnLevelPrivacyEnabled" `
            | Select-Object -ExpandProperty "RpcAuthnLevelPrivacyEnabled"
        
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
    Id   = "Registry-103"
    Task = "Ensure 'WDigest Authentication (disabling may require KB2871997)' is set to 'Disabled'."
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
    Id   = "Registry-104"
    Task = "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
                -Name "DisableExceptionChainValidation" `
            | Select-Object -ExpandProperty "DisableExceptionChainValidation"
        
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
    Id   = "Registry-105"
    Task = "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
                -Name "DriverLoadPolicy" `
            | Select-Object -ExpandProperty "DriverLoadPolicy"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-106"
    Task = "Ensure 'Configure SMB v1 server' is set to 'Disabled'."
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
    Id   = "Registry-107"
    Task = "Ensure 'Configure SMB v1 client driver' is set to 'Disable driver (recommended)'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MrxSmb10" `
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
    Id   = "Registry-108"
    Task = "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" `
                -Name "NoNameReleaseOnDemand" `
            | Select-Object -ExpandProperty "NoNameReleaseOnDemand"
        
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
    Id   = "Registry-109"
    Task = "Ensure 'NetBT NodeType configuration' is set to 'P-node (recommended)'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" `
                -Name "NodeType" `
            | Select-Object -ExpandProperty "NodeType"
        
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
    Id   = "Registry-110"
    Task = "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" `
                -Name "EnableICMPRedirect" `
            | Select-Object -ExpandProperty "EnableICMPRedirect"
        
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
    Id   = "Registry-111"
    Task = "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Highest protection, source routing is completely disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
                -Name "DisableIPSourceRouting" `
            | Select-Object -ExpandProperty "DisableIPSourceRouting"
        
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
    Id   = "Registry-112"
    Task = "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Highest protection, source routing is completely disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
                -Name "DisableIPSourceRouting" `
            | Select-Object -ExpandProperty "DisableIPSourceRouting"
        
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
    Id   = "Registry-113"
    Task = "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                -Name "ScRemoveOption" `
            | Select-Object -ExpandProperty "ScRemoveOption"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-114"
    Task = "The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "InactivityTimeoutSecs" `
            | Select-Object -ExpandProperty "InactivityTimeoutSecs"
        
            if (($regValue -ne 900)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 900"
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
    Id   = "Registry-115"
    Task = "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
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
    Id   = "Registry-116"
    Task = "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "EnablePlainTextPassword" `
            | Select-Object -ExpandProperty "EnablePlainTextPassword"
        
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
    Id   = "Registry-117"
    Task = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "LimitBlankPasswordUse" `
            | Select-Object -ExpandProperty "LimitBlankPasswordUse"
        
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
    Id   = "Registry-118"
    Task = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "RestrictAnonymousSAM" `
            | Select-Object -ExpandProperty "RestrictAnonymousSAM"
        
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
    Id   = "Registry-119"
    Task = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "RestrictAnonymous" `
            | Select-Object -ExpandProperty "RestrictAnonymous"
        
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
    Id   = "Registry-120"
    Task = "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "RestrictNullSessAccess" `
            | Select-Object -ExpandProperty "RestrictNullSessAccess"
        
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
    Id   = "Registry-121"
    Task = "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "SCENoApplyLegacyAuditPolicy" `
            | Select-Object -ExpandProperty "SCENoApplyLegacyAuditPolicy"
        
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
    Id   = "Registry-122"
    Task = "The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "NTLMMinClientSec" `
            | Select-Object -ExpandProperty "NTLMMinClientSec"
        
            if (($regValue -ne 537395200)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 537395200"
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
    Id   = "Registry-123"
    Task = "(ND, NE) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "LmCompatibilityLevel" `
            | Select-Object -ExpandProperty "LmCompatibilityLevel"
        
            if ($regValue -ne 5) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 5"
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
    Id   = "Registry-124"
    Task = "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "allownullsessionfallback" `
            | Select-Object -ExpandProperty "allownullsessionfallback"
        
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
    Id   = "Registry-125"
    Task = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "NTLMMinServerSec" `
            | Select-Object -ExpandProperty "NTLMMinServerSec"
        
            if (($regValue -ne 537395200)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 537395200"
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
    Id   = "Registry-126"
    Task = "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RequireStrongKey" `
            | Select-Object -ExpandProperty "RequireStrongKey"
        
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
    Id   = "Registry-127"
    Task = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "RequireSecuritySignature" `
            | Select-Object -ExpandProperty "RequireSecuritySignature"
        
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
    Id   = "Registry-128"
    Task = "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "sealsecurechannel" `
            | Select-Object -ExpandProperty "sealsecurechannel"
        
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
    Id   = "Registry-129"
    Task = "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RequireSignOrSeal" `
            | Select-Object -ExpandProperty "RequireSignOrSeal"
        
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
    Id   = "Registry-130"
    Task = "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "SignSecureChannel" `
            | Select-Object -ExpandProperty "SignSecureChannel"
        
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
    Id   = "Registry-131"
    Task = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "RequireSecuritySignature" `
            | Select-Object -ExpandProperty "RequireSecuritySignature"
        
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
    Id   = "Registry-132"
    Task = "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" `
                -Name "ProtectionMode" `
            | Select-Object -ExpandProperty "ProtectionMode"
        
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
    Id   = "Registry-133"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorAdmin" `
            | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin"
        
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
    Id   = "Registry-134"
    Task = "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableSecureUIAPaths" `
            | Select-Object -ExpandProperty "EnableSecureUIAPaths"
        
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
    Id   = "Registry-135"
    Task = "User Account Control must run all administrators in Admin Approval Mode, enabling UAC."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableLUA" `
            | Select-Object -ExpandProperty "EnableLUA"
        
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
    Id   = "Registry-136"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorUser" `
            | Select-Object -ExpandProperty "ConsentPromptBehaviorUser"
        
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
    Id   = "Registry-137"
    Task = "User Account Control must be configured to detect application installations and prompt for elevation"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableInstallerDetection" `
            | Select-Object -ExpandProperty "EnableInstallerDetection"
        
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
    Id   = "Registry-138"
    Task = "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "FilterAdministratorToken" `
            | Select-Object -ExpandProperty "FilterAdministratorToken"
        
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
    Id   = "Registry-139"
    Task = "User Account Control must virtualize file and registry write failures to per-user locations."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableVirtualization" `
            | Select-Object -ExpandProperty "EnableVirtualization"
        
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
    Id   = "Registry-140"
    Task = "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" `
                -Name "LDAPClientIntegrity" `
            | Select-Object -ExpandProperty "LDAPClientIntegrity"
        
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
    Id   = "Registry-141"
    Task = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RestrictRemoteSAM" `
            | Select-Object -ExpandProperty "RestrictRemoteSAM"
        
            if ($regValue -ne "O:BAG:BAD:(A;;RC;;;BA)") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: O:BAG:BAD:(A;;RC;;;BA)"
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
    Id   = "Registry-189"
    Task = "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" `
                -Name "PUAProtection" `
            | Select-Object -ExpandProperty "PUAProtection"
        
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
    Id   = "Registry-190"
    Task = "Ensure 'Select cloud protection level' is set to 'Enabled:High blocking level'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine" `
                -Name "MpCloudBlockLevel" `
            | Select-Object -ExpandProperty "MpCloudBlockLevel"
        
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
    Id   = "Registry-191"
    Task = "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'."
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableIOAVProtection" `
            | Select-Object -ExpandProperty "DisableIOAVProtection"
        
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
    Id   = "Registry-192"
    Task = "Ensure 'Turn off real-time protection' is set to 'Disabled'."
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableRealtimeMonitoring" `
            | Select-Object -ExpandProperty "DisableRealtimeMonitoring"
        
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
    Id   = "Registry-193"
    Task = "Ensure 'Turn on script scanning' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableScriptScanning" `
            | Select-Object -ExpandProperty "DisableScriptScanning"
        
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
    Id   = "Registry-194"
    Task = "Ensure 'Turn on behavior monitoring' is set to 'Enabled'."
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableBehaviorMonitoring" `
            | Select-Object -ExpandProperty "DisableBehaviorMonitoring"
        
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
    Id   = "Registry-195"
    Task = "Ensure 'Scan removable drives' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
                -Name "DisableRemovableDriveScanning" `
            | Select-Object -ExpandProperty "DisableRemovableDriveScanning"
        
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
    Id   = "Registry-196"
    Task = "Ensure 'Send file samples when further analysis is required' is set to 'Send safe samples'."
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "SubmitSamplesConsent" `
            | Select-Object -ExpandProperty "SubmitSamplesConsent"
        
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
    Id   = "Registry-197"
    Task = "Ensure 'Join Microsoft MAPS' is set to 'Advanced MAPS'."
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "SpynetReporting" `
            | Select-Object -ExpandProperty "SpynetReporting"
        
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
    Id   = "Registry-198"
    Task = "Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'."
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "DisableBlockAtFirstSeen" `
            | Select-Object -ExpandProperty "DisableBlockAtFirstSeen"
        
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
    Id   = "Registry-199"
    Task = "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
            $Value = "ExploitGuard_ASR_Rules"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
            $Value2 = "ExploitGuard_ASR_Rules"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-200"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block Office applications from injecting code into other processes'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-201"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block Office applications from creating executable content'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "3b576869-a4ec-4529-8536-b80a7769e899"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "3b576869-a4ec-4529-8536-b80a7769e899"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-202"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block Office applications from creating child processes'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-203"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block Win32 API calls from Office macro'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-204"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block execution of potentially obfuscated scripts'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" 

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" 

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-205"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block JavaScript or VBScript from launching downloaded executable content'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "d3e037e1-3eb8-44c8-a917-57927947596d"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "d3e037e1-3eb8-44c8-a917-57927947596d"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-206"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block executable content from email client and webmail'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-207"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block credential stealing from the Windows local security authority subsystem (lsass.exe))'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-208"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block untrusted and unsigned processes that run from USB' is configured"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-209"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block Office communication application from creating child processes'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "26190899-1602-49e8-8b27-eb1d0a1ce869"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "26190899-1602-49e8-8b27-eb1d0a1ce869"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-210"
    Task = "(ND, NE) Ensure 'Configure Attack Surface Reduction rules: Block Adobe Reader from creating child processes'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-211"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Use advanced protection against ransomware'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "c1db55ab-c21a-4637-bb3f-a12568109d35" `
            | Select-Object -ExpandProperty "c1db55ab-c21a-4637-bb3f-a12568109d35"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-212"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block persistence through WMI event subscription'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "e6db77e5-3df2-4cf1-b95a-636979351e5b"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "e6db77e5-3df2-4cf1-b95a-636979351e5b"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-213"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block abuse of exploited vulnerable signed drivers'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }                  
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value = "56a863a9-875e-4185-98a7-b882c64b5ce5"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if ($asrTest1) {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
            $Value2 = "56a863a9-875e-4185-98a7-b882c64b5ce5"

            $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
            if ($asrTest2) {
                $regValueTwo = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path2 `
                    -Name $Value2 `
                | Select-Object -ExpandProperty $Value2
            }

            if ($regValue -ne 1 -and $regValueTwo -ne 1) {
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
    Id   = "Registry-214"
    Task = "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Block'"
    Test = {
        try {
            if ($avstatus) {

                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }

            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
                -Name "EnableNetworkProtection" `
            | Select-Object -ExpandProperty "EnableNetworkProtection"
        
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
    Id   = "Registry-215"
    Task = "Ensure 'Remove `"Run this time`" button for outdated ActiveX controls in Internet Explorer ' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" `
                -Name "RunThisTimeEnabled" `
            | Select-Object -ExpandProperty "RunThisTimeEnabled"
        
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
    Id   = "Registry-216"
    Task = "Ensure 'Turn off blocking of outdated ActiveX controls for Internet Explorer' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" `
                -Name "VersionCheckEnabled" `
            | Select-Object -ExpandProperty "VersionCheckEnabled"
        
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
    Id   = "Registry-217"
    Task = "Ensure 'Allow software to run or install even if the signature is invalid' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Download" `
                -Name "RunInvalidSignatures" `
            | Select-Object -ExpandProperty "RunInvalidSignatures"
        
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
    Id   = "Registry-218"
    Task = "Set registry value 'CheckExeSignatures' to yes."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Download" `
                -Name "CheckExeSignatures" `
            | Select-Object -ExpandProperty "CheckExeSignatures"
        
            if ($regValue -ne "yes") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: yes"
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
    Id   = "Registry-219"
    Task = "Ensure 'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "Isolation64Bit" `
            | Select-Object -ExpandProperty "Isolation64Bit"
        
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
    Id   = "Registry-220"
    Task = "Ensure 'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "DisableEPMCompat" `
            | Select-Object -ExpandProperty "DisableEPMCompat"
        
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
    Id   = "Registry-221"
    Task = "Set registry value 'Isolation' to PMEM."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "Isolation" `
            | Select-Object -ExpandProperty "Isolation"
        
            if ($regValue -ne "PMEM") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: PMEM"
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
    Id   = "Registry-222"
    Task = "Ensure 'Internet Explorer Processes for MK protocol' is not enabled (Reserved)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-223"
    Task = "Ensure 'Internet Explorer Processes for MK protocol' is not enabled (iexplore.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-224"
    Task = " Ensure 'Internet Explorer Processes for MK protocol' is not enabled (explorer.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-225"
    Task = "Set registry value 'explorer.exe' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-226"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_MIME_HANDLING)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-227"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_MIME_HANDLING)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-228"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_MIME_SNIFFING)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-229"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_MIME_SNIFFING)"
    Test = {
        try {
            if ((Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature -ne $True) {
                return @{
                    Message = "RequireSecuritySignature is not set to True"
                    Status  = "False"
                }
            }
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        catch {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" `
                    -Name "RequireSecuritySignature" `
                | Select-Object -ExpandProperty "RequireSecuritySignature"
                
                return @{
                    Message = "Registry value is '$regValue'. Get-SMBServerConfiguration failed, resorted to checking registry, which might not be 100% accurate. See <a href=`"https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing#policy-locations-for-smb-signing`" target='_blank'>here</a> and <a href=`"https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-insider/ba-p/3831704`" target='_blank'>here</a>"
                    Status  = "Warning"
                }
            }
            catch [System.Management.Automation.PSArgumentException] {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
                    Status  = "False"
                }
            }
            catch [System.Management.Automation.ItemNotFoundException] {
                return @{
                    Message = "Registry key not found."
                    Status  = "False"
                }
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "Registry-230"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_MIME_SNIFFING)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-231"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_RESTRICT_ACTIVEXINSTALL)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-232"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_RESTRICT_ACTIVEXINSTALL)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-233"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_RESTRICT_ACTIVEXINSTALL)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-234"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_RESTRICT_FILEDOWNLOAD)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-235"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_RESTRICT_FILEDOWNLOAD)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-236"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_RESTRICT_FILEDOWNLOAD)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-237"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_SECURITYBAND)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-238"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_SECURITYBAND)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-239"
    Task = "Set 'Notification bar' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-240"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_WINDOW_RESTRICTIONS)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-241"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_WINDOW_RESTRICTIONS)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-242"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_WINDOW_RESTRICTIONS)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-243"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_ZONE_ELEVATION)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-244"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_ZONE_ELEVATION)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-245"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_ZONE_ELEVATION)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id   = "Registry-246"
    Task = "Set 'Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the Internet' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "PreventOverrideAppRepUnknown" `
            | Select-Object -ExpandProperty "PreventOverrideAppRepUnknown"
        
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
    Id   = "Registry-247"
    Task = "Set 'Prevent Bypassing SmartScreen Filter Warnings' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "PreventOverride" `
            | Select-Object -ExpandProperty "PreventOverride"
        
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
    Id   = "Registry-248"
    Task = "Ensure 'Prevent managing SmartScreen Filter' is set to 'On'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "EnabledV9" `
            | Select-Object -ExpandProperty "EnabledV9"
        
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
    Id   = "Registry-249"
    Task = "Set 'Turn off Crash Detection' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Restrictions" `
                -Name "NoCrashDetection" `
            | Select-Object -ExpandProperty "NoCrashDetection"
        
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
    Id   = "Registry-250"
    Task = "Ensure 'Turn off the Security Settings Check feature' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Security" `
                -Name "DisableSecuritySettingsCheck" `
            | Select-Object -ExpandProperty "DisableSecuritySettingsCheck"
        
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
    Id   = "Registry-251"
    Task = "Ensure 'Prevent per-user installation of ActiveX controls' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" `
                -Name "BlockNonAdminActiveXInstall" `
            | Select-Object -ExpandProperty "BlockNonAdminActiveXInstall"
        
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
    Id   = "Registry-252"
    Task = "Ensure 'Specify use of ActiveX Installer Service for installation of ActiveX controls' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AxInstaller" `
                -Name "OnlyUseAXISForActiveXInstall" `
            | Select-Object -ExpandProperty "OnlyUseAXISForActiveXInstall"
        
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
    Id   = "Registry-253"
    Task = "Set 'Security Zones: Do not allow users to add/delete sites' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_zones_map_edit" `
            | Select-Object -ExpandProperty "Security_zones_map_edit"
        
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
    Id   = "Registry-254"
    Task = "Set 'Security Zones: Do not allow users to change policies' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_options_edit" `
            | Select-Object -ExpandProperty "Security_options_edit"
        
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
    Id   = "Registry-255"
    Task = "Set 'Security Zones: Use only machine settings' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_HKLM_only" `
            | Select-Object -ExpandProperty "Security_HKLM_only"
        
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
    Id   = "Registry-256"
    Task = "Ensure 'Check for server certificate revocation' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "CertificateRevocation" `
            | Select-Object -ExpandProperty "CertificateRevocation"
        
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
    Id   = "Registry-257"
    Task = "Ensure 'Prevent ignoring certificate errors' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "PreventIgnoreCertErrors" `
            | Select-Object -ExpandProperty "PreventIgnoreCertErrors"
        
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
    Id   = "Registry-258"
    Task = "Set 'Turn on certificate address mismatch warning' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "WarnOnBadCertRecving" `
            | Select-Object -ExpandProperty "WarnOnBadCertRecving"
        
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
    Id   = "Registry-259"
    Task = "Ensure 'Allow fallback to SSL 3.0 (Internet Explorer)' is set to 'No Sites'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "EnableSSL3Fallback" `
            | Select-Object -ExpandProperty "EnableSSL3Fallback"
        
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
    Id   = "Registry-260"
    Task = "Ensure 'Turn off encryption support' is set to 'Use TLS 1.1 and TLS 1.2'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "SecureProtocols" `
            | Select-Object -ExpandProperty "SecureProtocols"
        
            if (($regValue -ne 2560)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 2560"
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
    Id   = "Registry-261"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Lockdown_Zones/0)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-262"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Lockdown_Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-263"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Lockdown_Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-264"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'. (Lockdown_Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
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
    Id   = "Registry-265"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'. (Lockdown_Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
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
    Id   = "Registry-266"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Lockdown_Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-267"
    Task = "Ensure 'Intranet Sites: Include all network paths (UNCs)' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" `
                -Name "UNCAsIntranet" `
            | Select-Object -ExpandProperty "UNCAsIntranet"
        
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
    Id   = "Registry-268"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Zones/0)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-269"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'. (Zones/0)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
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
    Id   = "Registry-270"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'. (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
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
    Id   = "Registry-271"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable'. (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-272"
    Task = "Ensure 'Java permissions' is set to 'High safety'. (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if (($regValue -ne 65536)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 65536"
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
    Id   = "Registry-273"
    Task = "Ensure 'Java permissions' is set to 'High safety'. (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if (($regValue -ne 65536)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 65536"
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
    Id   = "Registry-274"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'. (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
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
    Id   = "Registry-275"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable'. (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-276"
    Task = "Ensure 'Run .NET Framework-reliant components signed with Authenticode' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2001" `
            | Select-Object -ExpandProperty "2001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-277"
    Task = "Ensure 'Allow script-initiated windows without size or position constraints' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2102" `
            | Select-Object -ExpandProperty "2102"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-278"
    Task = "Ensure 'Allow drag and drop or copy and paste files' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1802" `
            | Select-Object -ExpandProperty "1802"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-279"
    Task = "Ensure 'Include local path when user is uploading files to a server' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "160A" `
            | Select-Object -ExpandProperty "160A"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-280"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-281"
    Task = "Ensure 'Access data sources across domains' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1406" `
            | Select-Object -ExpandProperty "1406"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-282"
    Task = "Ensure 'Launching applications and files in an IFRAME' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1804" `
            | Select-Object -ExpandProperty "1804"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-283"
    Task = "Ensure 'Automatic prompting for file downloads' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2200" `
            | Select-Object -ExpandProperty "2200"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-284"
    Task = "Ensure 'Allow scriptlets' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1209" `
            | Select-Object -ExpandProperty "1209"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-285"
    Task = "Ensure 'Allow scripting of Internet Explorer WebBrowser controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1206" `
            | Select-Object -ExpandProperty "1206"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-286"
    Task = "Ensure 'Use Pop-up Blocker' is set to 'Enable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1809" `
            | Select-Object -ExpandProperty "1809"
        
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
    Id   = "Registry-287"
    Task = "Ensure 'Turn on Protected Mode' is set to 'Enable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2500" `
            | Select-Object -ExpandProperty "2500"
        
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
    Id   = "Registry-288"
    Task = "Ensure 'Allow updates to status bar via script' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2103" `
            | Select-Object -ExpandProperty "2103"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-289"
    Task = "Ensure 'Userdata persistence' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1606" `
            | Select-Object -ExpandProperty "1606"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-290"
    Task = "Ensure 'Allow loading of XAML files' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2402" `
            | Select-Object -ExpandProperty "2402"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-291"
    Task = "Ensure 'Run .NET Framework-reliant components not signed with Authenticode' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2004" `
            | Select-Object -ExpandProperty "2004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-292"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-293"
    Task = "Ensure 'Download signed ActiveX controls' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1001" `
            | Select-Object -ExpandProperty "1001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-294"
    Task = "Ensure 'Logon options' is set to 'Prompt for user name and password'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1A00" `
            | Select-Object -ExpandProperty "1A00"
        
            if (($regValue -ne 65536)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 65536"
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
    Id   = "Registry-295"
    Task = "Ensure 'Enable dragging of content from different domains within a window' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2708" `
            | Select-Object -ExpandProperty "2708"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-296"
    Task = "Ensure 'Download unsigned ActiveX controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1004" `
            | Select-Object -ExpandProperty "1004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-297"
    Task = "Ensure 'Allow only approved domains to use ActiveX controls without prompt' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "120b" `
            | Select-Object -ExpandProperty "120b"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-298"
    Task = "Ensure 'Allow cut, copy or paste operations from the clipboard via script' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1407" `
            | Select-Object -ExpandProperty "1407"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-299"
    Task = "Ensure 'Turn on Cross-Site Scripting Filter' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1409" `
            | Select-Object -ExpandProperty "1409"
        
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
    Id   = "Registry-300"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
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
    Id   = "Registry-301"
    Task = "Ensure 'Navigate windows and frames across different domains' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1607" `
            | Select-Object -ExpandProperty "1607"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-302"
    Task = "Ensure 'Enable dragging of content from different domains across windows' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2709" `
            | Select-Object -ExpandProperty "2709"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-303"
    Task = "Ensure 'Web sites in less privileged Web content zones can navigate into this zone' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2101" `
            | Select-Object -ExpandProperty "2101"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-304"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
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
    Id   = "Registry-305"
    Task = "Ensure 'Show security warning for potentially unsafe files' is set to 'Prompt'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1806" `
            | Select-Object -ExpandProperty "1806"
        
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
    Id   = "Registry-306"
    Task = "Ensure 'Allow only approved domains to use the TDC ActiveX control' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "120c" `
            | Select-Object -ExpandProperty "120c"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-307"
    Task = "Set registry value '140C' to 3. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "140C" `
            | Select-Object -ExpandProperty "140C"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-308"
    Task = "Ensure 'Allow META REFRESH' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1608" `
            | Select-Object -ExpandProperty "1608"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-309"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-310"
    Task = "Ensure 'Download signed ActiveX controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1001" `
            | Select-Object -ExpandProperty "1001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-311"
    Task = "Ensure 'Navigate windows and frames across different domains' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1607" `
            | Select-Object -ExpandProperty "1607"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-312"
    Task = "Ensure 'Allow only approved domains to use ActiveX controls without prompt' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "120b" `
            | Select-Object -ExpandProperty "120b"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-313"
    Task = "Ensure 'Use Pop-up Blocker' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1809" `
            | Select-Object -ExpandProperty "1809"
        
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
    Id   = "Registry-314"
    Task = "Ensure 'Download unsigned ActiveX controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1004" `
            | Select-Object -ExpandProperty "1004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-315"
    Task = "Ensure 'Userdata persistence' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1606" `
            | Select-Object -ExpandProperty "1606"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-316"
    Task = "Ensure 'Allow cut, copy or paste operations from the clipboard via script' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1407" `
            | Select-Object -ExpandProperty "1407"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-317"
    Task = "Ensure 'Include local path when user is uploading files to a server' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "160A" `
            | Select-Object -ExpandProperty "160A"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-318"
    Task = "Ensure 'Access data sources across domains' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1406" `
            | Select-Object -ExpandProperty "1406"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-319"
    Task = "Ensure 'Allow script-initiated windows without size or position constraints' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2102" `
            | Select-Object -ExpandProperty "2102"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-320"
    Task = "Ensure 'Run .NET Framework-reliant components not signed with Authenticode' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2004" `
            | Select-Object -ExpandProperty "2004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-321"
    Task = "Ensure 'Automatic prompting for file downloads' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2200" `
            | Select-Object -ExpandProperty "2200"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-322"
    Task = "Ensure 'Allow binary and script behaviors' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2000" `
            | Select-Object -ExpandProperty "2000"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-323"
    Task = "Ensure 'Scripting of Java applets' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1402" `
            | Select-Object -ExpandProperty "1402"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-324"
    Task = "Ensure 'Allow file downloads' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1803" `
            | Select-Object -ExpandProperty "1803"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-325"
    Task = "Ensure 'Allow loading of XAML files' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2402" `
            | Select-Object -ExpandProperty "2402"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-326"
    Task = "Ensure 'Allow active scripting' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1400" `
            | Select-Object -ExpandProperty "1400"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-327"
    Task = "Ensure 'Logon options' is set to 'Anonymous logon'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1A00" `
            | Select-Object -ExpandProperty "1A00"
        
            if ($regValue -ne 196608) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 196608"
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
    Id   = "Registry-328"
    Task = "Ensure 'Run .NET Framework-reliant components signed with Authenticode' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2001" `
            | Select-Object -ExpandProperty "2001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-329"
    Task = "Ensure 'Turn on Protected Mode' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2500" `
            | Select-Object -ExpandProperty "2500"
        
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
    Id   = "Registry-330"
    Task = "Ensure 'Turn on Cross-Site Scripting Filter' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1409" `
            | Select-Object -ExpandProperty "1409"
        
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
    Id   = "Registry-331"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
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
    Id   = "Registry-332"
    Task = "Ensure 'Allow scriptlets' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1209" `
            | Select-Object -ExpandProperty "1209"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-333"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
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
    Id   = "Registry-334"
    Task = "Ensure 'Allow scripting of Internet Explorer WebBrowser controls' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1206" `
            | Select-Object -ExpandProperty "1206"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-335"
    Task = "Ensure 'Enable dragging of content from different domains within a window' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2708" `
            | Select-Object -ExpandProperty "2708"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-336"
    Task = "Ensure 'Allow drag and drop or copy and paste files' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1802" `
            | Select-Object -ExpandProperty "1802"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-337"
    Task = "Ensure 'Allow updates to status bar via script' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2103" `
            | Select-Object -ExpandProperty "2103"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-338"
    Task = "Ensure 'Enable dragging of content from different domains across windows' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2709" `
            | Select-Object -ExpandProperty "2709"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-339"
    Task = "Ensure 'Script ActiveX controls marked safe for scripting' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1405" `
            | Select-Object -ExpandProperty "1405"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-340"
    Task = "Ensure 'Web sites in less privileged Web content zones can navigate into this zone' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2101" `
            | Select-Object -ExpandProperty "2101"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-341"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
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
    Id   = "Registry-342"
    Task = "Ensure 'Run ActiveX controls and plugins' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1200" `
            | Select-Object -ExpandProperty "1200"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-343"
    Task = "Ensure 'Launching applications and files in an IFRAME' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1804" `
            | Select-Object -ExpandProperty "1804"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-344"
    Task = "Ensure 'Show security warning for potentially unsafe files' is set to 'Disable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1806" `
            | Select-Object -ExpandProperty "1806"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-345"
    Task = "Ensure 'Allow only approved domains to use the TDC ActiveX control' is set to 'Enable'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "120c" `
            | Select-Object -ExpandProperty "120c"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-346"
    Task = "Set registry value '140C' to 3. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "140C" `
            | Select-Object -ExpandProperty "140C"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 3"
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
    Id   = "Registry-347"
    Task = "Set 'Turn on the auto-complete feature for user names and passwords on forms' to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "FormSuggest Passwords" `
            | Select-Object -ExpandProperty "FormSuggest Passwords"
        
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
    Id   = "Registry-348"
    Task = "Ensure 'Turn on the auto-complete feature for user names and passwords on forms' is set to 'no'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "FormSuggest PW Ask" `
            | Select-Object -ExpandProperty "FormSuggest PW Ask"
        
            if ($regValue -ne "no") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: no"
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
    Id   = "Registry-349"
    Task = "Set registry value 'FormSuggest Passwords' to no."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "FormSuggest Passwords" `
            | Select-Object -ExpandProperty "FormSuggest Passwords"
        
            if ($regValue -ne "no") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: no"
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
    Id   = "Registry-351"
    Task = "Ensure 'Allow enhanced PINs for startup' is set 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" `
                -Name "UseEnhancedPin" `
            | Select-Object -ExpandProperty "UseEnhancedPin"
        
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
    Id   = "Registry-352"
    Task = "Set registry value 'RDVDenyCrossOrg' to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" `
                -Name "RDVDenyCrossOrg" `
            | Select-Object -ExpandProperty "RDVDenyCrossOrg"
        
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
    Id   = "Registry-353"
    Task = "Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" `
                -Name "DisableExternalDMAUnderLock" `
            | Select-Object -ExpandProperty "DisableExternalDMAUnderLock"
        
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
    Id   = "Registry-354"
    Task = "Ensure 'Allow Standby States (S1-S3) When Sleeping (On Battery)' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" `
                -Name "DCSettingIndex" `
            | Select-Object -ExpandProperty "DCSettingIndex"
        
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
    Id   = "Registry-355"
    Task = "Ensure 'Allow Standby States (S1-S3) When Sleeping (Plugged In)' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" `
                -Name "ACSettingIndex" `
            | Select-Object -ExpandProperty "ACSettingIndex"
        
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
    Id   = "Registry-356"
    Task = "Ensure 'Prevent installation of devices using drivers that match these device setup classes' set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" `
                -Name "DenyDeviceClasses" `
            | Select-Object -ExpandProperty "DenyDeviceClasses"
        
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
    Id   = "Registry-357"
    Task = "Ensure 'Prevent installation of devices using drivers that match these device setup classes' set to 'Also apply to matching devices that are already installed. (True) '."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" `
                -Name "DenyDeviceClassesRetroactive" `
            | Select-Object -ExpandProperty "DenyDeviceClassesRetroactive"
        
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
    Id   = "Registry-358"
    Task = "Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes' [IEEE 1394 devices that support the SBP2 Protocol Class]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" `
                -Name "1" `
            | Select-Object -ExpandProperty "1"
        
            if ($regValue -ne "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: {d48179be-ec20-11d1-b6b8-00c04fa372a7}"
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
    Id   = "Registry-359"
    Task = "Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\Microsoft\FVE" `
                -Name "RDVDenyWriteAccess" `
            | Select-Object -ExpandProperty "RDVDenyWriteAccess"
        
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
    Id   = "Registry-368"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "EnableVirtualizationBasedSecurity" `
            | Select-Object -ExpandProperty "EnableVirtualizationBasedSecurity"
        
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
    Id   = "Registry-369"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Secure Boot'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "RequirePlatformSecurityFeatures" `
            | Select-Object -ExpandProperty "RequirePlatformSecurityFeatures"
        
            if ($regValue -eq 3) {
                return @{
                    Message = "Set to 'Secure Boot and DMA Protection' which is more secure."
                    Status  = "True"
                }
            }
                
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
    Id   = "Registry-370"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled with UEFI lock'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "HypervisorEnforcedCodeIntegrity" `
            | Select-Object -ExpandProperty "HypervisorEnforcedCodeIntegrity"
        
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
    Id   = "Registry-371"
    Task = "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "HVCIMATRequired" `
            | Select-Object -ExpandProperty "HVCIMATRequired"
        
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
    Id   = "Registry-372"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled with UEFI lock'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "LsaCfgFlags" `
            | Select-Object -ExpandProperty "LsaCfgFlags"
        
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
    Id   = "Registry-373"
    Task = "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "ConfigureSystemGuardLaunch" `
            | Select-Object -ExpandProperty "ConfigureSystemGuardLaunch"
        
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
    Id   = "Registry-374"
    Task = "Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "ConfigureKernelShadowStacksLaunch" `
            | Select-Object -ExpandProperty "ConfigureKernelShadowStacksLaunch"
        
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
    Id   = "Registry-375"
    Task = "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableThirdPartySuggestions" `
            | Select-Object -ExpandProperty "DisableThirdPartySuggestions"
        
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
    Id   = "Registry-376"
    Task = "Toast notifications to the lock screen must be turned off."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" `
                -Name "NoToastApplicationNotificationOnLockScreen" `
            | Select-Object -ExpandProperty "NoToastApplicationNotificationOnLockScreen"
        
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
