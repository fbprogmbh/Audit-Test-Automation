# Common
$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$avstatus = CheckForActiveAV
$windefrunning = CheckWindefRunning
. "$RootPath\Helpers\Firewall.ps1"

# Tests
[AuditTest] @{
    Id   = "1.1.1"
    Task = "Ensure 'Remove `"Run this time`" button for outdated ActiveX controls in Internet Explorer ' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" `
                -Name "RunThisTimeEnabled" `
            | Select-Object -ExpandProperty "RunThisTimeEnabled"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2"
    Task = "Ensure 'Turn off blocking of outdated ActiveX controls for Internet Explorer' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" `
                -Name "VersionCheckEnabled" `
            | Select-Object -ExpandProperty "VersionCheckEnabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.3"
    Task = "Ensure 'Allow software to run or install even if the signature is invalid' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Download" `
                -Name "RunInvalidSignatures" `
            | Select-Object -ExpandProperty "RunInvalidSignatures"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.4"
    Task = "Ensure 'Check for signatures on downloaded programs' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Download" `
                -Name "CheckExeSignatures" `
            | Select-Object -ExpandProperty "CheckExeSignatures"
        
            if ($regValue -ne "yes") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: yes"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.5"
    Task = "Ensure 'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "Isolation64Bit" `
            | Select-Object -ExpandProperty "Isolation64Bit"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.6"
    Task = "Ensure 'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "DisableEPMCompat" `
            | Select-Object -ExpandProperty "DisableEPMCompat"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.7"
    Task = "Ensure 'Turn on Enhanced Protected Mode' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "Isolation" `
            | Select-Object -ExpandProperty "Isolation"
        
            if ($regValue -ne "PMEM") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: PMEM"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.8"
    Task = "Ensure 'Disable Internet Explorer 11 Launch Via COM Automation' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "DisableInternetExplorerLaunchViaCOM" `
            | Select-Object -ExpandProperty "DisableInternetExplorerLaunchViaCOM"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.9"
    Task = "Ensure 'Internet Explorer Processes for MK protocol' is not enabled (Reserved)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.10"
    Task = "Ensure 'Internet Explorer Processes for MK protocol' is not enabled (iexplore.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.11"
    Task = "Ensure 'Internet Explorer Processes for MK protocol' is not enabled (explorer.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.12"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.13"
    Task = "Ensure 'FEATURE_MIME_HANDLING for iexplore.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.14"
    Task = "Ensure 'FEATURE_MIME_HANDLING for (Reserved)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.15"
    Task = "Ensure 'FEATURE_MIME_SNIFFING for explorer.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.16"
    Task = "Ensure 'FEATURE_MIME_SNIFFING for iexplore.exe' is set to 'Enalbed'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.17"
    Task = "Ensure 'FEATURE_MIME_SNIFFING for (Reserved)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.18"
    Task = "Ensure 'FEATURE_RESTRICT_ACTIVEXINSTALL for (Reserved)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.19"
    Task = "Ensure 'FEATURE_RESTRICT_ACTIVEXINSTALL for explorer.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.20"
    Task = "Ensure 'FEATURE_RESTRICT_ACTIVEXINSTALL for iexplore.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.21"
    Task = "Ensure 'FEATURE_RESTRICT_FILEDOWNLOAD for (Reserved)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.22"
    Task = "Ensure 'FEATURE_RESTRICT_FILEDOWNLOAD for iexplore.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.23"
    Task = "Ensure 'FEATURE_RESTRICT_FILEDOWNLOAD for explorer.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.24"
    Task = "Ensure 'FEATURE_SECURITYBAND for (Reserved)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.25"
    Task = "Ensure 'FEATURE_SECURITYBAND for iexplore.exe' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.26"
    Task = "Ensure 'Notification bar' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.27"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (iexplorer.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.28"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (Reserved)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.29"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (explorer.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.30"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (Reserved)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "(Reserved)" `
            | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.31"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (explorer.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "explorer.exe" `
            | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.32"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (iexplore.exe)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "iexplore.exe" `
            | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.33"
    Task = "Ensure 'Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the Internet' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "PreventOverrideAppRepUnknown" `
            | Select-Object -ExpandProperty "PreventOverrideAppRepUnknown"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.34"
    Task = "Ensure 'Prevent Bypassing SmartScreen Filter Warnings' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "PreventOverride" `
            | Select-Object -ExpandProperty "PreventOverride"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.35"
    Task = "Ensure 'Prevent managing SmartScreen Filter' is set to 'Enabled: On'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "EnabledV9" `
            | Select-Object -ExpandProperty "EnabledV9"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.36"
    Task = "Ensure 'Turn off Crash Detection' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Restrictions" `
                -Name "NoCrashDetection" `
            | Select-Object -ExpandProperty "NoCrashDetection"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.37"
    Task = "Ensure 'Turn off the Security Settings Check feature' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Security" `
                -Name "DisableSecuritySettingsCheck" `
            | Select-Object -ExpandProperty "DisableSecuritySettingsCheck"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.38"
    Task = "Ensure 'Prevent per-user installation of ActiveX controls' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" `
                -Name "BlockNonAdminActiveXInstall" `
            | Select-Object -ExpandProperty "BlockNonAdminActiveXInstall"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.39"
    Task = "Ensure 'Specify use of ActiveX Installer Service for installation of ActiveX controls' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AxInstaller" `
                -Name "OnlyUseAXISForActiveXInstall" `
            | Select-Object -ExpandProperty "OnlyUseAXISForActiveXInstall"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.40"
    Task = "Ensure 'Security_zones_map_edit' is set to 'Restricted'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_zones_map_edit" `
            | Select-Object -ExpandProperty "Security_zones_map_edit"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.41"
    Task = "Ensure 'Security_options_edit' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_options_edit" `
            | Select-Object -ExpandProperty "Security_options_edit"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.42"
    Task = "Ensure 'Security_HKLM_only' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_HKLM_only" `
            | Select-Object -ExpandProperty "Security_HKLM_only"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.43"
    Task = "Ensure 'Check for server certificate revocation' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "CertificateRevocation" `
            | Select-Object -ExpandProperty "CertificateRevocation"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.44"
    Task = "Ensure 'Prevent ignoring certificate errors' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "PreventIgnoreCertErrors" `
            | Select-Object -ExpandProperty "PreventIgnoreCertErrors"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.45"
    Task = "Ensure 'Turn on certificate address mismatch warning' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "WarnOnBadCertRecving" `
            | Select-Object -ExpandProperty "WarnOnBadCertRecving"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.46"
    Task = "Ensure 'Allow fallback to SSL 3.0 (Internet Explorer)' is set to 'No Sites'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "EnableSSL3Fallback" `
            | Select-Object -ExpandProperty "EnableSSL3Fallback"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.47"
    Task = "Ensure 'Turn off encryption support' is set to 'Use TLS 1.1 and TLS 1.2'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "SecureProtocols" `
            | Select-Object -ExpandProperty "SecureProtocols"
        
            if ($regValue -ne 2560) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2560"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.48"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Lockdown_Zones/0)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.49"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Lockdown_Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.50"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Lockdown_Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.51"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable' (Lockdown_Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.52"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable' (Lockdown_Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.53"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Lockdown_Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.54"
    Task = "Ensure 'Intranet Sites: Include all network paths (UNCs)' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" `
                -Name "UNCAsIntranet" `
            | Select-Object -ExpandProperty "UNCAsIntranet"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.55"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Zones/0)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.56"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable' (Zones/0)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.57"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable' (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.58"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable' (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.59"
    Task = "Ensure 'Java permissions' is set to 'High safety' (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 65536) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 65536"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.60"
    Task = "Ensure 'Java permissions' is set to 'High safety' (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 65536) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 65536"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.61"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable' (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.62"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable' (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.63"
    Task = "Ensure 'Run .NET Framework-reliant components signed with Authenticode' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2001" `
            | Select-Object -ExpandProperty "2001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.64"
    Task = "Ensure 'Allow script-initiated windows without size or position constraints' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2102" `
            | Select-Object -ExpandProperty "2102"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.65"
    Task = "Ensure 'Allow drag and drop or copy and paste files' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1802" `
            | Select-Object -ExpandProperty "1802"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.66"
    Task = "Ensure 'Include local path when user is uploading files to a server' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "160A" `
            | Select-Object -ExpandProperty "160A"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.67"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.68"
    Task = "Ensure 'Access data sources across domains' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1406" `
            | Select-Object -ExpandProperty "1406"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.69"
    Task = "Ensure 'Launching applications and files in an IFRAME' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1804" `
            | Select-Object -ExpandProperty "1804"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.70"
    Task = "Ensure 'Automatic prompting for file downloads' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2200" `
            | Select-Object -ExpandProperty "2200"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.71"
    Task = "Ensure 'Allow scriptlets' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1209" `
            | Select-Object -ExpandProperty "1209"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.72"
    Task = "Ensure 'Allow scripting of Internet Explorer WebBrowser controls' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1206" `
            | Select-Object -ExpandProperty "1206"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.73"
    Task = "Ensure 'Use Pop-up Blocker' is set to 'Enable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1809" `
            | Select-Object -ExpandProperty "1809"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.74"
    Task = "Ensure 'Turn on Protected Mode' is set to 'Enable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2500" `
            | Select-Object -ExpandProperty "2500"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.75"
    Task = "Ensure 'Allow updates to status bar via script' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2103" `
            | Select-Object -ExpandProperty "2103"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.76"
    Task = "Ensure 'Userdata persistence' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1606" `
            | Select-Object -ExpandProperty "1606"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.77"
    Task = "Ensure 'Allow loading of XAML files' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2402" `
            | Select-Object -ExpandProperty "2402"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.78"
    Task = "Ensure 'Run .NET Framework-reliant components not signed with Authenticode' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2004" `
            | Select-Object -ExpandProperty "2004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.79"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.80"
    Task = "Ensure 'Download signed ActiveX controls' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1001" `
            | Select-Object -ExpandProperty "1001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.81"
    Task = "Ensure 'Logon options' is set to 'Prompt for user name and password' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1A00" `
            | Select-Object -ExpandProperty "1A00"
        
            if ($regValue -ne 65536) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 65536"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.82"
    Task = "Ensure 'Enable dragging of content from different domains within a window' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2708" `
            | Select-Object -ExpandProperty "2708"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.83"
    Task = "Ensure 'Download unsigned ActiveX controls' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1004" `
            | Select-Object -ExpandProperty "1004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.84"
    Task = "Ensure 'Allow only approved domains to use ActiveX controls without prompt' is set to 'Enable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "120b" `
            | Select-Object -ExpandProperty "120b"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.85"
    Task = "Ensure 'Allow cut, copy or paste operations from the clipboard via script' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1407" `
            | Select-Object -ExpandProperty "1407"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.86"
    Task = "Ensure 'Turn on Cross-Site Scripting Filter' is set to 'Enable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1409" `
            | Select-Object -ExpandProperty "1409"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.87"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.88"
    Task = "Ensure 'Navigate windows and frames across different domains' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1607" `
            | Select-Object -ExpandProperty "1607"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.89"
    Task = "Ensure 'Enable dragging of content from different domains across windows' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2709" `
            | Select-Object -ExpandProperty "2709"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.90"
    Task = "Ensure 'Web sites in less privileged Web content zones can navigate into this zone' is set to 'Disable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2101" `
            | Select-Object -ExpandProperty "2101"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.91"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.92"
    Task = "Ensure 'Show security warning for potentially unsafe files' is set to 'Prompt' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1806" `
            | Select-Object -ExpandProperty "1806"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.93"
    Task = "Ensure 'Allow only approved domains to use the TDC ActiveX control' is set to 'Enable' (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "120c" `
            | Select-Object -ExpandProperty "120c"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.94"
    Task = "Ensure 'Allow VBScript to run in Internet Explorer' is set to 3. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "140C" `
            | Select-Object -ExpandProperty "140C"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.95"
    Task = "Ensure 'Allow META REFRESH' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1608" `
            | Select-Object -ExpandProperty "1608"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.96"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1201" `
            | Select-Object -ExpandProperty "1201"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.97"
    Task = "Ensure 'Download signed ActiveX controls' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1001" `
            | Select-Object -ExpandProperty "1001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.98"
    Task = "Ensure 'Navigate windows and frames across different domains' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1607" `
            | Select-Object -ExpandProperty "1607"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.99"
    Task = "Ensure 'Allow only approved domains to use ActiveX controls without prompt' is set to 'Enable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "120b" `
            | Select-Object -ExpandProperty "120b"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.100"
    Task = "Ensure 'Use Pop-up Blocker' is set to 'Enable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1809" `
            | Select-Object -ExpandProperty "1809"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.101"
    Task = "Ensure 'Download unsigned ActiveX controls' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1004" `
            | Select-Object -ExpandProperty "1004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.102"
    Task = "Ensure 'Userdata persistence' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1606" `
            | Select-Object -ExpandProperty "1606"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.103"
    Task = "Ensure 'Allow cut, copy or paste operations from the clipboard via script' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1407" `
            | Select-Object -ExpandProperty "1407"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.104"
    Task = "Ensure 'Include local path when user is uploading files to a server' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "160A" `
            | Select-Object -ExpandProperty "160A"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.105"
    Task = "Ensure 'Access data sources across domains' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1406" `
            | Select-Object -ExpandProperty "1406"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.106"
    Task = "Ensure 'Allow script-initiated windows without size or position constraints' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2102" `
            | Select-Object -ExpandProperty "2102"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.107"
    Task = "Ensure 'Run .NET Framework-reliant components not signed with Authenticode' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2004" `
            | Select-Object -ExpandProperty "2004"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.108"
    Task = "Ensure 'Automatic prompting for file downloads' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2200" `
            | Select-Object -ExpandProperty "2200"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.109"
    Task = "Ensure 'Allow binary and script behaviors' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2000" `
            | Select-Object -ExpandProperty "2000"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.110"
    Task = "Ensure 'Scripting of Java applets' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1402" `
            | Select-Object -ExpandProperty "1402"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.111"
    Task = "Ensure 'Allow file downloads' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1803" `
            | Select-Object -ExpandProperty "1803"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.112"
    Task = "Ensure 'Allow loading of XAML files' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2402" `
            | Select-Object -ExpandProperty "2402"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.113"
    Task = "Ensure 'Allow active scripting' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1400" `
            | Select-Object -ExpandProperty "1400"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.114"
    Task = "Ensure 'Logon options' is set to 'Anonymous logon' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1A00" `
            | Select-Object -ExpandProperty "1A00"
        
            if ($regValue -ne 196608) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 196608"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.115"
    Task = "Ensure 'Run .NET Framework-reliant components signed with Authenticode' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2001" `
            | Select-Object -ExpandProperty "2001"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.116"
    Task = "Ensure 'Turn on Protected Mode' is set to 'Enable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2500" `
            | Select-Object -ExpandProperty "2500"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.117"
    Task = "Ensure 'Turn on Cross-Site Scripting Filter' is set to 'Enable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1409" `
            | Select-Object -ExpandProperty "1409"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.118"
    Task = "Ensure 'Java permissions' is set to 'Disable Java' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1C00" `
            | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.119"
    Task = "Ensure 'Allow scriptlets' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1209" `
            | Select-Object -ExpandProperty "1209"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.120"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "270C" `
            | Select-Object -ExpandProperty "270C"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.121"
    Task = "Ensure 'Allow scripting of Internet Explorer WebBrowser controls' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1206" `
            | Select-Object -ExpandProperty "1206"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.122"
    Task = "Ensure 'Enable dragging of content from different domains within a window' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2708" `
            | Select-Object -ExpandProperty "2708"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.123"
    Task = "Ensure 'Allow drag and drop or copy and paste files' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1802" `
            | Select-Object -ExpandProperty "1802"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.124"
    Task = "Ensure 'Allow updates to status bar via script' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2103" `
            | Select-Object -ExpandProperty "2103"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.125"
    Task = "Ensure 'Enable dragging of content from different domains across windows' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2709" `
            | Select-Object -ExpandProperty "2709"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.126"
    Task = "Ensure 'Script ActiveX controls marked safe for scripting' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1405" `
            | Select-Object -ExpandProperty "1405"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.127"
    Task = "Ensure 'Web sites in less privileged Web content zones can navigate into this zone' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2101" `
            | Select-Object -ExpandProperty "2101"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.128"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2301" `
            | Select-Object -ExpandProperty "2301"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.129"
    Task = "Ensure 'Run ActiveX controls and plugins' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1200" `
            | Select-Object -ExpandProperty "1200"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.130"
    Task = "Ensure 'Launching applications and files in an IFRAME' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1804" `
            | Select-Object -ExpandProperty "1804"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.131"
    Task = "Ensure 'Show security warning for potentially unsafe files' is set to 'Disable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1806" `
            | Select-Object -ExpandProperty "1806"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.132"
    Task = "Ensure 'Allow only approved domains to use the TDC ActiveX control' is set to 'Enable' (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "120c" `
            | Select-Object -ExpandProperty "120c"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.133"
    Task = "Ensure 'Allow VBScript to run in Internet Explorer' is set to 'Disabled' [Restricted Sites Zone]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "140C" `
            | Select-Object -ExpandProperty "140C"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.1"
    Task = "Ensure 'Turn on the auto-complete feature for user names and passwords on forms' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "FormSuggest Passwords" `
            | Select-Object -ExpandProperty "FormSuggest Passwords"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.2"
    Task = "Ensure 'Turn on the auto-complete feature for user names and passwords on forms' is set to 'no'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "FormSuggest PW Ask" `
            | Select-Object -ExpandProperty "FormSuggest PW Ask"
        
            if ($regValue -ne "no") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: no"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.3"
    Task = "Ensure 'Turn on the auto-complete feature for user names and passwords on forms' is set to 'no'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "FormSuggest Passwords" `
            | Select-Object -ExpandProperty "FormSuggest Passwords"
        
            if ($regValue -ne "no") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: no"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.1"
    Task = "Ensure 'Allow enhanced PINs for startup' is set 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" `
                -Name "UseEnhancedPin" `
            | Select-Object -ExpandProperty "UseEnhancedPin"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.2"
    Task = "Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" `
                -Name "RDVDenyCrossOrg" `
            | Select-Object -ExpandProperty "RDVDenyCrossOrg"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.3"
    Task = "Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" `
                -Name "DisableExternalDMAUnderLock" `
            | Select-Object -ExpandProperty "DisableExternalDMAUnderLock"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.4"
    Task = "Ensure 'Allow Standby States (S1-S3) When Sleeping (On Battery)' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" `
                -Name "DCSettingIndex" `
            | Select-Object -ExpandProperty "DCSettingIndex"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.5"
    Task = "Ensure 'Allow Standby States (S1-S3) When Sleeping (Plugged In)' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" `
                -Name "ACSettingIndex" `
            | Select-Object -ExpandProperty "ACSettingIndex"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.6"
    Task = "Ensure 'Prevent installation of devices using drivers that match these device setup classes' set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" `
                -Name "DenyDeviceClasses" `
            | Select-Object -ExpandProperty "DenyDeviceClasses"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.7"
    Task = "Ensure 'Prevent installation of devices using drivers that match these device setup classes' set to 'Also apply to matching devices that are already installed. (True) '"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" `
                -Name "DenyDeviceClassesRetroactive" `
            | Select-Object -ExpandProperty "DenyDeviceClassesRetroactive"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.9"
    Task = "Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes' [IEEE 1394 devices that support the SBP2 Protocol Class]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" `
                -Name "1" `
            | Select-Object -ExpandProperty "1"
        
            if ($regValue -ne "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: {d48179be-ec20-11d1-b6b8-00c04fa372a7}"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.10"
    Task = "Ensure 'Deny write access to removable drives not protected by BitLocker' set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\Microsoft\FVE" `
                -Name "RDVDenyWriteAccess" `
            | Select-Object -ExpandProperty "RDVDenyWriteAccess"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.1"
    Task = "Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\WcmSvc\wifinetworkmanager\config" `
                -Name "AutoConnectAllowedOEM" `
            | Select-Object -ExpandProperty "AutoConnectAllowedOEM"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.2"
    Task = "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
                -Name "EnumerateAdministrators" `
            | Select-Object -ExpandProperty "EnumerateAdministrators"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3"
    Task = "Ensure 'Turn off Autoplay' is set to 'All drives'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoDriveTypeAutoRun" `
            | Select-Object -ExpandProperty "NoDriveTypeAutoRun"
        
            if ($regValue -ne 255) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 255"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4"
    Task = "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoWebServices" `
            | Select-Object -ExpandProperty "NoWebServices"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.5"
    Task = "Ensure 'Set the default behavior for AutoRun' is set to 'Do not execute any autorun commands'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoAutorun" `
            | Select-Object -ExpandProperty "NoAutorun"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.6"
    Task = "Ensure 'BackupDirectory' is set to 'Back up the password to Windows Server Active Directory only'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
                -Name "BackupDirectory" `
            | Select-Object -ExpandProperty "BackupDirectory"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.7"
    Task = "Ensure 'Enable password encryption' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
                -Name "ADPasswordEncryptionEnabled" `
            | Select-Object -ExpandProperty "ADPasswordEncryptionEnabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.8"
    Task = "Ensure 'ADBackupDSRMPassword' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
                -Name "ADBackupDSRMPassword" `
            | Select-Object -ExpandProperty "ADBackupDSRMPassword"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.9"
    Task = "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "MSAOptional" `
            | Select-Object -ExpandProperty "MSAOptional"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.10"
    Task = "Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "DisableAutomaticRestartSignOn" `
            | Select-Object -ExpandProperty "DisableAutomaticRestartSignOn"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.11"
    Task = "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "LocalAccountTokenFilterPolicy" `
            | Select-Object -ExpandProperty "LocalAccountTokenFilterPolicy"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.12"
    Task = "Ensure 'EnableMPR' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableMPR" `
            | Select-Object -ExpandProperty "EnableMPR"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.13"
    Task = "Ensure 'Include command line in process creation events' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
                -Name "ProcessCreationIncludeCmdLine_Enabled" `
            | Select-Object -ExpandProperty "ProcessCreationIncludeCmdLine_Enabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.14"
    Task = "Ensure 'Encryption Oracle Remediation' is set to 'Force Updated Clients'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" `
                -Name "AllowEncryptionOracle" `
            | Select-Object -ExpandProperty "AllowEncryptionOracle"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.15"
    Task = "Ensure 'Configure hash algorithms for certificate logon' is set to 'Default'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" `
                -Name "PKINITHashAlgorithmConfigurationEnabled" `
            | Select-Object -ExpandProperty "PKINITHashAlgorithmConfigurationEnabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.16"
    Task = "Set registry value 'PKINITSHA1' to x == 0"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" `
                -Name "PKINITSHA1" `
            | Select-Object -ExpandProperty "PKINITSHA1"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.17"
    Task = "Set registry value 'PKINITSHA256' to x == 3"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" `
                -Name "PKINITSHA256" `
            | Select-Object -ExpandProperty "PKINITSHA256"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.18"
    Task = "Set registry value 'PKINITSHA384' to x == 3"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" `
                -Name "PKINITSHA384" `
            | Select-Object -ExpandProperty "PKINITSHA384"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.19"
    Task = "Set registry value 'PKINITSHA512' to x == 3"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" `
                -Name "PKINITSHA512" `
            | Select-Object -ExpandProperty "PKINITSHA512"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.20"
    Task = "Set registry value 'PKInitHashAlgorithmConfigurationEnabled' to x == 1"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "PKInitHashAlgorithmConfigurationEnabled" `
            | Select-Object -ExpandProperty "PKInitHashAlgorithmConfigurationEnabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.21"
    Task = "Set registry value 'PKInitSHA1' to x == 0"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "PKInitSHA1" `
            | Select-Object -ExpandProperty "PKInitSHA1"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.22"
    Task = "Set registry value 'PKInitSHA256' to x == 3"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "PKInitSHA256" `
            | Select-Object -ExpandProperty "PKInitSHA256"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.23"
    Task = "Set registry value 'PKInitSHA384' to x == 3"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "PKInitSHA384" `
            | Select-Object -ExpandProperty "PKInitSHA384"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.24"
    Task = "Set registry value 'PKInitSHA512' to x == 3"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
                -Name "PKInitSHA512" `
            | Select-Object -ExpandProperty "PKInitSHA512"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.25"
    Task = "Ensure 'Configure enhanced anti-spoofing' set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" `
                -Name "EnhancedAntiSpoofing" `
            | Select-Object -ExpandProperty "EnhancedAntiSpoofing"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.26"
    Task = "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds" `
                -Name "DisableEnclosureDownload" `
            | Select-Object -ExpandProperty "DisableEnclosureDownload"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.27"
    Task = "Ensure 'Require a password when a computer wakes (on battery)' set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
                -Name "DCSettingIndex" `
            | Select-Object -ExpandProperty "DCSettingIndex"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.28"
    Task = "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" `
                -Name "ACSettingIndex" `
            | Select-Object -ExpandProperty "ACSettingIndex"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.29"
    Task = "Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Force Deny'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" `
                -Name "LetAppsActivateWithVoiceAboveLock" `
            | Select-Object -ExpandProperty "LetAppsActivateWithVoiceAboveLock"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.30"
    Task = "Ensure 'Enable remote mailslots' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Bowser" `
                -Name "EnableMailslots" `
            | Select-Object -ExpandProperty "EnableMailslots"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.31"
    Task = "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableWindowsConsumerFeatures" `
            | Select-Object -ExpandProperty "DisableWindowsConsumerFeatures"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.32"
    Task = "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation" `
                -Name "AllowProtectedCreds" `
            | Select-Object -ExpandProperty "AllowProtectedCreds"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.33"
    Task = "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application" `
                -Name "MaxSize" `
            | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 32768) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 32768"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.34"
    Task = "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security" `
                -Name "MaxSize" `
            | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 196608) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 196608"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.35"
    Task = "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System" `
                -Name "MaxSize" `
            | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 32768) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 32768"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.36"
    Task = "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" `
                -Name "NoAutoplayfornonVolume" `
            | Select-Object -ExpandProperty "NoAutoplayfornonVolume"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.37"
    Task = "Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" `
                -Name "DisableMotWOnInsecurePathCopy" `
            | Select-Object -ExpandProperty "DisableMotWOnInsecurePathCopy"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.38"
    Task = "Ensure 'Windows Game Recording and Broadcasting' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameDVR" `
                -Name "AllowGameDVR" `
            | Select-Object -ExpandProperty "AllowGameDVR"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.39"
    Task = "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" `
                -Name "AlwaysInstallElevated" `
            | Select-Object -ExpandProperty "AlwaysInstallElevated"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.40"
    Task = "Ensure 'Allow user control over installs' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" `
                -Name "EnableUserControl" `
            | Select-Object -ExpandProperty "EnableUserControl"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.41"
    Task = "Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Block all'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection" `
                -Name "DeviceEnumerationPolicy" `
            | Select-Object -ExpandProperty "DeviceEnumerationPolicy"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.42"
    Task = "Ensure 'Audit client does not support encryption' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanServer" `
                -Name "AuditClientDoesNotSupportEncryption" `
            | Select-Object -ExpandProperty "AuditClientDoesNotSupportEncryption"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.43"
    Task = "Ensure 'Audit client does not support signing' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanServer" `
                -Name "AuditClientDoesNotSupportSigning" `
            | Select-Object -ExpandProperty "AuditClientDoesNotSupportSigning"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.44"
    Task = "Ensure 'Audit insecure guest logon' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanServer" `
                -Name "AuditInsecureGuestLogon" `
            | Select-Object -ExpandProperty "AuditInsecureGuestLogon"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.45"
    Task = "Ensure 'Enable authentication rate limiter' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
                -Name "EnableAuthRateLimiter" `
            | Select-Object -ExpandProperty "EnableAuthRateLimiter"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.46"
    Task = "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanServer" `
                -Name "MaxSmb2Dialect" `
            | Select-Object -ExpandProperty "MaxSmb2Dialect"
        
            if ($regValue -ne 785) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 785"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.47"
    Task = "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.0.0'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanServer" `
                -Name "MinSmb2Dialect" `
            | Select-Object -ExpandProperty "MinSmb2Dialect"
        
            if ($regValue -ne 768) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 768"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.48"
    Task = "Ensure 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanServer" `
                -Name "InvalidAuthenticationDelayTimeInMs" `
            | Select-Object -ExpandProperty "InvalidAuthenticationDelayTimeInMs"
        
            if ($regValue -ne 2000) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2000"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.49"
    Task = "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "AllowInsecureGuestAuth" `
            | Select-Object -ExpandProperty "AllowInsecureGuestAuth"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.50"
    Task = "Ensure 'Audit insecure guest logon' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "AuditInsecureGuestLogon" `
            | Select-Object -ExpandProperty "AuditInsecureGuestLogon"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.51"
    Task = "Ensure 'Audit server does not support encryption' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "AuditServerDoesNotSupportEncryption" `
            | Select-Object -ExpandProperty "AuditServerDoesNotSupportEncryption"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.52"
    Task = "Ensure 'Audit server does not support signing' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "AuditServerDoesNotSupportSigning" `
            | Select-Object -ExpandProperty "AuditServerDoesNotSupportSigning"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.53"
    Task = "Ensure 'Mandate the maximum version of SMB' is set to 'Enabled: 3.1.1'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "MaxSmb2Dialect" `
            | Select-Object -ExpandProperty "MaxSmb2Dialect"
        
            if ($regValue -ne 785) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 785"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.54"
    Task = "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.0.0'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "MinSmb2Dialect" `
            | Select-Object -ExpandProperty "MinSmb2Dialect"
        
            if ($regValue -ne 768) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 768"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.55"
    Task = "Ensure 'Require Encryption' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
                -Name "RequireEncryption" `
            | Select-Object -ExpandProperty "RequireEncryption"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.56"
    Task = "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections" `
                -Name "NC_ShowSharedAccessUI" `
            | Select-Object -ExpandProperty "NC_ShowSharedAccessUI"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.57"
    Task = "Ensure 'Enable remote mailslots' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" `
                -Name "EnableMailslots" `
            | Select-Object -ExpandProperty "EnableMailslots"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.58"
    Task = "Ensure 'Hardened UNC Paths' is set to `"Require Mutual Authentication=1, `"Require Integrity=1`" for `"\\*\SYSVOL`""
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
                -Name "\\*\SYSVOL" `
            | Select-Object -ExpandProperty "\\*\SYSVOL"
        
            if ($regValue -ne "RequireMutualAuthentication=1,RequireIntegrity=1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 'RequireMutualAuthentication=1'"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.59"
    Task = "Ensure 'Hardened UNC Paths' is set to `"Require Mutual Authentication=1, `"Require Integrity=1`" for `"\\*\NETLOGON`""
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
                -Name "\\*\NETLOGON" `
            | Select-Object -ExpandProperty "\\*\NETLOGON"
        
            if ($regValue -ne "RequireMutualAuthentication=1,RequireIntegrity=1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 'RequireMutualAuthentication=1'"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.60"
    Task = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" `
                -Name "NoLockScreenCamera" `
            | Select-Object -ExpandProperty "NoLockScreenCamera"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.61"
    Task = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" `
                -Name "NoLockScreenSlideshow" `
            | Select-Object -ExpandProperty "NoLockScreenSlideshow"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.62"
    Task = "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled' (EnableScriptBlockLogging)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                -Name "EnableScriptBlockLogging" `
            | Select-Object -ExpandProperty "EnableScriptBlockLogging"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.63"
    Task = "Ensure 'Turn on PowerShell Script Block Logging: Log script block invocation start / stop events' is not set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                -Name "EnableScriptBlockInvocationLogging" `
            | Select-Object -ExpandProperty "EnableScriptBlockInvocationLogging"
        
            return @{
                Status  = "False"
                Message = "Registry value found."
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
    Id   = "4.1.64"
    Task = "Ensure 'Configure the behavior of the sudo command' is set to 'Enabled: Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Sudo" `
                -Name "Enabled" `
            | Select-Object -ExpandProperty "Enabled"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.65"
    Task = "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "AllowDomainPINLogon" `
            | Select-Object -ExpandProperty "AllowDomainPINLogon"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.66"
    Task = "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "EnumerateLocalUsers" `
            | Select-Object -ExpandProperty "EnumerateLocalUsers"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.67"
    Task = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (EnableSmartScreen)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "EnableSmartScreen" `
            | Select-Object -ExpandProperty "EnableSmartScreen"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.68"
    Task = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (ShellSmartScreenLevel)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "ShellSmartScreenLevel" `
            | Select-Object -ExpandProperty "ShellSmartScreenLevel"
        
            if ($regValue -ne "Block") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: Block"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.69"
    Task = "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "AllowCustomSSPsAPs" `
            | Select-Object -ExpandProperty "AllowCustomSSPsAPs"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.70"
    Task = "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "RunAsPPL" `
            | Select-Object -ExpandProperty "RunAsPPL"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.71"
    Task = "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
                -Name "fBlockNonDomain" `
            | Select-Object -ExpandProperty "fBlockNonDomain"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.72"
    Task = "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" `
                -Name "AllowIndexingEncryptedStoresOrItems" `
            | Select-Object -ExpandProperty "AllowIndexingEncryptedStoresOrItems"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.73"
    Task = "Ensure 'Disallow Digest authentication' is set to 'Enabled' (Client)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowDigest" `
            | Select-Object -ExpandProperty "AllowDigest"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.74"
    Task = "Ensure 'Allow unencrypted traffic' is set to 'Disabled' (Client)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowUnencryptedTraffic" `
            | Select-Object -ExpandProperty "AllowUnencryptedTraffic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.75"
    Task = "Ensure 'Allow Basic authentication' is set to 'Disabled' (Client)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
                -Name "AllowBasic" `
            | Select-Object -ExpandProperty "AllowBasic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.76"
    Task = "Ensure 'Allow unencrypted traffic' is set to 'Disabled' (Service)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "AllowUnencryptedTraffic" `
            | Select-Object -ExpandProperty "AllowUnencryptedTraffic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.77"
    Task = "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled' (Service)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "DisableRunAs" `
            | Select-Object -ExpandProperty "DisableRunAs"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.78"
    Task = "Ensure 'Allow Basic authentication' is set to 'Disabled' (Service)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" `
                -Name "AllowBasic" `
            | Select-Object -ExpandProperty "AllowBasic"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.79"
    Task = "Ensure 'Notify Malicious' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "NotifyMalicious" `
            | Select-Object -ExpandProperty "NotifyMalicious"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.80"
    Task = "Ensure 'Notify Password Reuse' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "NotifyPasswordReuse" `
            | Select-Object -ExpandProperty "NotifyPasswordReuse"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.81"
    Task = "Ensure 'Notify Unsafe App' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "NotifyUnsafeApp" `
            | Select-Object -ExpandProperty "NotifyUnsafeApp"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.82"
    Task = "Ensure 'Service Enabled' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WTDS\Components" `
                -Name "ServiceEnabled" `
            | Select-Object -ExpandProperty "ServiceEnabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.83"
    Task = "Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" `
                -Name "EnableMulticast" `
            | Select-Object -ExpandProperty "EnableMulticast"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.84"
    Task = "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                -Name "EnableNetBIOS" `
            | Select-Object -ExpandProperty "EnableNetBIOS"
        
            if ($regValue -ne 2 -and $regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant values: 0, 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.85"
    Task = "Ensure 'Turn off downloading of print drivers over HTTP' set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" `
                -Name "DisableWebPnPDownload" `
            | Select-Object -ExpandProperty "DisableWebPnPDownload"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.86"
    Task = "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" `
                -Name "RedirectionGuardPolicy" `
            | Select-Object -ExpandProperty "RedirectionGuardPolicy"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.87"
    Task = "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
                -Name "CopyFilesPolicy" `
            | Select-Object -ExpandProperty "CopyFilesPolicy"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.88"
    Task = "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
                -Name "RestrictDriverInstallationToAdministrators" `
            | Select-Object -ExpandProperty "RestrictDriverInstallationToAdministrators"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.89"
    Task = "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcUseNamedPipeProtocol" `
            | Select-Object -ExpandProperty "RpcUseNamedPipeProtocol"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.90"
    Task = "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcAuthentication" `
            | Select-Object -ExpandProperty "RpcAuthentication"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.91"
    Task = "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcProtocols" `
            | Select-Object -ExpandProperty "RpcProtocols"
        
            if ($regValue -ne 5) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 5"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.92"
    Task = "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "ForceKerberosForRpc" `
            | Select-Object -ExpandProperty "ForceKerberosForRpc"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.93"
    Task = "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC" `
                -Name "RpcTcpPort" `
            | Select-Object -ExpandProperty "RpcTcpPort"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.94"
    Task = "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Authenticated'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" `
                -Name "RestrictRemoteClients" `
            | Select-Object -ExpandProperty "RestrictRemoteClients"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.95"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (fUseMailto)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fUseMailto" `
            | Select-Object -ExpandProperty "fUseMailto"
        
            return @{
                Status  = "False"
                Message = "Registry value found."
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
    Id   = "4.1.96"
    Task = "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fAllowToGetHelp" `
            | Select-Object -ExpandProperty "fAllowToGetHelp"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.97"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (fAllowFullControl)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fAllowFullControl" `
            | Select-Object -ExpandProperty "fAllowFullControl"
        
            return @{
                Status  = "False"
                Message = "Registry value found."
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
    Id   = "4.1.98"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (MaxTicketExpiry)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxTicketExpiry" `
            | Select-Object -ExpandProperty "MaxTicketExpiry"
        
            return @{
                Status  = "False"
                Message = "Registry value found."
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
    Id   = "4.1.99"
    Task = "Ensure 'Configure Solicited Remote Assistance' is not set (MaxTicketExpiryUnits)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxTicketExpiryUnits" `
            | Select-Object -ExpandProperty "MaxTicketExpiryUnits"
        
            return @{
                Status  = "False"
                Message = "Registry value found."
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
    Id   = "4.1.100"
    Task = "Ensure 'Set client connection encryption level' is set to 'High Level'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MinEncryptionLevel" `
            | Select-Object -ExpandProperty "MinEncryptionLevel"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.101"
    Task = "Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fPromptForPassword" `
            | Select-Object -ExpandProperty "fPromptForPassword"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.102"
    Task = "Ensure 'Do not allow drive redirection' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableCdm" `
            | Select-Object -ExpandProperty "fDisableCdm"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.103"
    Task = "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "DisablePasswordSaving" `
            | Select-Object -ExpandProperty "DisablePasswordSaving"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.104"
    Task = "Ensure 'Require secure RPC communication' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fEncryptRPCTraffic" `
            | Select-Object -ExpandProperty "fEncryptRPCTraffic"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.106"
    Task = "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "DefaultOutboundAction" `
            | Select-Object -ExpandProperty "DefaultOutboundAction"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.107"
    Task = "Ensure 'Windows Defender Firewall: Prohibit notifications' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "DisableNotifications" `
            | Select-Object -ExpandProperty "DisableNotifications"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.108"
    Task = "Ensure 'Windows Defender Firewall: Protect all network connections' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "EnableFirewall" `
            | Select-Object -ExpandProperty "EnableFirewall"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.109"
    Task = "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" `
                -Name "DefaultInboundAction" `
            | Select-Object -ExpandProperty "DefaultInboundAction"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.110"
    Task = "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
                -Name "LogDroppedPackets" `
            | Select-Object -ExpandProperty "LogDroppedPackets"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.111"
    Task = "Ensure 'Windows Defender Firewall: Allow logging' is set to '16384' (LogFileSize)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
                -Name "LogFileSize" `
            | Select-Object -ExpandProperty "LogFileSize"
        
            if ($regValue -ne 16384) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 16384"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.112"
    Task = "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
                -Name "LogSuccessfulConnections" `
            | Select-Object -ExpandProperty "LogSuccessfulConnections"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.113"
    Task = "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "EnableFirewall" `
            | Select-Object -ExpandProperty "EnableFirewall"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.114"
    Task = "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "DisableNotifications" `
            | Select-Object -ExpandProperty "DisableNotifications"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.115"
    Task = "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "DefaultInboundAction" `
            | Select-Object -ExpandProperty "DefaultInboundAction"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.116"
    Task = "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
                -Name "DefaultOutboundAction" `
            | Select-Object -ExpandProperty "DefaultOutboundAction"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.117"
    Task = "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
                -Name "LogSuccessfulConnections" `
            | Select-Object -ExpandProperty "LogSuccessfulConnections"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.118"
    Task = "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
                -Name "LogDroppedPackets" `
            | Select-Object -ExpandProperty "LogDroppedPackets"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.119"
    Task = "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
                -Name "LogFileSize" `
            | Select-Object -ExpandProperty "LogFileSize"
        
            if ($regValue -ne 16384) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 16384"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.120"
    Task = "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "DefaultOutboundAction" `
            | Select-Object -ExpandProperty "DefaultOutboundAction"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.121"
    Task = "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "EnableFirewall" `
            | Select-Object -ExpandProperty "EnableFirewall"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.122"
    Task = "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "DisableNotifications" `
            | Select-Object -ExpandProperty "DisableNotifications"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.123"
    Task = "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "AllowLocalIPsecPolicyMerge" `
            | Select-Object -ExpandProperty "AllowLocalIPsecPolicyMerge"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.124"
    Task = "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "AllowLocalPolicyMerge" `
            | Select-Object -ExpandProperty "AllowLocalPolicyMerge"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.125"
    Task = "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" `
                -Name "DefaultInboundAction" `
            | Select-Object -ExpandProperty "DefaultInboundAction"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.126"
    Task = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' set to '16,384' KB"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
                -Name "LogFileSize" `
            | Select-Object -ExpandProperty "LogFileSize"
        
            if ($regValue -ne 16384) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 16384"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.127"
    Task = "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
                -Name "LogDroppedPackets" `
            | Select-Object -ExpandProperty "LogDroppedPackets"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.128"
    Task = "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
                -Name "LogSuccessfulConnections" `
            | Select-Object -ExpandProperty "LogSuccessfulConnections"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.129"
    Task = "Ensure 'Allow Windows Ink Workspace' is set to 'On, but disallow access above lock'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace" `
                -Name "AllowWindowsInkWorkspace" `
            | Select-Object -ExpandProperty "AllowWindowsInkWorkspace"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.130"
    Task = "Ensure 'LSA Protection' is set to 'Enabled' [Legacy, MS Security Guide]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RunAsPPL" `
            | Select-Object -ExpandProperty "RunAsPPL"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.131"
    Task = "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print" `
                -Name "RpcAuthnLevelPrivacyEnabled" `
            | Select-Object -ExpandProperty "RpcAuthnLevelPrivacyEnabled"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.132"
    Task = "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
                -Name "DisableExceptionChainValidation" `
            | Select-Object -ExpandProperty "DisableExceptionChainValidation"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.133"
    Task = "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
                -Name "DriverLoadPolicy" `
            | Select-Object -ExpandProperty "DriverLoadPolicy"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.134"
    Task = "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                -Name "SMB1" `
            | Select-Object -ExpandProperty "SMB1"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.135"
    Task = "Ensure 'Configure SMB v1 client driver' is set to 'Disable driver (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MrxSmb10" `
                -Name "Start" `
            | Select-Object -ExpandProperty "Start"
        
            if ($regValue -ne 4) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 4"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.136"
    Task = "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" `
                -Name "NoNameReleaseOnDemand" `
            | Select-Object -ExpandProperty "NoNameReleaseOnDemand"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.137"
    Task = "Ensure 'NetBT NodeType configuration' is set to 'P-node (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" `
                -Name "NodeType" `
            | Select-Object -ExpandProperty "NodeType"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.138"
    Task = "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" `
                -Name "EnableICMPRedirect" `
            | Select-Object -ExpandProperty "EnableICMPRedirect"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.139"
    Task = "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Highest protection, source routing is completely disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
                -Name "DisableIPSourceRouting" `
            | Select-Object -ExpandProperty "DisableIPSourceRouting"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.140"
    Task = "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Highest protection, source routing is completely disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
                -Name "DisableIPSourceRouting" `
            | Select-Object -ExpandProperty "DisableIPSourceRouting"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.2"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Enhanced Privilege Protection Mode' is set to 'Prompt for consent on the secure desktop'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorEnhancedAdmin" `
            | Select-Object -ExpandProperty "ConsentPromptBehaviorEnhancedAdmin"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.3"
    Task = "Ensure 'User Account Control: Configure type of Admin Approval Mode' is set to 'Admin Approval Mode is running with enhanced privilege protection'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "TypeOfAdminApprovalMode" `
            | Select-Object -ExpandProperty "TypeOfAdminApprovalMode"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.4"
    Task = "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                -Name "ScRemoveOption" `
            | Select-Object -ExpandProperty "ScRemoveOption"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.5"
    Task = "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 seconds'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "InactivityTimeoutSecs" `
            | Select-Object -ExpandProperty "InactivityTimeoutSecs"
        
            if ($regValue -ne 900) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 900"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.6"
    Task = "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "EnablePlainTextPassword" `
            | Select-Object -ExpandProperty "EnablePlainTextPassword"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.7"
    Task = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "LimitBlankPasswordUse" `
            | Select-Object -ExpandProperty "LimitBlankPasswordUse"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.8"
    Task = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "RestrictAnonymousSAM" `
            | Select-Object -ExpandProperty "RestrictAnonymousSAM"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.9"
    Task = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "RestrictAnonymous" `
            | Select-Object -ExpandProperty "RestrictAnonymous"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.10"
    Task = "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "RestrictNullSessAccess" `
            | Select-Object -ExpandProperty "RestrictNullSessAccess"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.11"
    Task = "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "SCENoApplyLegacyAuditPolicy" `
            | Select-Object -ExpandProperty "SCENoApplyLegacyAuditPolicy"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.12"
    Task = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "NTLMMinClientSec" `
            | Select-Object -ExpandProperty "NTLMMinClientSec"
        
            if ($regValue -ne 537395200) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 537395200"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.13"
    Task = "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM&NTLM'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
                -Name "LmCompatibilityLevel" `
            | Select-Object -ExpandProperty "LmCompatibilityLevel"
        
            if ($regValue -ne 5) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 5"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.14"
    Task = "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "allownullsessionfallback" `
            | Select-Object -ExpandProperty "allownullsessionfallback"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.15"
    Task = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "NTLMMinServerSec" `
            | Select-Object -ExpandProperty "NTLMMinServerSec"
        
            if ($regValue -ne 537395200) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 537395200"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.16"
    Task = "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RequireStrongKey" `
            | Select-Object -ExpandProperty "RequireStrongKey"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.17"
    Task = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                -Name "RequireSecuritySignature" `
            | Select-Object -ExpandProperty "RequireSecuritySignature"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.18"
    Task = "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "sealsecurechannel" `
            | Select-Object -ExpandProperty "sealsecurechannel"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.19"
    Task = "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "RequireSignOrSeal" `
            | Select-Object -ExpandProperty "RequireSignOrSeal"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.20"
    Task = "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "SignSecureChannel" `
            | Select-Object -ExpandProperty "SignSecureChannel"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.21"
    Task = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" `
                -Name "RequireSecuritySignature" `
            | Select-Object -ExpandProperty "RequireSecuritySignature"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.22"
    Task = "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" `
                -Name "ProtectionMode" `
            | Select-Object -ExpandProperty "ProtectionMode"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.23"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorAdmin" `
            | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin"
        
            if ($regValue -ne 2) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.24"
    Task = "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableSecureUIAPaths" `
            | Select-Object -ExpandProperty "EnableSecureUIAPaths"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.25"
    Task = "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableLUA" `
            | Select-Object -ExpandProperty "EnableLUA"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.26"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorUser" `
            | Select-Object -ExpandProperty "ConsentPromptBehaviorUser"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.27"
    Task = "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableInstallerDetection" `
            | Select-Object -ExpandProperty "EnableInstallerDetection"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.28"
    Task = "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "FilterAdministratorToken" `
            | Select-Object -ExpandProperty "FilterAdministratorToken"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.29"
    Task = "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "EnableVirtualization" `
            | Select-Object -ExpandProperty "EnableVirtualization"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.30"
    Task = "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" `
                -Name "LDAPClientIntegrity" `
            | Select-Object -ExpandProperty "LDAPClientIntegrity"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.31"
    Task = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RestrictRemoteSAM" `
            | Select-Object -ExpandProperty "RestrictRemoteSAM"
        
            if ($regValue -ne "O:BAG:BAD:(A;;RC;;;BA)") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: O:BAG:BAD:(A;;RC;;;BA)"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "4.3.32"
    Task = "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "DisablePasswordChange" `
            | Select-Object -ExpandProperty "DisablePasswordChange"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.1"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "EnableVirtualizationBasedSecurity" `
            | Select-Object -ExpandProperty "EnableVirtualizationBasedSecurity"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.2"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Secure Boot'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "RequirePlatformSecurityFeatures" `
            | Select-Object -ExpandProperty "RequirePlatformSecurityFeatures"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.3"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled with UEFI lock'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "HypervisorEnforcedCodeIntegrity" `
            | Select-Object -ExpandProperty "HypervisorEnforcedCodeIntegrity"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.4"
    Task = "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "HVCIMATRequired" `
            | Select-Object -ExpandProperty "HVCIMATRequired"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.5"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled with UEFI lock'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "LsaCfgFlags" `
            | Select-Object -ExpandProperty "LsaCfgFlags"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.6"
    Task = "Ensure 'Turn On Virtualization Based Security: Machine Identity Isolation Configuration' is set to 'Enabled: Enabled in enforcement mode'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "MachineIdentityIsolation" `
            | Select-Object -ExpandProperty "MachineIdentityIsolation"
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.7"
    Task = "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "ConfigureSystemGuardLaunch" `
            | Select-Object -ExpandProperty "ConfigureSystemGuardLaunch"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.8"
    Task = "Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "ConfigureKernelShadowStacksLaunch" `
            | Select-Object -ExpandProperty "ConfigureKernelShadowStacksLaunch"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.1"
    Task = "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.2"
    Task = "Ensure 'Configure local administrator merge behavior for lists' is set to 'Disabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" `
                -Name "DisableLocalAdminMerge" `
            | Select-Object -ExpandProperty "DisableLocalAdminMerge"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.3"
    Task = "Set registry value 'HideExclusionsFromLocalAdmins' to x == 1"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" `
                -Name "HideExclusionsFromLocalAdmins" `
            | Select-Object -ExpandProperty "HideExclusionsFromLocalAdmins"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.4"
    Task = "Ensure 'Turn off routine remediation' is set to 'Disabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" `
                -Name "DisableRoutinelyTakingAction" `
            | Select-Object -ExpandProperty "DisableRoutinelyTakingAction"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.5"
    Task = "Ensure 'Enable EDR in block mode' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Features" `
                -Name "PassiveRemediation" `
            | Select-Object -ExpandProperty "PassiveRemediation"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.6"
    Task = "Ensure 'Select cloud protection level' is set to 'Enabled:High blocking level'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.7"
    Task = "Ensure 'Configure extended cloud check' is set to 'Enabled' and set to '50'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine" `
                -Name "MpBafsExtendedTimeout" `
            | Select-Object -ExpandProperty "MpBafsExtendedTimeout"
        
            if ($regValue -ne 50) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 50"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.8"
    Task = "Ensure 'Convert warn verdict to block' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\NIS" `
                -Name "EnableConvertWarnToBlock" `
            | Select-Object -ExpandProperty "EnableConvertWarnToBlock"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.9"
    Task = "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.10"
    Task = "Ensure 'Turn off real-time protection' is set to 'Disabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.11"
    Task = "Ensure 'Turn on script scanning' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.12"
    Task = "Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.13"
    Task = "Ensure 'Configure monitoring for incoming and outgoing file and program activity' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "RealtimeScanDirection" `
            | Select-Object -ExpandProperty "RealtimeScanDirection"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.14"
    Task = "Ensure 'Monitor file and program activity on your computer' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableOnAccessProtection" `
            | Select-Object -ExpandProperty "DisableOnAccessProtection"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.15"
    Task = "Ensure 'Turn on process scanning whenever real-time protection is enabled' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableScanOnRealtimeEnable" `
            | Select-Object -ExpandProperty "DisableScanOnRealtimeEnable"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.16"
    Task = "Ensure 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "OobeEnableRtpAndSigUpdate" `
            | Select-Object -ExpandProperty "OobeEnableRtpAndSigUpdate"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.17"
    Task = "Ensure 'Configure whether to report Dynamic Signature dropped events' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Reporting" `
                -Name "EnableDynamicSignatureDroppedEventReporting" `
            | Select-Object -ExpandProperty "EnableDynamicSignatureDroppedEventReporting"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.18"
    Task = "Ensure 'Scan removable drives' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan" `
                -Name "DisableRemovableDriveScanning" `
            | Select-Object -ExpandProperty "DisableRemovableDriveScanning"
        
            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.19"
    Task = "Ensure 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
                -Name "QuickScanIncludeExclusions" `
            | Select-Object -ExpandProperty "QuickScanIncludeExclusions"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.20"
    Task = "Ensure 'Join Microsoft MAPS' is set to 'Enabled': 'Advanced MAPS'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.21"
    Task = "Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 0"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.22"
    Task = "Ensure 'Send file samples when further analysis is required' is set to 'Send all samples'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
        
            if ($regValue -ne 3) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 3"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.23"
    Task = "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
                -Name "ExploitGuard_ASR_Rules" `
            | Select-Object -ExpandProperty "ExploitGuard_ASR_Rules"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.24"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block Office applications from injecting code into other processes'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" `
            | Select-Object -ExpandProperty "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.25"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block Office applications from creating executable content'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "3b576869-a4ec-4529-8536-b80a7769e899" `
            | Select-Object -ExpandProperty "3b576869-a4ec-4529-8536-b80a7769e899"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.26"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block Office applications from creating child processes'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "d4f940ab-401b-4efc-aadc-ad5f3c50688a" `
            | Select-Object -ExpandProperty "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.27"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block Win32 API calls from Office macro'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" `
            | Select-Object -ExpandProperty "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.28"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block execution of potentially obfuscated scripts'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "5beb7efe-fd9a-4556-801d-275e5ffc04cc" `
            | Select-Object -ExpandProperty "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.29"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block JavaScript or VBScript from launching downloaded executable content'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "d3e037e1-3eb8-44c8-a917-57927947596d" `
            | Select-Object -ExpandProperty "d3e037e1-3eb8-44c8-a917-57927947596d"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.30"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block executable content from email client and webmail'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" `
            | Select-Object -ExpandProperty "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.31"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block credential stealing from the Windows local security authority subsystem (lsass.exe)'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" `
            | Select-Object -ExpandProperty "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.32"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block untrusted and unsigned processes that run from USB' is configured"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" `
            | Select-Object -ExpandProperty "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.33"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block Office communication application from creating child processes'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "26190899-1602-49e8-8b27-eb1d0a1ce869" `
            | Select-Object -ExpandProperty "26190899-1602-49e8-8b27-eb1d0a1ce869"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.34"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block Adobe Reader from creating child processes'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" `
            | Select-Object -ExpandProperty "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.35"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Use advanced protection against ransomware'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.36"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block persistence through WMI event subscription'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "e6db77e5-3df2-4cf1-b95a-636979351e5b" `
            | Select-Object -ExpandProperty "e6db77e5-3df2-4cf1-b95a-636979351e5b"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.37"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Block abuse of exploited vulnerable signed drivers'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "56a863a9-875e-4185-98a7-b882c64b5ce5" `
            | Select-Object -ExpandProperty "56a863a9-875e-4185-98a7-b882c64b5ce5"
        
            if ($regValue -ne "1") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.38"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block process creations originating from PSExec and WMI commands)"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status  = "None"
                    }
                }
            }    
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
                -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" `
            | Select-Object -ExpandProperty "d1e49aac-8f56-4280-b9ba-993a6d77406c"
        
            if ($regValue -ne "2") {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 2"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.39"
    Task = "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
    Test = {
        try {
            if ($avstatus) {
                if (-not $windefrunning) {
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
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "8.2.1"
    Task = "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableThirdPartySuggestions" `
            | Select-Object -ExpandProperty "DisableThirdPartySuggestions"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "8.2.2"
    Task = "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" `
                -Name "NoToastApplicationNotificationOnLockScreen" `
            | Select-Object -ExpandProperty "NoToastApplicationNotificationOnLockScreen"
        
            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Compliant value: 1"
                    Status  = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status  = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
