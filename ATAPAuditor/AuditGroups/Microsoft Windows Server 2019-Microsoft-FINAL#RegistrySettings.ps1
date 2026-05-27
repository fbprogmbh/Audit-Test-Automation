$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$windefrunning = CheckWindefRunning
. "$RootPath\Helpers\Firewall.ps1"
[AuditTest] @{
    Id = "Registry-001"
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
    Id = "Registry-002"
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
    Id = "Registry-003"
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
    Id = "Registry-004"
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
    Id = "Registry-005"
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
    Id = "Registry-006"
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
    Id = "Registry-007"
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
    Id = "Registry-008"
    Task = "Set registry value '(Reserved)' to 1. (FEATURE_DISABLE_MK_PROTOCOL)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "(Reserved)" `
                | Select-Object -ExpandProperty "(Reserved)"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-009"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_DISABLE_MK_PROTOCOL)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "iexplore.exe" `
                | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-010"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_DISABLE_MK_PROTOCOL)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" `
                -Name "explorer.exe" `
                | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-011"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_MIME_HANDLING)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                -Name "explorer.exe" `
                | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-012"
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
    Id = "Registry-013"
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
    Id = "Registry-014"
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
    Id = "Registry-015"
    Task = "Set registry value 'iexplore.exe' to 1. (FEATURE_MIME_SNIFFING)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                -Name "iexplore.exe" `
                | Select-Object -ExpandProperty "iexplore.exe"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-016"
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
    Id = "Registry-017"
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
    Id = "Registry-018"
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
    Id = "Registry-019"
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
    Id = "Registry-020"
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
    Id = "Registry-021"
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
    Id = "Registry-022"
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
    Id = "Registry-023"
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
    Id = "Registry-024"
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
    Id = "Registry-025"
    Task = "Set registry value 'explorer.exe' to 1. (FEATURE_SECURITYBAND)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                -Name "explorer.exe" `
                | Select-Object -ExpandProperty "explorer.exe"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-026"
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
    Id = "Registry-027"
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
    Id = "Registry-028"
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
    Id = "Registry-029"
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
    Id = "Registry-030"
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
    Id = "Registry-031"
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
    Id = "Registry-032"
    Task = "Set registry value 'PreventOverrideAppRepUnknown' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "PreventOverrideAppRepUnknown" `
                | Select-Object -ExpandProperty "PreventOverrideAppRepUnknown"
        
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
    Id = "Registry-033"
    Task = "Set registry value 'PreventOverride' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" `
                -Name "PreventOverride" `
                | Select-Object -ExpandProperty "PreventOverride"
        
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
    Id = "Registry-034"
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
    Id = "Registry-035"
    Task = "Set registry value 'NoCrashDetection' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Restrictions" `
                -Name "NoCrashDetection" `
                | Select-Object -ExpandProperty "NoCrashDetection"
        
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
    Id = "Registry-036"
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
    Id = "Registry-037"
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
    Id = "Registry-038"
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
    Id = "Registry-039"
    Task = "Set registry value 'Security_zones_map_edit' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_zones_map_edit" `
                | Select-Object -ExpandProperty "Security_zones_map_edit"
        
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
    Id = "Registry-040"
    Task = "Set registry value 'Security_options_edit' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_options_edit" `
                | Select-Object -ExpandProperty "Security_options_edit"
        
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
    Id = "Registry-041"
    Task = "Set registry value 'Security_HKLM_only' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "Security_HKLM_only" `
                | Select-Object -ExpandProperty "Security_HKLM_only"
        
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
    Id = "Registry-042"
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
    Id = "Registry-043"
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
    Id = "Registry-044"
    Task = "Set registry value 'WarnOnBadCertRecving' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "WarnOnBadCertRecving" `
                | Select-Object -ExpandProperty "WarnOnBadCertRecving"
        
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
    Id = "Registry-045"
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
    Id = "Registry-046"
    Task = "Ensure 'Turn off encryption support' is set to 'Use TLS 1.1 and TLS 1.2'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
                -Name "SecureProtocols" `
                | Select-Object -ExpandProperty "SecureProtocols"
        
            if ($regValue -ne 2560) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 2560"
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
    Id = "Registry-047"
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
    Id = "Registry-048"
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
    Id = "Registry-049"
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
    Id = "Registry-050"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'. [Lockdown_Zones\3]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" `
                -Name "2301" `
                | Select-Object -ExpandProperty "2301"
        
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
    Id = "Registry-051"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'. [Lockdown_Zones\4]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" `
                -Name "2301" `
                | Select-Object -ExpandProperty "2301"
        
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
    Id = "Registry-052"
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
    Id = "Registry-053"
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
    Id = "Registry-054"
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
    Id = "Registry-055"
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
    Id = "Registry-056"
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
    Id = "Registry-057"
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
    Id = "Registry-058"
    Task = "Ensure 'Java permissions' is set to 'High safety'. (Zones/1)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" `
                -Name "1C00" `
                | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 65536) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 65536"
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
    Id = "Registry-059"
    Task = "Ensure 'Java permissions' is set to 'High safety'. (Zones/2)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" `
                -Name "1C00" `
                | Select-Object -ExpandProperty "1C00"
        
            if ($regValue -ne 65536) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 65536"
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
    Id = "Registry-060"
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
    Id = "Registry-061"
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
    Id = "Registry-062"
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
    Id = "Registry-063"
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
    Id = "Registry-064"
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
    Id = "Registry-065"
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
    Id = "Registry-066"
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
    Id = "Registry-067"
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
    Id = "Registry-068"
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
    Id = "Registry-069"
    Task = "Ensure 'Automatic prompting for file downloads' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2200" `
                | Select-Object -ExpandProperty "2200"
        
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
    Id = "Registry-070"
    Task = "Ensure 'Allow scriptlets' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1209" `
                | Select-Object -ExpandProperty "1209"
        
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
    Id = "Registry-071"
    Task = "Ensure 'Allow scripting of Internet Explorer WebBrowser controls' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1206" `
                | Select-Object -ExpandProperty "1206"
        
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
    Id = "Registry-072"
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
    Id = "Registry-073"
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
    Id = "Registry-074"
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
    Id = "Registry-075"
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
    Id = "Registry-076"
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
    Id = "Registry-077"
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
    Id = "Registry-078"
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
    Id = "Registry-079"
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
    Id = "Registry-080"
    Task = "Ensure 'Logon options' is set to 'Prompt for user name and password'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1A00" `
                | Select-Object -ExpandProperty "1A00"
        
            if ($regValue -ne 65536) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 65536"
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
    Id = "Registry-081"
    Task = "Ensure 'Enable dragging of content from different domains within a window' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2708" `
                | Select-Object -ExpandProperty "2708"
        
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
    Id = "Registry-082"
    Task = "Ensure 'Download unsigned ActiveX controls' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1004" `
                | Select-Object -ExpandProperty "1004"
        
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
    Id = "Registry-083"
    Task = "Ensure 'Allow only approved domains to use ActiveX controls without prompt' is set to 'Enable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "120b" `
                | Select-Object -ExpandProperty "120b"
        
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
    Id = "Registry-084"
    Task = "Ensure 'Allow cut, copy or paste operations from the clipboard via script' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1407" `
                | Select-Object -ExpandProperty "1407"
        
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
    Id = "Registry-085"
    Task = "Ensure 'Turn on Cross-Site Scripting Filter' is set to 'Enable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1409" `
                | Select-Object -ExpandProperty "1409"
        
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
    Id = "Registry-086"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "270C" `
                | Select-Object -ExpandProperty "270C"
        
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
    Id = "Registry-087"
    Task = "Ensure 'Navigate windows and frames across different domains' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1607" `
                | Select-Object -ExpandProperty "1607"
        
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
    Id = "Registry-088"
    Task = "Ensure 'Enable dragging of content from different domains across windows' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2709" `
                | Select-Object -ExpandProperty "2709"
        
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
    Id = "Registry-089"
    Task = "Ensure 'Web sites in less privileged Web content zones can navigate into this zone' is set to 'Disable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2101" `
                | Select-Object -ExpandProperty "2101"
        
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
    Id = "Registry-090"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'. [Zones\3]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2301" `
                | Select-Object -ExpandProperty "2301"
        
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
    Id = "Registry-091"
    Task = "Ensure 'Show security warning for potentially unsafe files' is set to 'Prompt'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1806" `
                | Select-Object -ExpandProperty "1806"
        
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
    Id = "Registry-092"
    Task = "Ensure 'Allow only approved domains to use the TDC ActiveX control' is set to 'Enable'. (Zones/3)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "120c" `
                | Select-Object -ExpandProperty "120c"
        
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
    Id = "Registry-093"
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
    Id = "Registry-094"
    Task = "Ensure 'Allow META REFRESH' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1608" `
                | Select-Object -ExpandProperty "1608"
        
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
    Id = "Registry-095"
    Task = "Ensure 'Initialize and script ActiveX controls not marked as safe' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1201" `
                | Select-Object -ExpandProperty "1201"
        
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
    Id = "Registry-096"
    Task = "Ensure 'Download signed ActiveX controls' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1001" `
                | Select-Object -ExpandProperty "1001"
        
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
    Id = "Registry-097"
    Task = "Ensure 'Navigate windows and frames across different domains' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1607" `
                | Select-Object -ExpandProperty "1607"
        
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
    Id = "Registry-098"
    Task = "Ensure 'Allow only approved domains to use ActiveX controls without prompt' is set to 'Enable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "120b" `
                | Select-Object -ExpandProperty "120b"
        
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
    Id = "Registry-099"
    Task = "Ensure 'Use Pop-up Blocker' is set to 'Enable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1809" `
                | Select-Object -ExpandProperty "1809"
        
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
    Id = "Registry-100"
    Task = "Ensure 'Download unsigned ActiveX controls' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1004" `
                | Select-Object -ExpandProperty "1004"
        
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
    Id = "Registry-101"
    Task = "Ensure 'Userdata persistence' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1606" `
                | Select-Object -ExpandProperty "1606"
        
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
    Id = "Registry-102"
    Task = "Ensure 'Allow cut, copy or paste operations from the clipboard via script' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1407" `
                | Select-Object -ExpandProperty "1407"
        
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
    Id = "Registry-103"
    Task = "Ensure 'Include local path when user is uploading files to a server' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "160A" `
                | Select-Object -ExpandProperty "160A"
        
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
    Id = "Registry-104"
    Task = "Ensure 'Access data sources across domains' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1406" `
                | Select-Object -ExpandProperty "1406"
        
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
    Id = "Registry-105"
    Task = "Ensure 'Allow script-initiated windows without size or position constraints' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2102" `
                | Select-Object -ExpandProperty "2102"
        
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
    Id = "Registry-106"
    Task = "Ensure 'Run .NET Framework-reliant components not signed with Authenticode' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2004" `
                | Select-Object -ExpandProperty "2004"
        
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
    Id = "Registry-107"
    Task = "Ensure 'Automatic prompting for file downloads' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2200" `
                | Select-Object -ExpandProperty "2200"
        
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
    Id = "Registry-108"
    Task = "Ensure 'Allow binary and script behaviors' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2000" `
                | Select-Object -ExpandProperty "2000"
        
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
    Id = "Registry-109"
    Task = "Ensure 'Scripting of Java applets' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1402" `
                | Select-Object -ExpandProperty "1402"
        
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
    Id = "Registry-110"
    Task = "Ensure 'Allow file downloads' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1803" `
                | Select-Object -ExpandProperty "1803"
        
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
    Id = "Registry-111"
    Task = "Ensure 'Allow loading of XAML files' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2402" `
                | Select-Object -ExpandProperty "2402"
        
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
    Id = "Registry-112"
    Task = "Ensure 'Allow active scripting' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1400" `
                | Select-Object -ExpandProperty "1400"
        
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
    Id = "Registry-113"
    Task = "Ensure 'Logon options' is set to 'Anonymous logon'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1A00" `
                | Select-Object -ExpandProperty "1A00"
        
            if ($regValue -ne 196608) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 196608"
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
    Id = "Registry-114"
    Task = "Ensure 'Run .NET Framework-reliant components signed with Authenticode' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2001" `
                | Select-Object -ExpandProperty "2001"
        
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
    Id = "Registry-115"
    Task = "Ensure 'Turn on Protected Mode' is set to 'Enable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2500" `
                | Select-Object -ExpandProperty "2500"
        
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
    Id = "Registry-116"
    Task = "Ensure 'Turn on Cross-Site Scripting Filter' is set to 'Enable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1409" `
                | Select-Object -ExpandProperty "1409"
        
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
    Id = "Registry-117"
    Task = "Ensure 'Java permissions' is set to 'Disable Java'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1C00" `
                | Select-Object -ExpandProperty "1C00"
        
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
    Id = "Registry-118"
    Task = "Ensure 'Allow scriptlets' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1209" `
                | Select-Object -ExpandProperty "1209"
        
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
    Id = "Registry-119"
    Task = "Ensure 'Don't run antimalware programs against ActiveX controls' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "270C" `
                | Select-Object -ExpandProperty "270C"
        
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
    Id = "Registry-120"
    Task = "Ensure 'Allow scripting of Internet Explorer WebBrowser controls' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1206" `
                | Select-Object -ExpandProperty "1206"
        
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
    Id = "Registry-121"
    Task = "Ensure 'Enable dragging of content from different domains within a window' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2708" `
                | Select-Object -ExpandProperty "2708"
        
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
    Id = "Registry-122"
    Task = "Ensure 'Allow drag and drop or copy and paste files' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1802" `
                | Select-Object -ExpandProperty "1802"
        
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
    Id = "Registry-123"
    Task = "Ensure 'Allow updates to status bar via script' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2103" `
                | Select-Object -ExpandProperty "2103"
        
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
    Id = "Registry-124"
    Task = "Ensure 'Enable dragging of content from different domains across windows' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2709" `
                | Select-Object -ExpandProperty "2709"
        
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
    Id = "Registry-125"
    Task = "Ensure 'Script ActiveX controls marked safe for scripting' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1405" `
                | Select-Object -ExpandProperty "1405"
        
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
    Id = "Registry-126"
    Task = "Ensure 'Web sites in less privileged Web content zones can navigate into this zone' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2101" `
                | Select-Object -ExpandProperty "2101"
        
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
    Id = "Registry-127"
    Task = "Ensure 'Turn on SmartScreen Filter scan' is set to 'Enable'. [Zones\4]"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2301" `
                | Select-Object -ExpandProperty "2301"
        
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
    Id = "Registry-128"
    Task = "Ensure 'Run ActiveX controls and plugins' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1200" `
                | Select-Object -ExpandProperty "1200"
        
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
    Id = "Registry-129"
    Task = "Ensure 'Launching applications and files in an IFRAME' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1804" `
                | Select-Object -ExpandProperty "1804"
        
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
    Id = "Registry-130"
    Task = "Ensure 'Show security warning for potentially unsafe files' is set to 'Disable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1806" `
                | Select-Object -ExpandProperty "1806"
        
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
    Id = "Registry-131"
    Task = "Ensure 'Allow only approved domains to use the TDC ActiveX control' is set to 'Enable'. (Zones/4)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "120c" `
                | Select-Object -ExpandProperty "120c"
        
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
    Id = "Registry-132"
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
    Id = "Registry-133"
    Task = "Set registry value 'PUAProtection' to 1."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" `
                -Name "PUAProtection" `
                | Select-Object -ExpandProperty "PUAProtection"
        
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
    Id = "Registry-134"
    Task = "Ensure 'Turn on behavior monitoring' is set to 'Enabled'."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                -Name "DisableBehaviorMonitoring" `
                | Select-Object -ExpandProperty "DisableBehaviorMonitoring"
        
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
    Id = "Registry-135"
    Task = "Ensure 'Scan removable drives' is set to 'Enabled'."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan" `
                -Name "DisableRemovableDriveScanning" `
                | Select-Object -ExpandProperty "DisableRemovableDriveScanning"
        
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
    Id = "Registry-136"
    Task = "Ensure 'Turn on e-mail scanning' is set to 'Enabled'."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan" `
                -Name "DisableEmailScanning" `
                | Select-Object -ExpandProperty "DisableEmailScanning"
        
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
    Id = "Registry-137"
    Task = "Ensure 'Send file samples when further analysis is required' is set to 'Send safe samples'."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "SubmitSamplesConsent" `
                | Select-Object -ExpandProperty "SubmitSamplesConsent"
        
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
    Id = "Registry-138"
    Task = "Ensure 'Join Microsoft MAPS' is set to 'Advanced MAPS'."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "SpynetReporting" `
                | Select-Object -ExpandProperty "SpynetReporting"
        
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
    Id = "Registry-139"
    Task = "Set registry value 'ExploitGuard_ASR_Rules' to 1."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = 0;
            $regValueTwo = 0;
            $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
            $Value = "ExploitGuard_ASR_Rules"

            $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
            if($asrTest1){
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path $Path `
                    -Name $Value `
                    | Select-Object -ExpandProperty $Value
            }

            $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
            $Value2 = "ExploitGuard_ASR_Rules"

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
    Id = "Registry-140"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Office applications from injecting code into other processes)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-141"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Office applications from creating executable content)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-142"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Office applications from creating child processes)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-143"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Win32 API calls from Office macro)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-144"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block execution of potentially obfuscated scripts)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-145"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block JavaScript or VBScript from launching downloaded executable content)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-146"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block executable content from email client and webmail)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-147"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block credential stealing from the Windows local security authority subsystem (lsass.exe))"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-148"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block untrusted and unsigned processes that run from USB)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-149"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Office communication application from creating child processes)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-150"
    Task = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Block Adobe Reader from creating child processes)"
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
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
    Id = "Registry-151"
    Task = "Set registry value 'EnableNetworkProtection' to 1."
    Test = {
        try {
            if ((-not $windefrunning)) {
                return @{
                    Message = "This rule requires Windows Defender Antivirus to be enabled."
                    Status = "None"
                }
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
                -Name "EnableNetworkProtection" `
                | Select-Object -ExpandProperty "EnableNetworkProtection"
        
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
    Id = "Registry-161"
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
    Id = "Registry-162"
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
                    Status = "True"
                }
            }

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
    Id = "Registry-163"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled with UEFI lock'. (HypervisorEnforcedCodeIntegrity)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "HypervisorEnforcedCodeIntegrity" `
                | Select-Object -ExpandProperty "HypervisorEnforcedCodeIntegrity"
        
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
    Id = "Registry-164"
    Task = "Set registry value 'HVCIMATRequired' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "HVCIMATRequired" `
                | Select-Object -ExpandProperty "HVCIMATRequired"
        
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
    Id = "Registry-165"
    Task = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled with UEFI lock'. (LsaCfgFlags)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "LsaCfgFlags" `
                | Select-Object -ExpandProperty "LsaCfgFlags"
        
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
    Id = "Registry-166"
    Task = "Set registry value 'ConfigureSystemGuardLaunch' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
                -Name "ConfigureSystemGuardLaunch" `
                | Select-Object -ExpandProperty "ConfigureSystemGuardLaunch"
        
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
    Id = "Registry-167"
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
    Id = "Registry-168"
    Task = "Ensure 'Set the default behavior for AutoRun' is set to 'Do not execute any autorun commands'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
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
    Id = "Registry-169"
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
    Id = "Registry-170"
    Task = "Set registry value 'LocalAccountTokenFilterPolicy' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-171"
    Task = "Set registry value 'AllowEncryptionOracle' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" `
                -Name "AllowEncryptionOracle" `
                | Select-Object -ExpandProperty "AllowEncryptionOracle"
        
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
    Id = "Registry-172"
    Task = "Set registry value 'EnhancedAntiSpoofing' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics\FacialFeatures" `
                -Name "EnhancedAntiSpoofing" `
                | Select-Object -ExpandProperty "EnhancedAntiSpoofing"
        
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
    Id = "Registry-173"
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
    Id = "Registry-174"
    Task = "Set registry value 'AllowProtectedCreds' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation" `
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
    Id = "Registry-175"
    Task = "Ensure 'Specify the maximum log file size (KB)' is set to '32768'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application" `
                -Name "MaxSize" `
                | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 32768) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 32768"
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
    Id = "Registry-176"
    Task = "Ensure 'Specify the maximum log file size (KB)' is set to '196608'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security" `
                -Name "MaxSize" `
                | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 196608) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 196608"
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
    Id = "Registry-177"
    Task = "Ensure 'Specify the maximum log file size (KB)' is set to '32768'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System" `
                -Name "MaxSize" `
                | Select-Object -ExpandProperty "MaxSize"
        
            if ($regValue -ne 32768) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 32768"
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
    Id = "Registry-178"
    Task = "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" `
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
    Id = "Registry-179"
    Task = "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" `
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
    Id = "Registry-180"
    Task = "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" `
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
    Id = "Registry-181"
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
    Id = "Registry-182"
    Task = "Ensure 'Configure registry policy processing' is set to '0'. (NoGPOListChanges)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" `
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
    Id = "Registry-183"
    Task = "Set registry value 'AlwaysInstallElevated' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" `
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
    Id = "Registry-184"
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
    Id = "Registry-185"
    Task = "Set registry value 'DeviceEnumerationPolicy' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection" `
                -Name "DeviceEnumerationPolicy" `
                | Select-Object -ExpandProperty "DeviceEnumerationPolicy"
        
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
    Id = "Registry-186"
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
    Id = "Registry-187"
    Task = "Set registry value '\\*\SYSVOL' to RequireMutualAuthentication=1, RequireIntegrity=1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
                -Name "\\*\SYSVOL" `
                | Select-Object -ExpandProperty "\\*\SYSVOL"
        
            if($regValue -eq $null){
                return @{
                    Message = "Registry key not found."
                    Status = "False"
                }
            }
            $array = $regValue.Split(',') | ForEach-Object{ $_.Trim() }

            $missingElements = @()
            $elementsToCheck = @("RequireMutualAuthentication=1", "RequireIntegrity=1")
            foreach ($element in $elementsToCheck) {
                if ($array -notcontains $element) {
                    $missingElements += $element
                }
            }

            if ($missingElements.Length -gt 0) {
                return @{
                    Message = ($missingElements -join " and ") + " not configured correctly."
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
    Id = "Registry-188"
    Task = "Set registry value '\\*\NETLOGON' to RequireMutualAuthentication=1, RequireIntegrity=1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
                -Name "\\*\NETLOGON" `
                | Select-Object -ExpandProperty "\\*\NETLOGON"
        
            if($regValue -eq $null){
                return @{
                    Message = "Registry key not found."
                    Status = "False"
                }
            }
            $array = $regValue.Split(',') | ForEach-Object{ $_.Trim() }

            $missingElements = @()
            $elementsToCheck = @("RequireMutualAuthentication=1", "RequireIntegrity=1")
            foreach ($element in $elementsToCheck) {
                if ($array -notcontains $element) {
                    $missingElements += $element
                }
            }

            if ($missingElements.Length -gt 0) {
                return @{
                    Message = ($missingElements -join " and ") + " not configured correctly."
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
    Id = "Registry-189"
    Task = "Set registry value 'NoLockScreenCamera' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" `
                -Name "NoLockScreenCamera" `
                | Select-Object -ExpandProperty "NoLockScreenCamera"
        
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
    Id = "Registry-190"
    Task = "Set registry value 'NoLockScreenSlideshow' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" `
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
    Id = "Registry-191"
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
    Id = "Registry-192"
    Task = "Ensure 'Turn on PowerShell Script Block Logging' is set to 'disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                -Name "EnableScriptBlockInvocationLogging" `
                | Select-Object -ExpandProperty "EnableScriptBlockInvocationLogging"
        
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
    Id = "Registry-193"
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
    Id = "Registry-194"
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
    Id = "Registry-195"
    Task = "Set registry value 'ShellSmartScreenLevel' to Block."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" `
                -Name "ShellSmartScreenLevel" `
                | Select-Object -ExpandProperty "ShellSmartScreenLevel"
        
            if ($regValue -ne "Block") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: Block"
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
    Id = "Registry-196"
    Task = "Set registry value 'AllowIndexingEncryptedStoresOrItems' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" `
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
    Id = "Registry-197"
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
    Id = "Registry-198"
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
    Id = "Registry-199"
    Task = "Ensure 'Disallow Digest authentication' is set to 'Enabled'. (Client)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" `
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
    Id = "Registry-200"
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
    Id = "Registry-201"
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
    Id = "Registry-202"
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
    Id = "Registry-203"
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
    Id = "Registry-204"
    Task = "Set registry value 'DisablePasswordSaving' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
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
    Id = "Registry-205"
    Task = "Set registry value 'fDisableCdm' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
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
    Id = "Registry-206"
    Task = "Set registry value 'fPromptForPassword' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
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
    Id = "Registry-207"
    Task = "Set registry value 'fEncryptRPCTraffic' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
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
    Id = "Registry-208"
    Task = "Set registry value 'MinEncryptionLevel' to 3."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" `
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
    Id = "Registry-210"
    Task = "Set registry value 'DefaultOutboundAction' to 0. (DomainProfile)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Workstation"}
    )
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"       
        $key = "DefaultOutboundAction"
        $expectedValue = 0;
        $profileType = "Domain"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-211"
    Task = "Set registry value 'DefaultInboundAction' to 1. (DomainProfile)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Workstation"}
    )
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"       
        $key = "DefaultInboundAction"
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
    Id = "Registry-212"
    Task = "Set registry value 'EnableFirewall' to 1. (DomainProfile)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Workstation"}
    )
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile";
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
        $key = "EnableFirewall";
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
    Id = "Registry-213"
    Task = "Set registry value 'EnableFirewall' to 1. (PrivateProfile)"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"       
        $key = "EnableFirewall"
        $expectedValue = 1;
        $profileType = "Private"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-214"
    Task = "Set registry value 'DefaultInboundAction' to 1. (PrivateProfile)"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"       
        $key = "DefaultInboundAction"
        $expectedValue = 1;
        $profileType = "Private"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-215"
    Task = "Set registry value 'DefaultOutboundAction' to 0. (PrivateProfile)"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"       
        $key = "DefaultOutboundAction"
        $expectedValue = 0;
        $profileType = "Private"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-216"
    Task = "Set registry value 'EnableFirewall' to 1. (PublicProfile)"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"       
        $key = "EnableFirewall"
        $expectedValue = 1;
        $profileType = "Public"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-217"
    Task = "Set registry value 'DefaultOutboundAction' to 0. (PublicProfile)"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"       
        $key = "DefaultOutboundAction"
        $expectedValue = 0;
        $profileType = "Public"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-218"
    Task = "Set registry value 'DefaultInboundAction' to 1. (PublicProfile)"
    Test = {
        $path1 = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
        $path2 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"       
        $key = "DefaultInboundAction"
        $expectedValue = 1;
        $profileType = "Public"
        $result = $path1, $path2 | Test-FirewallPaths -Key $key -ExpectedValue $expectedValue -ProfileType $profileType
        return @{
            Message = $($result.Message)
            Status = $($result.Status)
        }
    }
}
[AuditTest] @{
    Id = "Registry-219"
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
    Id = "Registry-220"
    Task = "Set registry value 'AdmPwdEnabled' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" `
                -Name "AdmPwdEnabled" `
                | Select-Object -ExpandProperty "AdmPwdEnabled"
        
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
    Id = "Registry-221"
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
    Id = "Registry-222"
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
    Id = "Registry-223"
    Task = "Set registry value 'DriverLoadPolicy' to 3."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
                -Name "DriverLoadPolicy" `
                | Select-Object -ExpandProperty "DriverLoadPolicy"
        
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
    Id = "Registry-224"
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
    Id = "Registry-225"
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
    Id = "Registry-226"
    Task = "Set registry value 'NoNameReleaseOnDemand' to 1."
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
    Id = "Registry-227"
    Task = "Set registry value 'EnableICMPRedirect' to 0."
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
    Id = "Registry-228"
    Task = "Set registry value 'DisableIPSourceRouting' to 2. (Tcpip)"
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
    Id = "Registry-229"
    Task = "Set registry value 'DisableIPSourceRouting' to 2. (Tcpip6)"
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
    Id = "Registry-230"
    Task = "Set registry value 'allownullsessionfallback' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
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
    Id = "Registry-231"
    Task = "Set registry value 'InactivityTimeoutSecs' to 900."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "InactivityTimeoutSecs" `
                | Select-Object -ExpandProperty "InactivityTimeoutSecs"
        
            if ($regValue -ne 900) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 900"
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
    Id = "Registry-232"
    Task = "Set registry value 'ScRemoveOption' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                -Name "ScRemoveOption" `
                | Select-Object -ExpandProperty "ScRemoveOption"
        
            if ($regValue -ne "1") {
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
    Id = "Registry-233"
    Task = "Set registry value 'SCENoApplyLegacyAuditPolicy' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
    Id = "Registry-234"
    Task = "Set registry value 'EnableVirtualization' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-235"
    Task = "Set registry value 'FilterAdministratorToken' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-236"
    Task = "Set registry value 'EnableLUA' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-237"
    Task = "Set registry value 'EnableInstallerDetection' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-238"
    Task = "Set registry value 'ConsentPromptBehaviorAdmin' to 2."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorAdmin" `
                | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin"
        
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
    Id = "Registry-239"
    Task = "Set registry value 'ConsentPromptBehaviorUser' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-240"
    Task = "Set registry value 'EnableSecureUIAPaths' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
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
    Id = "Registry-241"
    Task = "Set registry value 'LDAPClientIntegrity' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" `
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
    Id = "Registry-242"
    Task = "Set registry value 'LmCompatibilityLevel' to 5."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
    Id = "Registry-243"
    Task = "Set registry value 'NTLMMinClientSec' to 537395200."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
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
    Id = "Registry-244"
    Task = "Set registry value 'sealsecurechannel' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "sealsecurechannel" `
                | Select-Object -ExpandProperty "sealsecurechannel"
        
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
    Id = "Registry-245"
    Task = "Set registry value 'NTLMMinServerSec' to 537395200."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" `
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
    Id = "Registry-246"
    Task = "Set registry value 'requiresignorseal' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "requiresignorseal" `
                | Select-Object -ExpandProperty "requiresignorseal"
        
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
    Id = "Registry-247"
    Task = "Set registry value 'signsecurechannel' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "signsecurechannel" `
                | Select-Object -ExpandProperty "signsecurechannel"
        
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
    Id = "Registry-248"
    Task = "Set registry value 'RequireSecuritySignature' to 1."
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
    Id = "Registry-249"
    Task = "Set registry value 'requiresecuritysignature' to 1."
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
    Id = "Registry-250"
    Task = "Set registry value 'requirestrongkey' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "requirestrongkey" `
                | Select-Object -ExpandProperty "requirestrongkey"
        
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
    Id = "Registry-251"
    Task = "Set registry value 'RestrictAnonymousSAM' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
    Id = "Registry-252"
    Task = "Set registry value 'RestrictNullSessAccess' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" `
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
    Id = "Registry-253"
    Task = "Set registry value 'RestrictAnonymous' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
    Id = "Registry-254"
    Task = "Set registry value 'ProtectionMode' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" `
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
    Id = "Registry-255"
    Task = "Set registry value 'LimitBlankPasswordUse' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
    Id = "Registry-256"
    Task = "Set registry value 'maximumpasswordage' to 30."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "maximumpasswordage" `
                | Select-Object -ExpandProperty "maximumpasswordage"
        
            if ($regValue -ne 30) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 30"
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
    Id = "Registry-257"
    Task = "Set registry value 'disablepasswordchange' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" `
                -Name "disablepasswordchange" `
                | Select-Object -ExpandProperty "disablepasswordchange"
        
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
    Id = "Registry-258"
    Task = "Set registry value 'NoLMHash' to 1."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
    Id = "Registry-259"
    Task = "Set registry value 'EnablePlainTextPassword' to 0."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
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
    Id = "Registry-260"
    Task = "Set registry value 'RestrictRemoteSAM' to O:BAG:BAD:(A;;RC;;;BA)."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" `
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
