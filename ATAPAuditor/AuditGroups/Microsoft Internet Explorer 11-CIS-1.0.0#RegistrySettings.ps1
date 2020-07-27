[AuditTest] @{
    Id = "1.1"
    Task = "Set 'Turn on Enhanced Protected Mode' to 'Enabled'"
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
    Id = "1.2"
    Task = "Set 'Allow software to run or install even if the signature is invalid' to 'Disabled'"
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
    Id = "1.3"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.4"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "2.1"
    Task = "Set 'Prevent per-user installation of ActiveX controls' to 'Enabled'"
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
    Id = "2.2"
    Task = "Set 'Specify use of ActiveX Installer Service for installation of ActiveX controls' to 'Enabled'"
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
    Id = "2.3"
    Task = "Set 'Turn on ActiveX Filtering' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Safety\ActiveXFiltering" `
                -Name "IsEnabled" `
                | Select-Object -ExpandProperty "IsEnabled"
        
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
    Id = "2.4"
    Task = "Set 'Turn off ActiveX opt-in prompt' to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" `
                -Name "NoFirsttimeprompt" `
                | Select-Object -ExpandProperty "NoFirsttimeprompt"
        
            return @{
                Message = "Registry value found."
                Status = "False"
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
    Id = "2.5"
    Task = "Set 'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' to 'Enabled'"
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
    Id = "3.4"
    Task = "Set 'Days to keep pages in History' to '40'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" `
                -Name "DaysToKeep" `
                | Select-Object -ExpandProperty "DaysToKeep"
        
            if (($regValue -lt 40)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x >= 40"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "3.7"
    Task = "Set 'Prevent access to Delete Browsing History' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "DisableDeleteBrowsingHistory" `
                | Select-Object -ExpandProperty "DisableDeleteBrowsingHistory"
        
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
    Id = "4.2"
    Task = "Set 'Update check interval (in days):' to 'Enabled:30'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "Update_Check_Interval" `
                | Select-Object -ExpandProperty "Update_Check_Interval"
        
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
    Id = "5.1"
    Task = "Set 'Turn off Encryption Support' to 'Use TLS 1.1 and TLS 1.2'"
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
    Id = "5.2"
    Task = "Set 'Check for server certificate revocation' to 'Enabled'"
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
    Id = "5.3"
    Task = "Set 'Check for signatures on downloaded programs' to 'Enabled'"
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
    Id = "5.4"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "5.5"
    Task = "Set 'Prevent ignoring certificate errors' to 'Enabled'"
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
    Id = "5.6"
    Task = "Set 'Disable changing certificate settings' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "Certificates" `
                | Select-Object -ExpandProperty "Certificates"
        
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
    Id = "6.1"
    Task = "Set 'Turn off browser geolocation' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Geolocation" `
                -Name "PolicyDisableGeolocation" `
                | Select-Object -ExpandProperty "PolicyDisableGeolocation"
        
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
    Id = "8.1.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.1.2"
    Task = "Set 'Allow paste operations via script' to 'Enabled:Disable'"
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
    Id = "8.1.3"
    Task = "Set 'Protected Mode' to 'Enabled:Enable'"
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
    Id = "8.1.4"
    Task = "Set 'Turn on Cross-Site Scripting (XSS) Filter' to 'Enabled:Enable'"
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
    Id = "8.1.5"
    Task = "Set 'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled:Disable'"
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
    Id = "8.1.6"
    Task = "Set 'Use Pop-up Blocker' to 'Enabled:Enable'"
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
    Id = "8.1.7"
    Task = "Set 'Scriptlets' to 'Enabled:Disable'"
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
    Id = "8.1.8"
    Task = "Set 'Only allow approved domains to use ActiveX controls without prompt' to 'Enabled:Enable'"
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
    Id = "8.1.9"
    Task = "Set 'Allow drag and drop or copy and paste files' to 'Enabled:Disable'"
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
    Id = "8.1.10"
    Task = "Set 'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled:Disable'"
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
    Id = "8.1.11"
    Task = "Set 'Internet Explorer web browser control' to 'Enabled:Disable'"
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
    Id = "8.1.12"
    Task = "Set 'Download unsigned ActiveX controls' to 'Enabled:Disable'"
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
    Id = "8.1.13"
    Task = "Set 'Download signed ActiveX controls' to 'Enabled:Disable'"
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
    Id = "8.1.14"
    Task = "Set 'Allow font downloads' to 'Enabled:Disable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1604" `
                | Select-Object -ExpandProperty "1604"
        
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
    Id = "8.1.15"
    Task = "Set 'Launching programs and unsafe files' to 'Enabled:Disable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
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
    Id = "8.1.16"
    Task = "Set 'Automatic prompting for file downloads' to 'Enabled:Disable'"
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
    Id = "8.1.17"
    Task = "Set 'Allow installation of desktop items' to 'Enabled:Disable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1800" `
                | Select-Object -ExpandProperty "1800"
        
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
    Id = "8.1.18"
    Task = "Set 'XAML Files' to 'Enabled:Disable'"
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
    Id = "8.1.19"
    Task = "Set 'Initialize and script ActiveX controls not marked as safe' to 'Enabled:Disable'"
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
    Id = "8.1.20"
    Task = "Set 'Enable MIME Sniffing' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2100" `
                | Select-Object -ExpandProperty "2100"
        
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
    Id = "8.1.21"
    Task = "Set 'Logon options' to 'Enabled:Prompt for user name and password'"
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
    Id = "8.1.22"
    Task = "Set 'Access data sources across domains' to 'Enabled:Disable'"
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
    Id = "8.1.23"
    Task = "Set 'Status bar updates via script' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "2103" `
                | Select-Object -ExpandProperty "2103"
        
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
    Id = "8.1.24"
    Task = "Set 'Include local directory path when uploading files to a server' to 'Enabled:Disable'"
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
    Id = "8.1.25"
    Task = "Set 'Userdata persistence' to 'Enabled:Disable'"
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
    Id = "8.1.26"
    Task = "Set 'Enable dragging of content from different domains within a window' to 'Enabled:Disable'"
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
    Id = "8.1.27"
    Task = "Set 'Navigate windows and frames across different domains' to 'Enabled:Disable'"
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
    Id = "8.1.28"
    Task = "Set 'Enable dragging of content from different domains across windows' to 'Enabled:Disable'"
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
    Id = "8.1.29"
    Task = "Set 'Allow script-initiated windows without size or position constraints' to 'Enabled:Disable'"
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
    Id = "8.1.30"
    Task = "Set 'Launching applications and files in an IFRAME' to 'Enabled:Disable'"
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
    Id = "8.1.31"
    Task = "Set 'Software channel permissions' to 'Enabled:High safety'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
                -Name "1E05" `
                | Select-Object -ExpandProperty "1E05"
        
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
    Id = "8.1.33"
    Task = "Set 'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled:Disable'"
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
    Id = "8.1.34"
    Task = "Set 'Don't run antimalware programs against ActiveX controls' to 'Enabled:Disabled'"
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
    Id = "8.2.1"
    Task = "Set 'Java permissions' to 'Enabled:High safety'"
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
    Id = "8.2.2"
    Task = "Set 'Initialize and script ActiveX controls not marked as safe' to 'Enabled:Disable'"
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
    Id = "8.2.3"
    Task = "Set 'Intranet Sites: Include all network paths (UNCs)' to 'Disabled'"
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
    Id = "8.2.4"
    Task = "Set 'Don't run antimalware programs against ActiveX controls' to 'Enabled:Disabled'"
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
    Id = "8.3.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.3.2"
    Task = "Set 'Allow drag and drop or copy and paste files' to 'Enabled:Disable'"
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
    Id = "8.3.3"
    Task = "Set 'Download signed ActiveX controls' to 'Enabled:Disable'"
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
    Id = "8.3.4"
    Task = "Set 'Script ActiveX controls marked safe for scripting' to 'Enabled:Disable'"
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
    Id = "8.3.5"
    Task = "Set 'Allow active scripting' to 'Enabled:Disable'"
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
    Id = "8.3.6"
    Task = "Set 'Turn on Cross-Site Scripting (XSS) Filter' to 'Enabled:Enable'"
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
    Id = "8.3.7"
    Task = "Set 'Initialize and script ActiveX controls not marked as safe' to 'Enabled:Disable'"
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
    Id = "8.3.8"
    Task = "Set 'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled:Disable'"
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
    Id = "8.3.9"
    Task = "Set 'Allow paste operations via script' to 'Enabled:Disable'"
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
    Id = "8.3.10"
    Task = "Set 'Protected Mode' to 'Enabled:Enable'"
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
    Id = "8.3.11"
    Task = "Set 'Allow installation of desktop items' to 'Enabled:Disable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1800" `
                | Select-Object -ExpandProperty "1800"
        
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
    Id = "8.3.12"
    Task = "Set 'Launching programs and unsafe files' to 'Enabled:Prompt'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
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
    Id = "8.3.13"
    Task = "Set 'Automatic prompting for file downloads' to 'Enabled:Disable'"
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
    Id = "8.3.14"
    Task = "Set 'XAML Files' to 'Enabled:Disable'"
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
    Id = "8.3.15"
    Task = "Set 'Allow font downloads' to 'Enabled:Disable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1604" `
                | Select-Object -ExpandProperty "1604"
        
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
    Id = "8.3.16"
    Task = "Set 'Enable MIME Sniffing' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2100" `
                | Select-Object -ExpandProperty "2100"
        
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
    Id = "8.3.17"
    Task = "Set 'Internet Explorer web browser control' to 'Enabled:Disable'"
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
    Id = "8.3.18"
    Task = "Set 'Allow Binary and Script Behaviors' to 'Enabled:Disable'"
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
    Id = "8.3.19"
    Task = "Set 'Scripting of Java applets' to 'Enabled:Disable'"
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
    Id = "8.3.20"
    Task = "Set 'Use Pop-up Blocker' to 'Enabled:Enable'"
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
    Id = "8.3.21"
    Task = "Set 'Download unsigned ActiveX controls' to 'Enabled:Disable'"
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
    Id = "8.3.22"
    Task = "Set 'Scriptlets' to 'Enabled:Disable'"
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
    Id = "8.3.23"
    Task = "Set 'Allow file downloads' to 'Enabled:Disable'"
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
    Id = "8.3.24"
    Task = "Set 'Only allow approved domains to use ActiveX controls without prompt' to 'Enabled:Enable'"
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
    Id = "8.3.25"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
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
    Id = "8.3.26"
    Task = "Set 'Run ActiveX controls and plugins' to 'Enabled:Disable'"
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
    Id = "8.3.27"
    Task = "Set 'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled:Disable'"
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
    Id = "8.3.28"
    Task = "Set 'Logon options' to 'Enabled:Anonymous logon'"
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
    Id = "8.3.29"
    Task = "Set 'Allow script-initiated windows without size or position constraints' to 'Enabled:Disable'"
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
    Id = "8.3.30"
    Task = "Set 'Allow META REFRESH' to 'Enabled:Disable'"
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
    Id = "8.3.31"
    Task = "Set 'Userdata persistence' to 'Enabled:Disable'"
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
    Id = "8.3.32"
    Task = "Set 'Navigate windows and frames across different domains' to 'Enabled:Disable'"
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
    Id = "8.3.33"
    Task = "Set 'Software channel permissions' to 'Enabled:High safety'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "1E05" `
                | Select-Object -ExpandProperty "1E05"
        
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
    Id = "8.3.34"
    Task = "Set 'Include local directory path when uploading files to a server' to 'Enabled:Disable'"
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
    Id = "8.3.35"
    Task = "Set 'Enable dragging of content from different domains within a window' to 'Enabled:Disable'"
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
    Id = "8.3.36"
    Task = "Set 'Status bar updates via script' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" `
                -Name "2103" `
                | Select-Object -ExpandProperty "2103"
        
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
    Id = "8.3.37"
    Task = "Set 'Access data sources across domains' to 'Enabled:Disable'"
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
    Id = "8.3.38"
    Task = "Set 'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled:Disable'"
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
    Id = "8.3.40"
    Task = "Set 'Enable dragging of content from different domains across windows' to 'Enabled:Disable'"
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
    Id = "8.3.41"
    Task = "Set 'Launching applications and files in an IFRAME' to 'Enabled:Disable'"
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
    Id = "8.3.42"
    Task = "Set 'Don't run antimalware programs against ActiveX controls' to 'Enabled:Disabled'"
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
    Id = "8.4.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.4.2"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" `
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
    Id = "8.4.3"
    Task = "Set 'Don't run antimalware programs against ActiveX controls' to 'Enabled:Disabled'"
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
    Id = "8.5.1"
    Task = "Set 'Java permissions' to 'Enabled:High safety'"
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
    Id = "8.5.2"
    Task = "Set 'Initialize and script ActiveX controls not marked as safe' to 'Enabled:Disable'"
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
    Id = "8.5.3"
    Task = "Set 'Don't run antimalware programs against ActiveX controls' to 'Enabled:Disabled'"
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
    Id = "8.6.1"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
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
    Id = "8.6.2"
    Task = "Set 'Only allow approved domains to use ActiveX controls without prompt' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" `
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
    Id = "8.7.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.7.2"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" `
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
    Id = "8.8.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.8.2"
    Task = "Set 'Only allow approved domains to use ActiveX controls without prompt' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" `
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
    Id = "8.8.3"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
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
    Id = "8.9.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.9.2"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" `
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
    Id = "8.10.1"
    Task = "Set 'Java permissions' to 'Enabled:Disable Java'"
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
    Id = "8.10.2"
    Task = "Set 'Use SmartScreen Filter' to 'Enabled:Enable'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" `
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
    Id = "8.11"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "8.12"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "8.13"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "9.1"
    Task = "Set 'Disable the Security page' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "SecurityTab" `
                | Select-Object -ExpandProperty "SecurityTab"
        
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
    Id = "9.2"
    Task = "Set 'Disable the Advanced page' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "AdvancedTab" `
                | Select-Object -ExpandProperty "AdvancedTab"
        
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
    Id = "9.3"
    Task = "Set 'Prevent downloading of enclosures' to 'Enabled'"
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
    Id = "9.7"
    Task = "Set 'Prevent changing proxy settings' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "Proxy" `
                | Select-Object -ExpandProperty "Proxy"
        
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
    Id = "9.9"
    Task = "Set 'Prevent `"Fix settings`" functionality' to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Security" `
                -Name "DisableFixSecuritySettings" `
                | Select-Object -ExpandProperty "DisableFixSecuritySettings"
        
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
    Id = "9.10"
    Task = "Set 'Turn off the Security Settings Check feature' to 'Disabled'"
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
    Id = "9.12"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "9.13"
    Task = "Set 'Disable AutoComplete for forms' to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Control Panel" `
                -Name "FormSuggest" `
                | Select-Object -ExpandProperty "FormSuggest"
        
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
    Id = "9.15"
    Task = "Set 'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' to 'Enabled'"
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
