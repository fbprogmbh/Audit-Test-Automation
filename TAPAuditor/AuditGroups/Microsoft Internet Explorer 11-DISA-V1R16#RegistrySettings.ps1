[AuditTest] @{
    Id = "DTBI014-IE11"
    Task = "Turn off Encryption Support must be enabled."
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
    Id = "DTBI015-IE11"
    Task = "The Internet Explorer warning about certificate address mismatch must be enforced."
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
    Id = "DTBI018-IE11"
    Task = "Check for publishers certificate revocation must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" `
                -Name "State" `
                | Select-Object -ExpandProperty "State"
        
            if ($regValue -ne 146432) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 146432"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "DTBI022-IE11"
    Task = "The Download signed ActiveX controls property must be disallowed (Internet zone)."
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
    Id = "DTBI023-IE11"
    Task = "The Download unsigned ActiveX controls property must be disallowed (Internet zone)."
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
    Id = "DTBI024-IE11"
    Task = "The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone)."
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
    Id = "DTBI030-IE11"
    Task = "Font downloads must be disallowed (Internet zone)."
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
    Id = "DTBI031-IE11"
    Task = "The Java permissions must be disallowed (Internet zone)."
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
    Id = "DTBI032-IE11"
    Task = "Accessing data sources across domains must be disallowed (Internet zone)."
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
    Id = "DTBI036-IE11"
    Task = "Functionality to drag and drop or copy and paste files must be disallowed (Internet zone)."
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
    Id = "DTBI038-IE11"
    Task = "Launching programs and files in IFRAME must be disallowed (Internet zone)."
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
    Id = "DTBI039-IE11"
    Task = "Navigating windows and frames across different domains must be disallowed (Internet zone)."
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
    Id = "DTBI042-IE11"
    Task = "Userdata persistence must be disallowed (Internet zone)."
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
    Id = "DTBI044-IE11"
    Task = "Clipboard operations via script must be disallowed (Internet zone)."
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
    Id = "DTBI046-IE11"
    Task = "Logon options must be configured to prompt (Internet zone)."
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
    Id = "DTBI061-IE11"
    Task = "Java permissions must be configured with High Safety (Intranet zone)."
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
    Id = "DTBI091-IE11"
    Task = "Java permissions must be configured with High Safety (Trusted Sites zone)."
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
    Id = "DTBI1000-IE11"
    Task = "Dragging of content from different domains within a window must be disallowed (Internet zone)."
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
    Id = "DTBI1005-IE11"
    Task = "Dragging of content from different domains across windows must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI1010-IE11"
    Task = "Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer)."
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
    Id = "DTBI1020-IE11"
    Task = "Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore)."
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
    Id = "DTBI1025-IE11"
    Task = "Dragging of content from different domains within a window must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI112-IE11"
    Task = "The Download signed ActiveX controls property must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI113-IE11"
    Task = "The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI114-IE11"
    Task = "The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI115-IE11"
    Task = "ActiveX controls and plug-ins must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI116-IE11"
    Task = "ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI119-IE11"
    Task = "File downloads must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI120-IE11"
    Task = "Font downloads must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI121-IE11"
    Task = "Java permissions must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI122-IE11"
    Task = "Accessing data sources across domains must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI123-IE11"
    Task = "The Allow META REFRESH property must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI126-IE11"
    Task = "Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI128-IE11"
    Task = "Launching programs and files in IFRAME must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI129-IE11"
    Task = "Navigating windows and frames across different domains must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI132-IE11"
    Task = "Userdata persistence must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI133-IE11"
    Task = "Active scripting must be disallowed (Restricted Sites Zone)."
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
    Id = "DTBI134-IE11"
    Task = "Clipboard operations via script must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI136-IE11"
    Task = "Logon options must be configured and enforced (Restricted Sites zone)."
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
    Id = "DTBI300-IE11"
    Task = "Configuring History setting must be set to 40 days."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" `
                -Name "DaysToKeep" `
                | Select-Object -ExpandProperty "DaysToKeep"
        
            if ($regValue -ne 40) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 40"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "DTBI318-IE11"
    Task = "Internet Explorer must be set to disallow users to add/delete sites."
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
    Id = "DTBI319-IE11"
    Task = "Internet Explorer must be configured to disallow users to change policies."
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
    Id = "DTBI320-IE11"
    Task = "Internet Explorer must be configured to use machine settings."
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
    Id = "DTBI325-IE11"
    Task = "Security checking features must be enforced."
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
    Id = "DTBI350-IE11"
    Task = "Software must be disallowed to run or install with invalid signatures."
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
    Id = "DTBI365-IE11"
    Task = "Checking for server certificate revocation must be enforced."
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
    Id = "DTBI370-IE11"
    Task = "Checking for signatures on downloaded programs must be enforced."
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
    Id = "DTBI375-IE11"
    Task = "All network paths (UNCs) for Intranet sites must be disallowed."
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
    Id = "DTBI385-IE11"
    Task = "Script-initiated windows without size or position constraints must be disallowed (Internet zone)."
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
    Id = "DTBI390-IE11"
    Task = "Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI395-IE11"
    Task = "Scriptlets must be disallowed (Internet zone)."
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
    Id = "DTBI415-IE11"
    Task = "Automatic prompting for file downloads must be disallowed (Internet zone)."
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
    Id = "DTBI425-IE11"
    Task = "Java permissions must be disallowed (Local Machine zone)."
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
    Id = "DTBI430-IE11"
    Task = "Java permissions must be disallowed (Locked Down Local Machine zone)."
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
    Id = "DTBI435-IE11"
    Task = "Java permissions must be disallowed (Locked Down Intranet zone)."
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
    Id = "DTBI440-IE11"
    Task = "Java permissions must be disallowed (Locked Down Trusted Sites zone)."
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
    Id = "DTBI450-IE11"
    Task = "Java permissions must be disallowed (Locked Down Restricted Sites zone)."
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
    Id = "DTBI455-IE11"
    Task = "XAML files must be disallowed (Internet zone)."
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
    Id = "DTBI460-IE11"
    Task = "XAML files must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI485-IE11"
    Task = "Protected Mode must be enforced (Internet zone)."
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
    Id = "DTBI490-IE11"
    Task = "Protected Mode must be enforced (Restricted Sites zone)."
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
    Id = "DTBI495-IE11"
    Task = "Pop-up Blocker must be enforced (Internet zone)."
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
    Id = "DTBI500-IE11"
    Task = "Pop-up Blocker must be enforced (Restricted Sites zone)."
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
    Id = "DTBI515-IE11"
    Task = "Websites in less privileged web content zones must be prevented from navigating into the Internet zone."
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
    Id = "DTBI520-IE11"
    Task = "Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone."
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
    Id = "DTBI575-IE11"
    Task = "Allow binary and script behaviors must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI580-IE11"
    Task = "Automatic prompting for file downloads must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI590-IE11"
    Task = "Internet Explorer Processes for MIME handling must be enforced. (Reserved)"
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
    Id = "DTBI592-IE11"
    Task = "Internet Explorer Processes for MIME handling must be enforced (Explorer)."
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
    Id = "DTBI594-IE11"
    Task = "Internet Explorer Processes for MIME handling must be enforced (iexplore)."
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
    Id = "DTBI595-IE11"
    Task = "Internet Explorer Processes for MIME sniffing must be enforced (Reserved)."
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
    Id = "DTBI596-IE11"
    Task = "Internet Explorer Processes for MIME sniffing must be enforced (Explorer)."
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
    Id = "DTBI597-IE11"
    Task = "Internet Explorer Processes for MIME sniffing must be enforced (iexplore)."
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
    Id = "DTBI599-IE11"
    Task = "Internet Explorer Processes for MK protocol must be enforced (Reserved)."
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
    Id = "DTBI600-IE11"
    Task = "Internet Explorer Processes for MK protocol must be enforced (Explorer)."
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
    Id = "DTBI605-IE11"
    Task = "Internet Explorer Processes for MK protocol must be enforced (iexplore)."
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
    Id = "DTBI610-IE11"
    Task = "Internet Explorer Processes for Zone Elevation must be enforced (Reserved)."
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
    Id = "DTBI612-IE11"
    Task = "Internet Explorer Processes for Zone Elevation must be enforced (Explorer)."
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
    Id = "DTBI614-IE11"
    Task = "Internet Explorer Processes for Zone Elevation must be enforced (iexplore)."
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
    Id = "DTBI630-IE11"
    Task = "Internet Explorer Processes for Restrict File Download must be enforced (Reserved)."
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
    Id = "DTBI635-IE11"
    Task = "Internet Explorer Processes for Restrict File Download must be enforced (Explorer)."
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
    Id = "DTBI640-IE11"
    Task = "Internet Explorer Processes for Restrict File Download must be enforced (iexplore)."
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
    Id = "DTBI645-IE11"
    Task = "Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved)."
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
    Id = "DTBI647-IE11"
    Task = "Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer)."
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
    Id = "DTBI649-IE11"
    Task = "Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore)."
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
    Id = "DTBI650-IE11"
    Task = ".NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone)."
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
    Id = "DTBI655-IE11"
    Task = ".NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone)."
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
    Id = "DTBI670-IE11"
    Task = "Scripting of Java applets must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI690-IE11"
    Task = "AutoComplete feature for forms must be disallowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "Use FormSuggest" `
                | Select-Object -ExpandProperty "Use FormSuggest"
        
            if ($regValue -ne "no") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: no"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "DTBI715-IE11"
    Task = "Crash Detection management must be enforced."
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
    Id = "DTBI725-IE11"
    Task = "Turn on the auto-complete feature for user names and passwords on forms must be disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Main" `
                -Name "FormSuggest PW Ask" `
                | Select-Object -ExpandProperty "FormSuggest PW Ask"
        
            if ($regValue -ne "no") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: no"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "DTBI740-IE11"
    Task = "Managing SmartScreen Filter use must be enforced."
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
    Id = "DTBI760-IE11"
    Task = "Browser must retain history on exit."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Privacy" `
                -Name "ClearBrowsingHistoryOnExit" `
                | Select-Object -ExpandProperty "ClearBrowsingHistoryOnExit"
        
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
    Id = "DTBI770-IE11"
    Task = "Deleting websites that the user has visited must be disallowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Privacy" `
                -Name "CleanHistory" `
                | Select-Object -ExpandProperty "CleanHistory"
        
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
    Id = "DTBI780-IE11"
    Task = "InPrivate Browsing must be disallowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Privacy" `
                -Name "EnableInPrivateBrowsing" `
                | Select-Object -ExpandProperty "EnableInPrivateBrowsing"
        
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
    Id = "DTBI800-IE11"
    Task = "Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone)."
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
    Id = "DTBI810-IE11"
    Task = "When uploading files to a server, the local directory path must be excluded (Internet zone)."
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
    Id = "DTBI815-IE11"
    Task = "Internet Explorer Processes for Notification Bars must be enforced (Reserved)."
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
    Id = "DTBI820-IE11"
    Task = "Security Warning for unsafe files must be set to prompt (Internet zone)."
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
    Id = "DTBI825-IE11"
    Task = "Internet Explorer Processes for Notification Bars must be enforced (Explorer)."
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
    Id = "DTBI830-IE11"
    Task = "ActiveX controls without prompt property must be used in approved domains only (Internet zone)."
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
    Id = "DTBI835-IE11"
    Task = "Internet Explorer Processes for Notification Bars must be enforced (iexplore)."
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
    Id = "DTBI840-IE11"
    Task = "Cross-Site Scripting Filter must be enforced (Internet zone)."
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
    Id = "DTBI850-IE11"
    Task = "Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI860-IE11"
    Task = "When uploading files to a server, the local directory path must be excluded (Restricted Sites zone)."
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
    Id = "DTBI870-IE11"
    Task = "Security Warning for unsafe files must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI880-IE11"
    Task = "ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone)."
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
    Id = "DTBI890-IE11"
    Task = "Cross-Site Scripting Filter property must be enforced (Restricted Sites zone)."
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
    Id = "DTBI900-IE11"
    Task = "Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved)."
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
    Id = "DTBI910-IE11"
    Task = "Status bar updates via script must be disallowed (Internet zone)."
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
    Id = "DTBI920-IE11"
    Task = ".NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone)."
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
    Id = "DTBI930-IE11"
    Task = ".NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone)."
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
    Id = "DTBI940-IE11"
    Task = "Scriptlets must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI950-IE11"
    Task = "Status bar updates via script must be disallowed (Restricted Sites zone)."
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
    Id = "DTBI985-IE11"
    Task = "When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode."
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
    Id = "DTBI990-IE11"
    Task = "Dragging of content from different domains across windows must be disallowed (Internet zone)."
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
    Id = "DTBI995-IE11"
    Task = "Enhanced Protected Mode functionality must be enforced."
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
    Id = "DTBI356-IE11"
    Task = "The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on."
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
    Id = "DTBI1046-IE11"
    Task = "Anti-Malware programs against ActiveX controls must be run for the Internet zone."
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
    Id = "DTBI062-IE11"
    Task = "Anti-Malware programs against ActiveX controls must be run for the Intranet zone."
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
    Id = "DTBI426-IE11"
    Task = "Anti-Malware programs against ActiveX controls must be run for the Local Machine zone."
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
    Id = "DTBI1051-IE11"
    Task = "Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone."
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
    Id = "DTBI092-IE11"
    Task = "Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone."
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
    Id = "DTBI1060-IE11"
    Task = "Prevent bypassing SmartScreen Filter warnings must be enabled."
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
    Id = "DTBI1065-IE11"
    Task = "Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled."
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
    Id = "DTBI1070-IE11"
    Task = "Prevent per-user installation of ActiveX controls must be enabled."
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
    Id = "DTBI1075-IE11"
    Task = "Prevent ignoring certificate errors option must be enabled."
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
    Id = "DTBI1080-IE11"
    Task = "Turn on SmartScreen Filter scan option for the Internet Zone must be enabled."
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
    Id = "DTBI1085-IE11"
    Task = "Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled."
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
    Id = "DTBI1090-IE11"
    Task = "The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone)."
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
    Id = "DTBI1095-IE11"
    Task = "The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone)."
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
    Id = "DTBI1100-IE11"
    Task = "Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled."
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
    Id = "DTBI1105-IE11"
    Task = "Run once selection for running outdated ActiveX controls must be disabled."
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
    Id = "DTBI1110-IE11"
    Task = "Enabling outdated ActiveX controls for Internet Explorer must be blocked."
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
    Id = "DTBI1115-IE11"
    Task = "Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone."
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
    Id = "DTBI1120-IE11"
    Task = "Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone."
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
    Id = "DTBI1125-IE11"
    Task = "VBScript must not be allowed to run in Internet Explorer (Internet zone).(This policy setting will only exist on Windows 10 Redstone 2 or later)"
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
    Id = "DTBI1130-IE11"
    Task = "VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone).(This policy setting will only exist on Windows 10 Redstone 2 or later)"
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
