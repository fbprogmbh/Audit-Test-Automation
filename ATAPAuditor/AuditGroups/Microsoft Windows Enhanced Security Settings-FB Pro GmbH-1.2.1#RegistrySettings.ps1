[AuditTest] @{
    Id = "2.0"
    Task = "Ensure 'Enable DCOM Hardening' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" `
                -Name "RequireIntegrityActivationAuthenticationLevel" `
                | Select-Object -ExpandProperty "RequireIntegrityActivationAuthenticationLevel"
        
            if (($regValue -ne 1)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
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
    Task = "Ensure 'Raise Authentication Level' is set to 'Raise the authentication level for all non-anonymous activation requests from Windows-based DCOM clients'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" `
                -Name "RaiseActivationAuthenticationLevel" `
                | Select-Object -ExpandProperty "RaiseActivationAuthenticationLevel"
        
            if (($regValue -ne 2)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 2"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "3.0"
    Task = "IPv6 Configuration Policy: Prefer IPv4 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0x20 (32)')"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" `
                -Name "DisabledComponents" `
                | Select-Object -ExpandProperty "DisabledComponents"
        
            if (($regValue -ne 32)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 32"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "4.0"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Prompt for credentials on the secure desktop'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "ConsentPromptBehaviorUser" `
                | Select-Object -ExpandProperty "ConsentPromptBehaviorUser"
        
            if (($regValue -ne 1)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 1"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
