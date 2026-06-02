# Common
$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$avstatus = CheckForActiveAV
$windefrunning = CheckWindefRunning
. "$RootPath\Helpers\Firewall.ps1"

# Tests
[AuditTest] @{
    Id   = "2.0"
    Task = "Ensure 'Enable DCOM Hardening' is set to 'Enabled'"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" `
                        -Name "RequireIntegrityActivationAuthenticationLevel" `
                        | Select-Object -ExpandProperty "RequireIntegrityActivationAuthenticationLevel"
        
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
    Id   = "2.1"
    Task = "Ensure 'Raise Authentication Level' is set to 'Raise the authentication level for all non-anonymous activation requests from Windows-based DCOM clients'"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" `
                        -Name "RaiseActivationAuthenticationLevel" `
                        | Select-Object -ExpandProperty "RaiseActivationAuthenticationLevel"
        
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
    Id   = "3.0"
    Task = "IPv6 Configuration Policy: Prefer IPv4 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0x20 (32)')"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" `
                        -Name "DisabledComponents" `
                        | Select-Object -ExpandProperty "DisabledComponents"
        
                    if ($regValue -ne 32) {
                        return @{
                            Message = "Registry value is '$regValue'. Compliant value: 32"
                            Status  = "False"
                        }
                    }
                }
                catch [System.Management.Automation.PSArgumentException] {
                    return @{
                        Message = "Registry value not found."
                        Status  = "False"
                    }
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    return @{
                        Message = "Registry key not found."
                        Status  = "False"
                    }
                }
        
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
    }
}
[AuditTest] @{
    Id   = "4.0"
    Task = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Prompt for credentials on the secure desktop'"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                        -Name "ConsentPromptBehaviorUser" `
                        | Select-Object -ExpandProperty "ConsentPromptBehaviorUser"
        
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
    Id   = "5.0"
    Task = "Mitigation for speculative execution side-channel vulnerabilities: FeatureSettingsOverride"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                        -Name "FeatureSettingsOverride" `
                        | Select-Object -ExpandProperty "FeatureSettingsOverride"
        
                    if ($regValue -ne 72) {
                        return @{
                            Message = "Registry value is '$regValue'. Compliant value: 72"
                            Status  = "False"
                        }
                    }
                }
                catch [System.Management.Automation.PSArgumentException] {
                    return @{
                        Message = "Registry value not found."
                        Status  = "False"
                    }
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    return @{
                        Message = "Registry key not found."
                        Status  = "False"
                    }
                }
        
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
    }
}
[AuditTest] @{
    Id   = "5.1"
    Task = "Mitigation for speculative execution side-channel vulnerabilities: FeatureSettingOverrideMask"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                        -Name "FeatureSettingsOverrideMask" `
                        | Select-Object -ExpandProperty "FeatureSettingsOverrideMask"
        
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
    Id   = "5.2"
    Task = "Mitigation for WinVerifyTrust Signature Validation Vulnerability (for 32 and 64 bit systems)"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" `
                        -Name "EnableCertPaddingCheck" `
                        | Select-Object -ExpandProperty "EnableCertPaddingCheck"
        
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
    Id   = "5.3"
    Task = "Mitigation for WinVerifyTrust Signature Validation Vulnerability (for 64 bit systems)"
    Test = {
        try {
                    $regValue = Get-ItemProperty -ErrorAction Stop `
                        -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" `
                        -Name "EnableCertPaddingCheck" `
                        | Select-Object -ExpandProperty "EnableCertPaddingCheck"
        
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
