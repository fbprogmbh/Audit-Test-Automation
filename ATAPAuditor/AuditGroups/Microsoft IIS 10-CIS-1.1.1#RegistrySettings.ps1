$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$listOfWeakCipherSuites = getListOfWeakCipherSuites
$listOfInsecureCipherSuites = getListOfInsecureCipherSuites
[AuditTest] @{
    Id = "7.2_1"
    Task = "(L1) Ensure SSLv2 is Disabled - Set server key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.2_2"
    Task = "(L1) Ensure SSLv2 is Disabled - Set client key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.2_3"
    Task = "(L1) Ensure SSLv2 is Disabled - Set server by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.2_4"
    Task = "(L1) Ensure SSLv2 is Disabled - Set client by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.3_1"
    Task = "(L1) Ensure SSLv3 is Disabled - Set server key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.3_2"
    Task = "(L1) Ensure SSLv3 is Disabled - Set client key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.3_3"
    Task = "(L1) Ensure SSLv3 is Disabled - Set server by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.3_4"
    Task = "(L1) Ensure SSLv3 is Disabled - Set client by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.4_1"
    Task = "(L1) Ensure TLS 1.0 is Disabled - Set server key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.4_2"
    Task = "(L1) Ensure TLS 1.0 is Disabled - Set client key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.4_3"
    Task = "(L1) Ensure TLS 1.0 is Disabled - Set server by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.4_4"
    Task = "(L1) Ensure TLS 1.0 is Disabled - Set client by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.5_1"
    Task = "(L1) Ensure TLS 1.1 is Disabled - Set server key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.5_2"
    Task = "(L1) Ensure TLS 1.1 is Disabled - Set client key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.5_3"
    Task = "(L1) Ensure TLS 1.1 is Disabled - Set server by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.5_4"
    Task = "(L1) Ensure TLS 1.1 is Disabled - Set client by default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.6_1"
    Task = "(L1) Ensure TLS 1.2 is Enabled - Set server key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
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
    Id = "7.6_2"
    Task = "(L1) Ensure TLS 1.2 is Enabled - Set server default key"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
                -Name "DisabledByDefault" `
                | Select-Object -ExpandProperty "DisabledByDefault"
        
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
    Id = "7.7"
    Task = "(L1) Ensure NULL Cipher Suites is Disabled"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.8"
    Task = "(L1) Ensure DES Cipher Suites is Disabled"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.9_1"
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
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "7.9_2"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled RC4 56/128"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.9_3"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled RC4 64/128"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.9_4"
    Task = "(L1) Ensure RC4 Cipher Suites is Disabled RC4 128/128"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.10"
    Task = "(L1) Ensure AES 128/128 Cipher Suite is Disabled"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"
        
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
    Id = "7.11"
    Task = "(L1) Ensure AES 256/256 Cipher Suite is Enabled"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" `
                -Name "Enabled" `
                | Select-Object -ExpandProperty "Enabled"

            if ($regValue -eq 4294967295) {
                return @{
                    Message = "The current registry value is '$regValue', which is no longer supported by Microsoft. For more information, please refer to this link:<br/>"`
                    +'<a href="https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman#tls-dtls-and-ssl-protocol-version-settings">'`
                    +'Learn.microsoft.com - TLS, DTLS, and SSL protocol version settings<a/>'
                    Status = "False"
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
    Id = "7.12"
    Task = "(L2) Ensure TLS Cipher Suite ordering is Configured"
    Test = {
        #check if correct type 
        $typeTable = @{
            "String" = "String Value"
            "Byte" = "Byte Value"
            "Int32" = "DWORD (32-bit) Value"
            "Int64" = "QWORD (64-bit) Value"
            "String[]" = "Multi-String Value"
        }
        #Default status
        $status = "Error"
    
        #Output
        $verbInsecure = "rules have"
        $verbWeak = "rules have"
    
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
            -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
            -Name "Functions"
            $reference = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            $res = $regValue.Functions.GetType().Name
    
    
            $currentType = $typeTable[$res]
            if ($res -ne [String]) {
                return @{  
                    Message = "Wrong Registry type! Registry type is '$currentType'. Expected: 'String Value'"
                    Status = "False"
                }
            }
    
            #check if insecure or weak cipher is inside value
            $regValues = $regValue.Split(',')
            $regValues = $regValues -replace ' ', ''
            $weakRulesFound = @()
            $insecureRulesFound = @()
            foreach($element in $regValues){
                if($listOfWeakCipherSuites.Contains($element)){
                    $weakRulesFound += $element
                }
                if($listOfInsecureCipherSuites.Contains($element)){
                    $insecureRulesFound += $element
                }
            }
            if($insecureRulesFound.Count -eq 1){$verbInsecure = "rule has"}
            if($weakRulesFound.Count -eq 1){$verbWeak = "rule has"}
            $insecureMessage = "$($insecureRulesFound.Count) insecure $($verbInsecure) been found! List of insecure rules: <br/>"
            $weakMessage = "$($weakRulesFound.Count) weak $($verbWeak) been found! List of weak rules: <br/>"
    
            #Preparing message
            foreach($member in $weakRulesFound){
                $status = "Warning"
                $weakMessage += "$($member)<br/>"
            }          
            foreach($member in $insecureRulesFound){
                $status = "False"
                $insecureMessage += "$($member)<br/>"
            }          
            #Combine or shorten message
            if($insecureRulesFound.Count -gt 0 -or $weakRulesFound.Count -gt 0){
                $message = ""
                if($weakRulesFound.Count -eq 0){ $weakMessage = "" }
                if($insecureRulesFound.Count -eq 0){ $insecureMessage = "" }
    
                $message = $insecureMessage + $weakMessage
                return @{
                    Message = $message
                    Status = $status
                }
            }
    
            if ($regValue -ne $reference) {
                return @{                                                                               
                    Message = "Registry value is '$regValue'. To implement CIS recommendation, please consult <a href='https://www.tenable.com/audits/items/CIS_MS_IIS_10_v1.2.0_Level_2.audit:3a283f2bfffa27bf2edee4be256d3e08'>following tenable recommendations</a>"
                    Status = "False"
                }
            }
        }
        catch {
            $regValue = Get-ItemProperty -ErrorAction Stop `
            -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" `
            -Name "Functions"
            $reference = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            $res = $regValue.Functions.GetType().Name
    
            $currentType = $typeTable[$res]
            if ($res -ne [String[]]) {
                return @{  
                    Message = "Wrong Registry type! Registry type is '$currentType'. Expected: 'Multi-String Value'"
                    Status = "False"
                }
            }
    
            #check if insecure or weak cipher is inside value
            $regValues = $regValue -replace ' ', ''
            $weakRulesFound = @()
            $insecureRulesFound = @()
            foreach($element in $regValues){
                if($listOfWeakCipherSuites.Contains($element)){
                    $weakRulesFound += $element
                }
                if($listOfInsecureCipherSuites.Contains($element)){
                    $insecureRulesFound += $element
                }
            }
            if($insecureRulesFound.Count -eq 1){$verbInsecure = "rule has"}
            if($weakRulesFound.Count -eq 1){$verbWeak = "rule has"}
            $insecureMessage = "$($insecureRulesFound.Count) insecure $($verbInsecure) been found! List of insecure rules: <br/>"
            $weakMessage = "$($weakRulesFound.Count) weak $($verbWeak) been found! List of weak rules: <br/>"
    
            #Preparing message
            foreach($member in $weakRulesFound){
                $status = "Warning"
                $weakMessage += "$($member)<br/>"
            }          
            foreach($member in $insecureRulesFound){
                $status = "False"
                $insecureMessage += "$($member)<br/>"
            }          
            #Combine or shorten message
            if($insecureRulesFound.Count -gt 0 -or $weakRulesFound.Count -gt 0){
                $message = ""
                if($weakRulesFound.Count -eq 0){ $weakMessage = "" }
                if($insecureRulesFound.Count -eq 0){ $insecureMessage = "" }
    
                $message = $insecureMessage + $weakMessage
                return @{
                    Message = $message
                    Status = $status
                }
            }
    
            if ($regValue -ne $reference) {
                return @{                                                                               
                    Message = "Registry value is '$regValue'. To implement CIS recommendation, please consult <a href='https://www.tenable.com/audits/items/CIS_MS_IIS_10_v1.2.0_Level_2.audit:3a283f2bfffa27bf2edee4be256d3e08'>following tenable recommendations</a>"
                    Status = "False"
                }
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
