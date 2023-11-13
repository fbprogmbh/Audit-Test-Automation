[AuditTest] @{
    Id = "1.2.1"
    Task = "(L1) Ensure 'Enable Google Cast' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "EnableMediaRouter" `
                | Select-Object -ExpandProperty "EnableMediaRouter"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.3.1"
    Task = "(L2) Ensure 'Allow read access via the File System API on these sites' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "FileSystemReadAskForUrls" `
                | Select-Object -ExpandProperty "FileSystemReadAskForUrls"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.3.2"
    Task = "(L1) Ensure 'Choose whether users can receive customized background images and text, suggestions, notifications, and tips for Microsoft services' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SpotlightExperiencesAndRecommendationsEnabled" `
                | Select-Object -ExpandProperty "SpotlightExperiencesAndRecommendationsEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.3.3"
    Task = "(L1) Ensure 'Control use of insecure content exceptions' is set to 'Enabled: Do not allow any site to load mixed content'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultinsecurecontentSetting" `
                | Select-Object -ExpandProperty "DefaultinsecurecontentSetting"
        
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
    Id = "1.3.4"
    Task = "(L2) Ensure 'Control use of JavaScript JIT' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultJavaScriptJitSetting" `
                | Select-Object -ExpandProperty "DefaultJavaScriptJitSetting"
        
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
    Id = "1.3.5"
    Task = "(L2) Ensure 'Control use of the File System API for reading' is set to 'Enabled: Don't allow any site to request read access to files and directories'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultFileSystemReadGuardSetting" `
                | Select-Object -ExpandProperty "DefaultFileSystemReadGuardSetting"
        
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
    Id = "1.3.6"
    Task = "(L1) Ensure 'Control use of the File System API for writing' is set to 'Enabled: Don't allow any site to request write access to files and directories'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultFileSystemWriteGuardSetting" `
                | Select-Object -ExpandProperty "DefaultFileSystemWriteGuardSetting"
        
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
    Id = "1.3.7"
    Task = "(L2) Ensure 'Control use of the Web Bluetooth API' is set to 'Enabled: Do not allow any site to request access to Bluetooth'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultWebBluetoothGuardSetting" `
                | Select-Object -ExpandProperty "DefaultWebBluetoothGuardSetting"
        
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
    Id = "1.3.8"
    Task = "(L2) Ensure 'Control use of the WebHID API' is set to 'Enabled: Do not allow any site to request access to HID devices via the WebHID API'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultWebHidGuardSetting" `
                | Select-Object -ExpandProperty "DefaultWebHidGuardSetting"
        
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
    Id = "1.3.9"
    Task = "(L1) Ensure 'Default geolocation setting' is set to 'Enabled: Don't allow any site to track users physical location'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultGeolocationSetting" `
                | Select-Object -ExpandProperty "DefaultGeolocationSetting"
        
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
    Id = "1.5.1"
    Task = "(L1) Ensure 'Configure users ability to override feature flags' is set to 'Enabled: Prevent users from overriding feature flags'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "FeatureFlagOverridesControl" `
                | Select-Object -ExpandProperty "FeatureFlagOverridesControl"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.6.1"
    Task = "(L2) Ensure 'Configure extension management settings' is set to 'Enabled: *'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ExtensionSettings" `
                | Select-Object -ExpandProperty "ExtensionSettings"
        
            if ($regValue -ne "*") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: *"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.7.1"
    Task = "(L1) Ensure 'Allow Basic authentication for HTTP' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BasicAuthOverHttpEnabled" `
                | Select-Object -ExpandProperty "BasicAuthOverHttpEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.7.2"
    Task = "(L1) Ensure 'Allow cross-origin HTTP Basic Auth prompts' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AllowCrossOriginAuthPrompt" `
                | Select-Object -ExpandProperty "AllowCrossOriginAuthPrompt"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.7.3"
    Task = "(L2) Ensure 'Supported authentication schemes' is set to 'Enabled: ntlm, negotiate'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AuthSchemes" `
                | Select-Object -ExpandProperty "AuthSchemes"
        
            if ($regValue -ne "ntlm, negotiate") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: ntlm, negotiate"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.13.1"
    Task = "(L1) Ensure 'Enable saving passwords to the password manager' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "PasswordManagerEnabled" `
                | Select-Object -ExpandProperty "PasswordManagerEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.14.1"
    Task = "(L1) Ensure 'Enable startup boost' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "StartupBoostEnabled" `
                | Select-Object -ExpandProperty "StartupBoostEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.17.1"
    Task = "(L1) Ensure 'Specifies whether to allow insecure websites to make requests to more-private network endpoints' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InsecurePrivateNetworkRequestsAllowed" `
                | Select-Object -ExpandProperty "InsecurePrivateNetworkRequestsAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.20.1"
    Task = "(L1) Ensure 'Configure Microsoft Defender SmartScreen' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SmartScreenEnabled" `
                | Select-Object -ExpandProperty "SmartScreenEnabled"
        
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
    Id = "1.20.2"
    Task = "(L1) Ensure 'Configure Microsoft Defender SmartScreen to block potentially unwanted apps' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SmartScreenPuaEnabled" `
                | Select-Object -ExpandProperty "SmartScreenPuaEnabled"
        
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
    Id = "1.20.3"
    Task = "(L1) Ensure 'Enable Microsoft Defender SmartScreen DNS requests' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SmartScreenDnsRequestsEnabled" `
                | Select-Object -ExpandProperty "SmartScreenDnsRequestsEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.20.4"
    Task = "(L1) Ensure 'Force Microsoft Defender SmartScreen checks on downloads from trusted sources' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SmartScreenForTrustedDownloadsEnabled" `
                | Select-Object -ExpandProperty "SmartScreenForTrustedDownloadsEnabled"
        
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
    Id = "1.20.5"
    Task = "(L1) Ensure 'Prevent bypassing Microsoft Defender SmartScreen prompts for sites' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "PreventSmartScreenPromptOverride" `
                | Select-Object -ExpandProperty "PreventSmartScreenPromptOverride"
        
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
    Id = "1.20.6"
    Task = "(L1) Ensure 'Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "PreventSmartScreenPromptOverrideForFiles" `
                | Select-Object -ExpandProperty "PreventSmartScreenPromptOverrideForFiles"
        
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
    Id = "1.22.1"
    Task = "(L1) Ensure 'Configure Edge TyposquattingChecker' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "TyposquattingCheckerEnabled" `
                | Select-Object -ExpandProperty "TyposquattingCheckerEnabled"
        
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
    Id = "1.23"
    Task = "(L1) Ensure 'Ads setting for sites with intrusive ads' is set to 'Enabled: Block ads on sites with intrusive ads'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AdsSettingForIntrusiveAdsSites" `
                | Select-Object -ExpandProperty "AdsSettingForIntrusiveAdsSites"
        
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
    Id = "1.24"
    Task = "(L1) Ensure 'Allow download restrictions' is set to 'Enabled: Block potentially dangerous downloads'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DownloadRestrictions" `
                | Select-Object -ExpandProperty "DownloadRestrictions"
        
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
    Id = "1.25"
    Task = "(L2) Ensure 'Allow features to download assets from the Asset Delivery Service' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "EdgeAssetDeliveryServiceEnabled" `
                | Select-Object -ExpandProperty "EdgeAssetDeliveryServiceEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.26"
    Task = "(L2) Ensure 'Allow file selection dialog' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AllowFileSelectionDialogs" `
                | Select-Object -ExpandProperty "AllowFileSelectionDialogs"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.27"
    Task = "(L1) Ensure 'Allow Google Cast to connect to Cast devices on all IP addresses' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "MediaRouterCastAllowAllIPs" `
                | Select-Object -ExpandProperty "MediaRouterCastAllowAllIPs"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.28"
    Task = "(L1) Ensure 'Allow importing of autofill form data' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ImportAutofillFormData" `
                | Select-Object -ExpandProperty "ImportAutofillFormData"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.29"
    Task = "(L1) Ensure 'Allow importing of browser settings' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ImportBrowserSettings" `
                | Select-Object -ExpandProperty "ImportBrowserSettings"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.30"
    Task = "(L1) Ensure 'Allow importing of home page settings' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ImportHomepage" `
                | Select-Object -ExpandProperty "ImportHomepage"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.31"
    Task = "(L1) Ensure 'Allow importing of payment info' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ImportPaymentInfo" `
                | Select-Object -ExpandProperty "ImportPaymentInfo"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.32"
    Task = "(L1) Ensure 'Allow importing of saved passwords' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ImportSavedPasswords" `
                | Select-Object -ExpandProperty "ImportSavedPasswords"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.33"
    Task = "(L1) Ensure 'Allow importing of search engine settings' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ImportSearchEngine" `
                | Select-Object -ExpandProperty "ImportSearchEngine"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.34"
    Task = "(L1) Ensure 'Allow managed extensions to use the Enterprise Hardware Platform API' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "EnterpriseHardwarePlatformAPIEnabled" `
                | Select-Object -ExpandProperty "EnterpriseHardwarePlatformAPIEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.35"
    Task = "(L2) Ensure 'Allow or block audio capture' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AudioCaptureAllowed" `
                | Select-Object -ExpandProperty "AudioCaptureAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.36"
    Task = "(L2) Ensure 'Allow or block video capture' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "VideoCaptureAllowed" `
                | Select-Object -ExpandProperty "VideoCaptureAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.37"
    Task = "(L2) Ensure 'Allow or deny screen capture' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ScreenCaptureAllowed" `
                | Select-Object -ExpandProperty "ScreenCaptureAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.38"
    Task = "(L1) Ensure 'Allow personalization of ads search and news by sending browsing history to Microsoft' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "PersonalizationReportingEnabled" `
                | Select-Object -ExpandProperty "PersonalizationReportingEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.39"
    Task = "(L1) Ensure 'Allow queries to a Browser Network Time service' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BrowserNetworkTimeQueriesEnabled" `
                | Select-Object -ExpandProperty "BrowserNetworkTimeQueriesEnabled"
        
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
    Id = "1.40"
    Task = "(L1) Ensure 'Allow remote debugging' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "RemoteDebuggingAllowed" `
                | Select-Object -ExpandProperty "RemoteDebuggingAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.41"
    Task = "(L2) Ensure 'Allow suggestions from local providers' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "LocalProvidersEnabled" `
                | Select-Object -ExpandProperty "LocalProvidersEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.42"
    Task = "(L1) Ensure 'Allow the audio sandbox to run' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AudioSandboxEnabled" `
                | Select-Object -ExpandProperty "AudioSandboxEnabled"
        
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
    Id = "1.43"
    Task = "(L2) Ensure 'Allow unconfigured sites to be reloaded in Internet Explorer mode' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InternetExplorerIntegrationReloadInIEModeAllowed" `
                | Select-Object -ExpandProperty "InternetExplorerIntegrationReloadInIEModeAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.44"
    Task = "(L1) Ensure 'Allow user feedback' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "UserFeedbackAllowed" `
                | Select-Object -ExpandProperty "UserFeedbackAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.45"
    Task = "(L2) Ensure 'Allow users to open files using the ClickOnce protocol' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ClickOnceEnabled" `
                | Select-Object -ExpandProperty "ClickOnceEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.46"
    Task = "(L2) Ensure 'Allow users to open files using the DirectInvoke protocol' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DirectInvokeEnabled" `
                | Select-Object -ExpandProperty "DirectInvokeEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.47"
    Task = "(L2) Ensure 'Allow users to proceed from the HTTPS warning page' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SSLErrorOverrideAllowed" `
                | Select-Object -ExpandProperty "SSLErrorOverrideAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.48"
    Task = "(L1) Ensure 'Allow websites to query for available payment methods' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "PaymentMethodQueryEnabled" `
                | Select-Object -ExpandProperty "PaymentMethodQueryEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.49"
    Task = "(L2) Ensure 'AutoLaunch Protocols Component Enabled' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AutoLaunchProtocolsComponentEnabled" `
                | Select-Object -ExpandProperty "AutoLaunchProtocolsComponentEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.50"
    Task = "(L1) Ensure 'Automatically import another browser's data and settings at first run' is set to 'Enabled: Disables automatic import, and the import section of the first-run experience is skipped'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AutoImportAtFirstRun" `
                | Select-Object -ExpandProperty "AutoImportAtFirstRun"
        
            if (($regValue -ne 4)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 4"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.51"
    Task = "(L2) Ensure 'Block third party cookies' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BlockThirdPartyCookies" `
                | Select-Object -ExpandProperty "BlockThirdPartyCookies"
        
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
    Id = "1.52"
    Task = "(L1) Ensure 'Block tracking of users' web-browsing activity' is set to 'Enabled: Balanced (Blocks harmful trackers and trackers from sites user has not visited; content and ads will be less personalized)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "TrackingPrevention" `
                | Select-Object -ExpandProperty "TrackingPrevention"
        
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
    Id = "1.53"
    Task = "(L2) Ensure 'Browser sign-in settings' is set to 'Enabled: Disable browser sign-in'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BrowserSignin" `
                | Select-Object -ExpandProperty "BrowserSignin"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.54"
    Task = "(L1) Ensure 'Clear browsing data when Microsoft Edge closes' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ClearBrowsingDataOnExit" `
                | Select-Object -ExpandProperty "ClearBrowsingDataOnExit"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.55"
    Task = "(L1) Ensure 'Clear cached images and files when Microsoft Edge closes' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ClearCachedImagesAndFilesOnExit" `
                | Select-Object -ExpandProperty "ClearCachedImagesAndFilesOnExit"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.56"
    Task = "(L1) Ensure 'Configure InPrivate mode availability' is set to 'Enabled: InPrivate mode disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InPrivateModeAvailability" `
                | Select-Object -ExpandProperty "InPrivateModeAvailability"
        
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
    Id = "1.57"
    Task = "(L2) Ensure 'Configure Online Text To Speech' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ConfigureOnlineTextToSpeech" `
                | Select-Object -ExpandProperty "ConfigureOnlineTextToSpeech"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.58"
    Task = "(L2) Ensure 'Configure Related Matches in Find on Page' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "RelatedMatchesCloudServiceEnabled" `
                | Select-Object -ExpandProperty "RelatedMatchesCloudServiceEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.59"
    Task = "(L2) Ensure 'Configure Speech Recognition' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SpeechRecognitionEnabled" `
                | Select-Object -ExpandProperty "SpeechRecognitionEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.60"
    Task = "(L1) Ensure 'Configure the list of names that will bypass the HSTS policy check' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "HSTSPolicyBypassList" `
                | Select-Object -ExpandProperty "HSTSPolicyBypassList"
        
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
    Id = "1.61 A"
    Task = "(L1) Ensure 'Configure the list of types that are excluded from synchronization' is set to 'Enabled' (passwords)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled" `
                -Name "1" `
                | Select-Object -ExpandProperty "1"
        
            if ($regValue -ne "passwords") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: passwords"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.61 B"
    Task = "(L2) Ensure 'Configure the list of types that are excluded from synchronization' is set to 'Enabled' (settings)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled" `
                -Name "2" `
                | Select-Object -ExpandProperty "2"
        
            if ($regValue -ne "settings") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: settings"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.61 C"
    Task = " (L2) Ensure 'Configure the list of types that are excluded from synchronization' is set to 'Enabled' (favorites)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled" `
                -Name "3" `
                | Select-Object -ExpandProperty "3"
        
            if ($regValue -ne "favorites") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: favorites"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.61 D"
    Task = "(L2) Ensure 'Configure the list of types that are excluded from synchronization' is set to 'Enabled' (addressesAndMore)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled" `
                -Name "4" `
                | Select-Object -ExpandProperty "4"
        
            if ($regValue -ne "addressesAndMore") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: addressesAndMore"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.61 E"
    Task = "(L2) Ensure 'Configure the list of types that are excluded from synchronization' is set to 'Enabled' (extensions)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled" `
                -Name "5" `
                | Select-Object -ExpandProperty "5"
        
            if ($regValue -ne "extensions") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: extensions"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.61 F"
    Task = "(L2) Ensure 'Configure the list of types that are excluded from synchronization' is set to 'Enabled' (collections)"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled" `
                -Name "6" `
                | Select-Object -ExpandProperty "6"
        
            if ($regValue -ne "collections") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: collections"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.62"
    Task = "(L1) Ensure 'Configure the Share experience' is set to 'Enabled: Don't allow using the Share experience'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ConfigureShare" `
                | Select-Object -ExpandProperty "ConfigureShare"
        
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
    Id = "1.63"
    Task = "(L1) Ensure 'Configure whether form data and HTTP headers will be sent when entering or exiting Internet Explorer mode' is set to 'Enabled: Do not send form data or headers'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InternetExplorerIntegrationComplexNavDataTypes" `
                | Select-Object -ExpandProperty "InternetExplorerIntegrationComplexNavDataTypes"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.64"
    Task = "(L1) Ensure 'Continue running background apps after Microsoft Edge closes' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BackgroundModeEnabled" `
                | Select-Object -ExpandProperty "BackgroundModeEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.65"
    Task = "(L1) Ensure 'Control communication with the Experimentation and Configuration Service' is set to 'Enabled: Disable communication with the Experimentation and Configuration Service'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ExperimentationAndConfigurationServiceControl" `
                | Select-Object -ExpandProperty "ExperimentationAndConfigurationServiceControl"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.66"
    Task = "(L2) Ensure 'Control use of the Headless Mode' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "HeadlessModeEnabled" `
                | Select-Object -ExpandProperty "HeadlessModeEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.67"
    Task = "(L2) Ensure 'Control use of the Serial API' is set to 'Enable: Do not allow any site to request access to serial ports via the Serial API'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultSerialGuardSetting" `
                | Select-Object -ExpandProperty "DefaultSerialGuardSetting"
        
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
    Id = "1.68"
    Task = "(L2) Ensure 'Control where security restrictions on insecure origins apply' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "OverrideSecurityRestrictionsOnInsecureOriginDesc" `
                | Select-Object -ExpandProperty "OverrideSecurityRestrictionsOnInsecureOriginDesc"
        
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
    Id = "1.69"
    Task = "(L2) Ensure 'Default sensor setting' is set to 'Enabled: Do not allow any site to access sensors'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DefaultSensorsSetting" `
                | Select-Object -ExpandProperty "DefaultSensorsSetting"
        
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
    Id = "1.70"
    Task = "(L1) Ensure 'Delete old browser data on migration' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DeleteDataOnMigration" `
                | Select-Object -ExpandProperty "DeleteDataOnMigration"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.71"
    Task = "(L1) Ensure 'Disable saving browser history' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SavingBrowserHistoryDisabled" `
                | Select-Object -ExpandProperty "SavingBrowserHistoryDisabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.72"
    Task = "(L1) Ensure 'Disable synchronization of data using Microsoft sync services' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SyncDisabled" `
                | Select-Object -ExpandProperty "SyncDisabled"
        
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
    Id = "1.73"
    Task = "(L1) Ensure 'DNS interception checks enabled' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DNSInterceptionChecksEnabled" `
                | Select-Object -ExpandProperty "DNSInterceptionChecksEnabled"
        
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
    Id = "1.74"
    Task = "(L1) Ensure 'Enable AutoFill for addresses' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AutofillAddressEnabled" `
                | Select-Object -ExpandProperty "AutofillAddressEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.75"
    Task = "(L1) Ensure 'Enable AutoFill for payment instructions' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AutofillCreditCardEnabled" `
                | Select-Object -ExpandProperty "AutofillCreditCardEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.76"
    Task = "(L1) Ensure 'Enable browser legacy extension point blocking' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BrowserLegacyExtensionPointsBlockingEnabled" `
                | Select-Object -ExpandProperty "BrowserLegacyExtensionPointsBlockingEnabled"
        
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
    Id = "1.77"
    Task = "(L1) Ensure 'Enable component updates in Microsoft Edge' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ComponentUpdatesEnabled" `
                | Select-Object -ExpandProperty "ComponentUpdatesEnabled"
        
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
    Id = "1.78"
    Task = "(L1) Ensure 'Enable deleting browser and download history' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AllowDeletingBrowserHistory" `
                | Select-Object -ExpandProperty "AllowDeletingBrowserHistory"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.79"
    Task = "(L1) Ensure 'Enable Follow service in Microsoft Edge' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "EdgeFollowEnabled" `
                | Select-Object -ExpandProperty "EdgeFollowEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.80"
    Task = "(L1) Ensure 'Enable globally scoped HTTP auth cache' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "GloballyScopeHTTPAuthCacheEnabled" `
                | Select-Object -ExpandProperty "GloballyScopeHTTPAuthCacheEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.81"
    Task = "(L2) Ensure 'Enable guest mode' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BrowserGuestModeEnabled" `
                | Select-Object -ExpandProperty "BrowserGuestModeEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.82"
    Task = "(L1) Ensure 'Enable network prediction' is set to 'Enabled: Don't predict network actions on any network connection'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "NetworkPredictionOptions" `
                | Select-Object -ExpandProperty "NetworkPredictionOptions"
        
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
    Id = "1.83"
    Task = "(L1) Ensure 'Enable profile creation from the Identity flyout menu or the Settings page' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "BrowserAddProfileEnabled" `
                | Select-Object -ExpandProperty "BrowserAddProfileEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.84"
    Task = "(L1) Ensure 'Enable renderer code integrity' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "RendererCodeIntegrityEnabled" `
                | Select-Object -ExpandProperty "RendererCodeIntegrityEnabled"
        
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
    Id = "1.85"
    Task = "(L1) Ensure 'Enable resolution of navigation errors using a web service' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ResolveNavigationErrorsUseWebService" `
                | Select-Object -ExpandProperty "ResolveNavigationErrorsUseWebService"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.86"
    Task = "(L2) Ensure 'Enable Search suggestions' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SearchSuggestEnabled" `
                | Select-Object -ExpandProperty "SearchSuggestEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.87"
    Task = "(L1) Ensure 'Enable security warnings for command-line flags' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "CommandLineFlagSecurityWarningsEnabled" `
                | Select-Object -ExpandProperty "CommandLineFlagSecurityWarningsEnabled"
        
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
    Id = "1.88"
    Task = "(L1) Ensure 'Enable site isolation for every site' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SitePerProcess" `
                | Select-Object -ExpandProperty "SitePerProcess"
        
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
    Id = "1.89"
    Task = "(L2) Ensure 'Enable Translate' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "TranslateEnabled" `
                | Select-Object -ExpandProperty "TranslateEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.90"
    Task = "(L1) Ensure 'Enable travel assistance' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "TravelAssistanceEnabled" `
                | Select-Object -ExpandProperty "TravelAssistanceEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.91"
    Task = "(L1) Ensure 'Enable use of ephemeral profiles' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ForceEphemeralProfiles" `
                | Select-Object -ExpandProperty "ForceEphemeralProfiles"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.92"
    Task = "(L1) Ensure 'Enable warnings for insecure forms' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InsecureFormsWarningsEnabled" `
                | Select-Object -ExpandProperty "InsecureFormsWarningsEnabled"
        
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
    Id = "1.93"
    Task = "(L2) Ensure 'Enforce Bing SafeSearch' is set to 'Enabled: Configure moderate search restrictions in Bing'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ForceBingSafeSearch" `
                | Select-Object -ExpandProperty "ForceBingSafeSearch"
        
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
    Id = "1.94"
    Task = "(L2) Ensure 'Enforce Google SafeSearch' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ForceGoogleSafeSearch" `
                | Select-Object -ExpandProperty "ForceGoogleSafeSearch"
        
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
    Id = "1.95"
    Task = "(L1) Ensure 'Enhance the security state in Microsoft Edge' is set to 'Enabled: Balanced mode'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "EnhanceSecurityMode" `
                | Select-Object -ExpandProperty "EnhanceSecurityMode"
        
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
    Id = "1.96"
    Task = "(L1) Ensure 'Hide the First-run experience and splash screen' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "HideFirstRunExperience" `
                | Select-Object -ExpandProperty "HideFirstRunExperience"
        
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
    Id = "1.97"
    Task = "(L1) Ensure 'In-app support Enabled' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InAppSupportEnabled" `
                | Select-Object -ExpandProperty "InAppSupportEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.98"
    Task = "(L2) Ensure 'Let users snip a Math problem and get the solution with a step-by-step explanation in Microsoft Edge' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "MathSolverEnabled" `
                | Select-Object -ExpandProperty "MathSolverEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.99"
    Task = "(L1) Ensure 'Manage exposure of local IP addresses by WebRTC' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\WebRtcLocalIpsAllowedUrls" `
                -Name "Default" `
                | Select-Object -ExpandProperty "Default"
        
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
    Id = "1.100"
    Task = "(L1) Ensure 'Notify a user that a browser restart is recommended or required for pending updates' is set to 'Enabled: Required - Show a recurring prompt to the user indicating that a restart is required'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "RelaunchNotification" `
                | Select-Object -ExpandProperty "RelaunchNotification"
        
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
    Id = "1.101"
    Task = "(L1) Ensure 'Restrict exposure of local IP address by WebRTC' is set to 'Enabled: Allow public interface over http default route. This doesn't expose the local IP address'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "WebRtcLocalhostIpHandling" `
                | Select-Object -ExpandProperty "WebRtcLocalhostIpHandling"
        
            if ($regValue -ne "default_public_interface_only") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: default_public_interface_only"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.102"
    Task = "(L1) Ensure 'Set disk cache size, in bytes' is set to 'Enabled: 250609664'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "DiskCacheSize" `
                | Select-Object -ExpandProperty "DiskCacheSize"
        
            if (($regValue -ne 250609664)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 250609664"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.103"
    Task = "(L1) Ensure 'Set the time period for update notifications' is set to 'Enabled: 86400000'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "RelaunchNotificationPeriod" `
                | Select-Object -ExpandProperty "RelaunchNotificationPeriod"
        
            if (($regValue -ne 86400000)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 86400000"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.104"
    Task = "(L2) Ensure 'Shopping in Microsoft Edge Enabled' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "EdgeShoppingAssistantEnabled" `
                | Select-Object -ExpandProperty "EdgeShoppingAssistantEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.105"
    Task = "(L2) Ensure 'Show an `"Always open`" checkbox in external protocol dialog' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ExternalProtocolDialogShowAlwaysOpenCheckbox" `
                | Select-Object -ExpandProperty "ExternalProtocolDialogShowAlwaysOpenCheckbox"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.106"
    Task = "(L2) Ensure 'Show Microsoft Rewards experiences' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "ShowMicrosoftRewards" `
                | Select-Object -ExpandProperty "ShowMicrosoftRewards"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.107"
    Task = "(L1) Ensure 'Show the Reload in Internet Explorer mode button in the toolbar' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "InternetExplorerModeToolbarButtonEnabled" `
                | Select-Object -ExpandProperty "InternetExplorerModeToolbarButtonEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.108"
    Task = "(L1) Ensure 'Specifies whether SharedArrayBuffers can be used in a non cross-origin-isolated context' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SharedArrayBufferUnrestrictedAccessAllowed" `
                | Select-Object -ExpandProperty "SharedArrayBufferUnrestrictedAccessAllowed"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.109"
    Task = "(L2) Ensure 'Specify if online OCSP/CRL checks are required for local trust anchors' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "RequireOnlineRevocationChecksForLocalAnchors" `
                | Select-Object -ExpandProperty "RequireOnlineRevocationChecksForLocalAnchors"
        
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
    Id = "1.110"
    Task = "(L1) Ensure 'Suggest similar pages when a webpage can’t be found' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "AlternateErrorPagesEnabled" `
                | Select-Object -ExpandProperty "AlternateErrorPagesEnabled"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.111"
    Task = "(L1) Ensure 'Suppress the unsupported OS warning' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
                -Name "SuppressUnsupportedOSWarning" `
                | Select-Object -ExpandProperty "SuppressUnsupportedOSWarning"
        
            if (($regValue -ne 0)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: x == 0"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "3.1.1"
    Task = "(L1) Ensure 'Update policy override default' is set to 'Enabled: Always allow updates (recommended)'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate" `
                -Name "UpdateDefault" `
                | Select-Object -ExpandProperty "UpdateDefault"
        
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
