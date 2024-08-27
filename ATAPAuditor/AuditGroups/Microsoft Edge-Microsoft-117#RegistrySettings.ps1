[AuditTest] @{
    Id = "1.1.1"
    Task = "Ensure 'Enable site isolation for every site' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.2"
    Task = "Ensure 'Supported authentication schemes' is set to 'ntlm, negotiate'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
                -Name "AuthSchemes" `
                | Select-Object -ExpandProperty "AuthSchemes"
        
            if ($regValue -notmatch "^(ntlm\s*,\s*negotiate|negotiate\s*,\s*ntlm)$") {
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
    Id = "1.1.3"
    Task = "Ensure 'Allow user-level native messaging hosts (installed without admin permissions)' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
                -Name "NativeMessagingUserLevelHosts" `
                | Select-Object -ExpandProperty "NativeMessagingUserLevelHosts"
        
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
    Id = "1.1.4"
    Task = "Ensure 'Configure Microsoft Defender SmartScreen' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.5"
    Task = "Ensure 'Prevent bypassing Microsoft Defender SmartScreen prompts for sites' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.6"
    Task = "Ensure 'Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.7"
    Task = "Ensure 'Allow users to proceed from the HTTPS warning page' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.8"
    Task = "Ensure 'Configure Microsoft Defender SmartScreen to block potentially unwanted apps' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.9"
    Task = "Ensure 'Allow Basic authentication for HTTP' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.10"
    Task = "Ensure 'Allow unconfigured sites to be reloaded in Internet Explorer mode' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.11"
    Task = "Ensure 'Specifies whether SharedArrayBuffers can be used in a non cross-origin-isolated context' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.12"
    Task = "Ensure 'Specifies whether to allow websites to make requests to more-private network endpoints' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.13"
    Task = "Ensure 'Enable browser legacy extension point blocking' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.14"
    Task = "Ensure 'Show the Reload in Internet Explorer mode button in the toolbar' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.15"
    Task = "Ensure 'Configure Edge TyposquattingChecker' is set to 'Enabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
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
    Id = "1.1.16"
    Task = "Ensure 'Enhance images enabled' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
                -Name "EdgeEnhanceImagesEnabled" `
                | Select-Object -ExpandProperty "EdgeEnhanceImagesEnabled"
        
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
    Id = "1.1.17"
    Task = "Ensure 'Force WebSQL to be enabled' is set to 'Disabled'"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
                -Name "WebSQLAccess" `
                | Select-Object -ExpandProperty "WebSQLAccess"
        
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
    Id = "1.1.18"
    Task = "Ensure 'Automatically open downloaded MHT or MHTML files from the web in Internet Explorer mode' is set to 'Disabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" `
                -Name "InternetExplorerIntegrationZoneIdentifierMhtFileAllowed" `
                | Select-Object -ExpandProperty "InternetExplorerIntegrationZoneIdentifierMhtFileAllowed"
        
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
    Id = "1.1.20"
    Task = "Block all extensions not on allow list"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist" `
                -Name "1" `
                | Select-Object -ExpandProperty "1"
        
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
