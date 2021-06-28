[AuditTest] @{
    Id = "DTOO104"
    Task = "Disabling of user name and password syntax from being used in URLs must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO110"
    Task = "Blocking as default file block opening behavior must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "OpenInProtectedView" `
                | Select-Object -ExpandProperty "OpenInProtectedView"
        
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
    Id = "DTOO111"
    Task = "The Internet Explorer Bind to Object functionality must be enabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO117"
    Task = "Saved from URL mark to assure Internet zone processing must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO119"
    Task = "Configuration for file validation must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\filevalidation" `
                -Name "EnableOnLoad" `
                | Select-Object -ExpandProperty "EnableOnLoad"
        
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
    Id = "DTOO121"
    Task = "Files from the Internet zone must be opened in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\protectedview" `
                -Name "DisableInternetFilesInPV" `
                | Select-Object -ExpandProperty "DisableInternetFilesInPV"
        
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
    Id = "DTOO123"
    Task = "Navigation to URLs embedded in Office products must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO124"
    Task = "Scripted Window Security must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO126"
    Task = "Add-on Management functionality must be allowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO127"
    Task = "Add-ins to Office applications must be signed by a Trusted Publisher."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security" `
                -Name "RequireAddinSig" `
                | Select-Object -ExpandProperty "RequireAddinSig"
        
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
    Id = "DTOO129"
    Task = "Links that invoke instances of Internet Explorer from within an Office product must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO131"
    Task = "Trust Bar Notifications for unsigned application add-ins must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security" `
                -Name "NoTBPromptUnsignedAddin" `
                | Select-Object -ExpandProperty "NoTBPromptUnsignedAddin"
        
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
    Id = "DTOO132"
    Task = "File Downloads must be configured for proper restrictions."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO133"
    Task = "All automatic loading from trusted locations must be disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\trusted locations" `
                -Name "AllLocationsDisabled" `
                | Select-Object -ExpandProperty "AllLocationsDisabled"
        
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
    Id = "DTOO134"
    Task = "Disallowance of trusted locations on the network must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\trusted locations" `
                -Name "AllowNetworkLocations" `
                | Select-Object -ExpandProperty "AllowNetworkLocations"
        
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
    Id = "DTOO139"
    Task = "The Save commands default file format must be configured."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\options" `
                -Name "DefaultFormat" `
                | Select-Object -ExpandProperty "DefaultFormat"
        
            if ($regValue -ne "(blank)") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: (blank)"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "DTOO142"
    Task = "Force encrypted macros to be scanned in open XML documents must be determined and configured."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security" `
                -Name "WordBypassEncryptedMacroScan" `
                | Select-Object -ExpandProperty "WordBypassEncryptedMacroScan"
        
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
    Id = "DTOO146"
    Task = "Trust access for VBA must be disallowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security" `
                -Name "AccessVBOM" `
                | Select-Object -ExpandProperty "AccessVBOM"
        
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
    Id = "DTOO209"
    Task = "Protection from zone elevation must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO211"
    Task = "ActiveX Installs must be configured for proper restriction."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
        
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
    Id = "DTOO288"
    Task = "Files in unsafe locations must be opened in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\protectedview" `
                -Name "DisableUnsafeLocationsInPV" `
                | Select-Object -ExpandProperty "DisableUnsafeLocationsInPV"
        
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
    Id = "DTOO292"
    Task = "Document behavior if file validation fails must be set."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation" `
                -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"
        
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
    Id = "DTOO292_b"
    Task = "Document behavior if file validation fails must be set."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation" `
                -Name "DisableEditFromPV" `
                | Select-Object -ExpandProperty "DisableEditFromPV"
        
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
    Id = "DTOO293"
    Task = "Attachments opened from Outlook must be in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\protectedview" `
                -Name "DisableAttachmentsInPV" `
                | Select-Object -ExpandProperty "DisableAttachmentsInPV"
        
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
    Id = "DTOO302"
    Task = "The automatically update links feature must be disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\options" `
                -Name "DontUpdateLinks" `
                | Select-Object -ExpandProperty "DontUpdateLinks"
        
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
    Id = "DTOO304"
    Task = "Warning Bar settings for VBA macros must be configured."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security" `
                -Name "VBAWarnings" `
                | Select-Object -ExpandProperty "VBAWarnings"
        
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
    Id = "DTOO328"
    Task = "Online translation dictionaries must not be used."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\software\policies\Microsoft\office\16.0\common\research\translation" `
                -Name "useonline" `
                | Select-Object -ExpandProperty "useonline"
        
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
    Id = "DTOO333"
    Task = "Word 2 and earlier binary documents and templates must be blocked for open/save."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "Word2Files" `
                | Select-Object -ExpandProperty "Word2Files"
        
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
    Id = "DTOO334"
    Task = "Word 2000 binary documents and templates must be configured to edit in protected view."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "Word2000Files" `
                | Select-Object -ExpandProperty "Word2000Files"
        
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
    Id = "DTOO336"
    Task = "Word 6.0 binary documents and templates must be configured for block open/save actions."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "Word60Files" `
                | Select-Object -ExpandProperty "Word60Files"
        
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
    Id = "DTOO337"
    Task = "Word 95 binary documents and templates must be configured to edit in protected view."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "Word95Files" `
                | Select-Object -ExpandProperty "Word95Files"
        
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
    Id = "DTOO338"
    Task = "Word 97 binary documents and templates must be configured to edit in protected view."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "Word97Files" `
                | Select-Object -ExpandProperty "Word97Files"
        
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
    Id = "DTOO339"
    Task = "Word XP binary documents and templates must be configured to edit in protected view."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" `
                -Name "WordXPFiles" `
                | Select-Object -ExpandProperty "WordXPFiles"
        
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
    Id = "DTOO600"
    Task = "Macros must be blocked from running in Office files from the Internet."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\word\security" `
                -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"
        
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
    Id = "DTOO605"
    Task = "Files on local Intranet UNC must be opened in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Word\security\protectedview" `
                -Name "DisableIntranetCheck" `
                | Select-Object -ExpandProperty "DisableIntranetCheck"
        
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
