[AuditTest] @{
    Id = "DTOO104"
    Task = "Disabling of user name and password syntax from being used in URLs must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
    Id = "DTOO105"
    Task = "Open/Save actions for Excel 4 macrosheets and add-in files must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL4Macros" `
                | Select-Object -ExpandProperty "XL4Macros"
        
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
    Id = "DTOO106"
    Task = "Open/Save actions for Excel 4 workbooks must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL4Workbooks" `
                | Select-Object -ExpandProperty "XL4Workbooks"
        
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
    Id = "DTOO107"
    Task = "Open/Save actions for Excel 4 worksheets must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL4Worksheets" `
                | Select-Object -ExpandProperty "XL4Worksheets"
        
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
    Id = "DTOO108"
    Task = "Actions for Excel 95 workbooks must be configured to edit in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL95Workbooks" `
                | Select-Object -ExpandProperty "XL95Workbooks"
        
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
    Id = "DTOO109"
    Task = "Actions for Excel 95-97 workbooks and templates must be configured to edit in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security\fileblock" `
                -Name "XL9597WorkbooksandTemplates" `
                | Select-Object -ExpandProperty "XL9597WorkbooksandTemplates"
        
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
    Id = "DTOO110"
    Task = "Blocking as default file block opening behavior must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
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
    Task = "Enabling IE Bind to Object functionality must be present."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" `
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
    Id = "DTOO112"
    Task = "Open/Save actions for Dif and Sylk files must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "DifandSylkFiles" `
                | Select-Object -ExpandProperty "DifandSylkFiles"
        
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
    Id = "DTOO113"
    Task = "Open/Save actions for Excel 2 macrosheets and add-in files must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL2Macros" `
                | Select-Object -ExpandProperty "XL2Macros"
        
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
    Id = "DTOO114"
    Task = "Open/Save actions for Excel 2 worksheets must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL2Worksheets" `
                | Select-Object -ExpandProperty "XL2Worksheets"
        
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
    Id = "DTOO115"
    Task = "Open/Save actions for Excel 3 macrosheets and add-in files must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL3Macros" `
                | Select-Object -ExpandProperty "XL3Macros"
        
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
    Id = "DTOO116"
    Task = "Open/Save actions for Excel 3 worksheets must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "XL3Worksheets" `
                | Select-Object -ExpandProperty "XL3Worksheets"
        
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
    Id = "DTOO117"
    Task = "Saved from URL mark to assure Internet zone processing must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation" `
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
    Id = "DTOO120"
    Task = "Open/Save actions for web pages and Excel 2003 XML spreadsheets must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "HtmlandXmlssFiles" `
                | Select-Object -ExpandProperty "HtmlandXmlssFiles"
        
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
    Id = "DTOO121"
    Task = "Files from the Internet zone must be opened in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" `
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
    Id = "DTOO122"
    Task = "Open/Save actions for dBase III / IV files must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" `
                -Name "DBaseFiles" `
                | Select-Object -ExpandProperty "DBaseFiles"
        
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
    Id = "DTOO123"
    Task = "Navigation to URLs embedded in Office products must be blocked."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security" `
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
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security" `
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
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" `
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" `
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\options" `
                -Name "DefaultFormat" `
                | Select-Object -ExpandProperty "DefaultFormat"
        
            if ($regValue -ne 51) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 51"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
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
    Task = "The scanning of encrypted macros in open XML documents must be enforced."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security" `
                -Name "ExcelBypassEncryptedMacroScan" `
                | Select-Object -ExpandProperty "ExcelBypassEncryptedMacroScan"
        
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
    Id = "DTOO145"
    Task = "Macro storage must be in personal macro workbooks."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\options\binaryoptions" `
                -Name "fGlobalSheet_37_1" `
                | Select-Object -ExpandProperty "fGlobalSheet_37_1"
        
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
    Id = "DTOO146"
    Task = "Trust access for VBA must be disallowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security" `
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
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"
        
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" `
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation" `
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation" `
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
    Task = "Excel attachments opened from Outlook must be in Protected View."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Excel\security\protectedview" `
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
    Id = "DTOO304"
    Task = "Warning Bar settings for VBA macros must be configured."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\software\policies\Microsoft\office\16.0\excel\security" `
                -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"
        
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
    Id = "DTOO418"
    Task = "WEBSERVICE functions must be disabled."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\software\policies\Microsoft\office\16.0\excel\security" `
                -Name "webservicefunctionwarnings" `
                | Select-Object -ExpandProperty "webservicefunctionwarnings"
        
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
    Id = "DTOO419"
    Task = "Corrupt workbook options must be disallowed."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\software\policies\Microsoft\office\16.0\excel\options" `
                -Name "extractdatadisableui" `
                | Select-Object -ExpandProperty "extractdatadisableui"
        
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
    Id = "DTOO600"
    Task = "Macros must be blocked from running in Office files from the Internet."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security" `
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
                -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" `
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
