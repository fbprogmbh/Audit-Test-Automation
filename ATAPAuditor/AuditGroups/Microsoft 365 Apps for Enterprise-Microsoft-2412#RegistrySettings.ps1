# Office root folder
$officePaths = @(
    # Office 365 / 2019 / 2021 (the standard install paths)
    "C:\Program Files\Microsoft Office\root\Office16",
    "C:\Program Files (x86)\Microsoft Office\root\Office16"
    
    # Office 2016 (MSI)
    "C:\Program Files\Microsoft Office\Office16",
    "C:\Program Files (x86)\Microsoft Office\Office16",

    # Office 2016 (x32 MSI on x64 OS)
    "C:\Program Files (x86)\Microsoft Office\root\Office16",
    "C:\Program Files (x86)\Microsoft Office\Office16\",
    
    # Office 2016 (x64 MSI on x64 OS)
    "C:\Program Files\Microsoft Office\Office16\"
)

# Mapping of applications to exe names
$exeMap = @{
    "Groove"              = "GROOVE.EXE"
    "Excel"               = "EXCEL.EXE"
    "Publisher"           = "MSPUB.EXE"
    "PowerPoint"          = "POWERPNT.EXE"
    "PowerPoint Viewer"   = "PPTVIEW.EXE"
    "Project"             = "WINPROJ.EXE"
    "Word"                = "WINWORD.EXE"
    "Outlook"             = "OUTLOOK.EXE"
    "SharePoint Designer" = "SPDESIGN.EXE"
    "Expression Web"      = "EXPRWD.EXE"
    "Access"              = "MSACCESS.EXE"
    "OneNote"             = "ONENOTE.EXE"
    "MS Script Editor"    = "MSE7.EXE"
    "Visio"               = "VISIO.EXE"
    
}

# Check if any Office installation path exists -> if not existend, then Office is not installed
$OfficeInstalled = $false
foreach ($path in $officePaths) {
    if (Test-Path $path) {
        $OfficeInstalled = $true
        break
    }
}

# Determine which Office apps are installed
$installedOfficeApps = @{}

if ($OfficeInstalled) {
    foreach ($app in $exeMap.Keys) {
        foreach ($path in $officePaths) {
            $exePath = Join-Path $path $exeMap[$app]
            if (Test-Path $exePath) {
                $installedOfficeApps[$app] = $true
                break
            }
        }
        if (-not $installedOfficeApps.ContainsKey($app)) {
            $installedOfficeApps[$app] = $false
        }
    }
}
else {
    Write-Warning "Office could not be found on this system."
    Write-Warning "If Office is installed, please leave a comment in Issue-718 (https://github.com/fbprogmbh/Hardening-Audit-Tool-AuditTAP/issues/718) and provide requested information from 'What happened?' section."
}

[AuditTest] @{
    Id   = "1.1.1"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"
            
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.2"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.3"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"
                
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.4"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"
                
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.5"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"
            
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.6"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.7"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"
                
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.8"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"
                
                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.9"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.10"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (spDesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.11"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.12"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.13"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.14"
    Task = "Ensure 'Add-on Management' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.15"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.16"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.17"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.18"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.19"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.20"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {        
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.21"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.22"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.23"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.24"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.25"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.26"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.27"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.28"
    Task = "Ensure 'Disable user name and password' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.29"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneDrive for Business"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.30"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.31"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.32"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.33"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.34"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.35"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.36"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.37"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.38"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.39"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.40"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.41"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.42"
    Task = "Ensure 'Local Machine Zone Lockdown Security' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.43"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.44"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.45"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.46"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.47"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.48"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.49"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.50"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.51"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.52"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.53"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.54"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.55"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.56"
    Task = "Ensure 'Consistent Mime Handling' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.57"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.58"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.59"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.60"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.61"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.62"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.63"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.64"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.65"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.66"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (spDesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.67"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.68"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.69"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.70"
    Task = "Ensure 'Mime Sniffing Safety Feature' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.71"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.72"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.73"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.74"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.75"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.76"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.77"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.78"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.79"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.80"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.81"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.82"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.83"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.84"
    Task = "Ensure 'Object Caching Protection' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_OBJECT_CACHING" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.85"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.86"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.87"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.88"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.89"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.90"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.91"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.92"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.93"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.94"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.95"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.96"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.97"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.98"
    Task = "Ensure 'Restrict ActiveX Install' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.99"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.100"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.101"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.102"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.103"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.104"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.105"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.106"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.107"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.108"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.109"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.110"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.111"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.112"
    Task = "Ensure 'Restrict File Download' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.113"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.114"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.115"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.116"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {    
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.117"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.118"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.119"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.120"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.121"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.122"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.123"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.124"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.125"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.126"
    Task = "Ensure 'Information Bar' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.127"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.128"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.129"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.130"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.131"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.132"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.133"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.134"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.135"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.136"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.137"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.138"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.139"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.140"
    Task = "Ensure 'Saved from URL' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.141"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.142"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.143"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.144"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.145"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.146"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.147"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.148"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.149"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.150"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.151"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.152"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.153"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.154"
    Task = "Ensure 'Navigate URL' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.155"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.156"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.157"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.158"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.159"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.160"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.161"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.162"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.163"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.164"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.165"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.166"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.167"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.168"
    Task = "Ensure 'Scripted Window Security Restrictions' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.169"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (groove.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Groove"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "groove.exe" `
                | Select-Object -ExpandProperty "groove.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.170"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.171"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.172"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.173"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (pptview.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint Viewer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "pptview.exe" `
                | Select-Object -ExpandProperty "pptview.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.174"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.175"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.176"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.177"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.178"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (spdesign.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["SharePoint Designer"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "spDesign.exe" `
                | Select-Object -ExpandProperty "spDesign.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.179"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (exprwd.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Expression Web"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "exprwd.exe" `
                | Select-Object -ExpandProperty "exprwd.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.180"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.181"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (onent.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "onent.exe" `
                | Select-Object -ExpandProperty "onent.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.182"
    Task = "Ensure 'Protection From Zone Elevation' is set to 'Enabled' (mse7.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["MS Script Editor"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" `
                    -Name "mse7.exe" `
                | Select-Object -ExpandProperty "mse7.exe"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "1.1.183"
    Task = "Block Flash activation in Office documents (Office 16.0, ActivationFilterOverride, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.184"
    Task = "Block Flash activation in Office documents (Office 16.0, Compatibility Flags, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.185"
    Task = "Block Flash activation in Office documents (Office 16.0, ActivationFilterOverride, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.186"
    Task = "Block Flash activation in Office documents (Office 16.0, Compatibility Flags, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.187"
    Task = "Ensure 'Block Flash activation in Office documents' is set to '[Equaling `"Block all Flash activation`"]'."
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\Common\COM Compatibility" `
                -Name "Comment" `
            | Select-Object -ExpandProperty "Comment"

            if ($regValue -ne "Block all Flash activation") {
                return @{
                    Message = "Registry value is '$regValue'. Expected: Block all Flash activation"
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
    Id   = "1.1.188"
    Task = "Block Flash activation in Office documents (Office, ActivationFilterOverride, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.189"
    Task = "Block Flash activation in Office documents (Office, Compatibility Flags, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.190"
    Task = "Block Flash activation in Office documents (Office, ActivationFilterOverride, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.191"
    Task = "Block Flash activation in Office documents (Office, Compatibility Flags, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.192"
    Task = "Ensure 'Disable HTTP fallback for SIP connection' is set to 'Enabled' (lync)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\office\16.0\lync" `
                -Name "disablehttpconnect" `
            | Select-Object -ExpandProperty "disablehttpconnect"

            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
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
    Id   = "1.1.193"
    Task = "Ensure 'Configure SIP security mode' is set to 'Enabled' (lync)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\office\16.0\lync" `
                -Name "enablesiphighsecuritymode" `
            | Select-Object -ExpandProperty "enablesiphighsecuritymode"

            if ($regValue -ne 1) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1"
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
    Id   = "1.1.194"
    Task = "Block Flash activation in Office documents (WOW6432, Office 16.0, ActivationFilterOverride, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.195"
    Task = "Block Flash activation in Office documents (WOW6432, Office 16.0, Compatibility Flags, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.196"
    Task = "Block Flash activation in Office documents (WOW6432, Office 16.0, ActivationFilterOverride, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.197"
    Task = "Block Flash activation in Office documents (WOW6432, Office 16.0, Compatibility Flags, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.198"
    Task = "Block Flash activation in Office documents (WOW6432, Office, ActivationFilterOverride, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.199"
    Task = "Block Flash activation in Office documents (WOW6432, Office, Compatibility Flags, Shockwave Flash Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "1.1.200"
    Task = "Block Flash activation in Office documents (WOW6432, Office, ActivationFilterOverride, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }

        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "ActivationFilterOverride" `
            | Select-Object -ExpandProperty "ActivationFilterOverride"

            if ($regValue -ne 0) {
                return @{
                    Message = "Registry value is '$regValue'. Expected:0"
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
    Id   = "1.1.201"
    Task = "Block Flash activation in Office documents (WOW6432, Office, Compatibility Flags, Macromedia Flash Factory Object)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" `
                -Name "Compatibility Flags" `
            | Select-Object -ExpandProperty "Compatibility Flags"

            if (($regValue -ne 1024)) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 1024"
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
    Id   = "2.2.1"
    Task = "Ensure 'Don't allow Dynamic Data Exchange (DDE) server launch in Excel' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\external content" `
                    -Name "disableddeserverlaunch" `
                | Select-Object -ExpandProperty "disableddeserverlaunch"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "2.2.2"
    Task = "Ensure 'Don't allow Dynamic Data Exchange (DDE) server lookup in Excel' is set to 'Enabled' (disableddeserverlookup)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\external content" `
                    -Name "disableddeserverlookup" `
                | Select-Object -ExpandProperty "disableddeserverlookup"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "2.2.3"
    Task = "Ensure 'Dynamic Data Exchange' is not set (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "allowdde" `
                | Select-Object -ExpandProperty "allowdde"
                
                return @{
                    Message = "Registry value found."
                    Status  = "False"
                }
            }
            catch [System.Management.Automation.PSArgumentException] {
                return @{
                    Message = "Compliant. Registry value not found."
                    Status  = "True"
                }
            }
            catch [System.Management.Automation.ItemNotFoundException] {
                return @{
                    Message = "Compliant. Registry key not found."
                    Status  = "True"
                }
            }
        
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
    }

}
[AuditTest] @{
    Id   = "3.2.1"
    Task = "Ensure 'dBase III / IV files' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "dbasefiles" `
                | Select-Object -ExpandProperty "dbasefiles"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.2"
    Task = "Ensure 'Dif and Sylk files' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "difandsylkfiles" `
                | Select-Object -ExpandProperty "difandsylkfiles"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.3"
    Task = "Ensure 'Excel 2 macrosheets and add-in files' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl2macros" `
                | Select-Object -ExpandProperty "xl2macros"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.4"
    Task = "Ensure 'Excel 2 worksheets' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl2worksheets" `
                | Select-Object -ExpandProperty "xl2worksheets"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.5"
    Task = "Ensure 'Excel 3 macrosheets and add-in files' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl3macros" `
                | Select-Object -ExpandProperty "xl3macros"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.6"
    Task = "Ensure 'Excel 3 worksheets' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl3worksheets" `
                | Select-Object -ExpandProperty "xl3worksheets"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.7"
    Task = "Ensure 'Excel 4 macrosheets and add-in files' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl4macros" `
                | Select-Object -ExpandProperty "xl4macros"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.8"
    Task = "Ensure 'Excel 4 workbooks' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl4workbooks" `
                | Select-Object -ExpandProperty "xl4workbooks"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.9"
    Task = "Ensure 'Excel 4 worksheets' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl4worksheets" `
                | Select-Object -ExpandProperty "xl4worksheets"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.10"
    Task = "Ensure 'Excel 95 workbooks' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl95workbooks" `
                | Select-Object -ExpandProperty "xl95workbooks"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.11"
    Task = "Ensure 'Excel 95-97 workbooks and templates' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl9597workbooksandtemplates" `
                | Select-Object -ExpandProperty "xl9597workbooksandtemplates"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.12"
    Task = "Ensure 'Set default file block behavior' is set to 'Blocked files are not opened' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "3.2.13"
    Task = "Ensure 'Web pages and Excel 2003 XML spreadsheets' is set to ' File block setting: Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "htmlandxmlssfiles" `
                | Select-Object -ExpandProperty "htmlandxmlssfiles"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.14"
    Task = "Ensure 'Excel 97-2003 workbooks and templates' is set to 'Open/Save blocked, use open policy' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\fileblock" `
                    -Name "xl97workbooksandtemplates" `
                | Select-Object -ExpandProperty "xl97workbooksandtemplates"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.15"
    Task = "Ensure 'Set default file block behavior' is set to 'Blocked files are not opened' (PowerPoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\fileblock" `
                    -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "3.2.16"
    Task = "Ensure 'PowerPoint 97-2003 presentations, shows, templates and add-in files' is set to 'Open/Save blocked, use open policy' (PowerPoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\fileblock" `
                    -Name "binaryfiles" `
                | Select-Object -ExpandProperty "binaryfiles"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.17"
    Task = "Ensure 'Visio 2000-2002 Binary Drawings, Templates and Stencils' is set to 'Open/Save blocked' (visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security\fileblock" `
                    -Name "visio2000files" `
                | Select-Object -ExpandProperty "visio2000files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.18"
    Task = "Ensure 'Visio 2003-2010 Binary Drawings, Templates and Stencils' is set to 'Open/Save blocked' (visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security\fileblock" `
                    -Name "visio2003files" `
                | Select-Object -ExpandProperty "visio2003files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.19"
    Task = "Ensure 'Visio 5.0 or earlier Binary Drawings, Templates and Stencils' is set to 'Open/Save blocked' (visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security\fileblock" `
                    -Name "visio50andearlierfiles" `
                | Select-Object -ExpandProperty "visio50andearlierfiles"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.20"
    Task = "Ensure 'Set default file block behavior' is set to 'Blocked files are not opened' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "3.2.21"
    Task = "Ensure 'Word 2 and earlier binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word2files" `
                | Select-Object -ExpandProperty "word2files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.22"
    Task = "Ensure 'Word 6.0 binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word60files" `
                | Select-Object -ExpandProperty "word60files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.23"
    Task = "Ensure 'Word 95 binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word95files" `
                | Select-Object -ExpandProperty "word95files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.24"
    Task = "Ensure 'Word 97 binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word97files" `
                | Select-Object -ExpandProperty "word97files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.25"
    Task = "Ensure 'Word 2000 binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word2000files" `
                | Select-Object -ExpandProperty "word2000files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.26"
    Task = "Ensure 'Word 2003 binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word2003files" `
                | Select-Object -ExpandProperty "word2003files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.27"
    Task = "Ensure 'Word 2007 and later binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "word2007files" `
                | Select-Object -ExpandProperty "word2007files"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "3.2.28"
    Task = "Ensure 'Word XP binary documents and templates' is set to 'Open/Save blocked, use open policy' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\fileblock" `
                    -Name "wordxpfiles" `
                | Select-Object -ExpandProperty "wordxpfiles"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "4.1.1"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (excel.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "excel.exe" `
                | Select-Object -ExpandProperty "excel.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.2"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (mspub.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "mspub.exe" `
                | Select-Object -ExpandProperty "mspub.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.3"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (powerpnt.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "powerpnt.exe" `
                | Select-Object -ExpandProperty "powerpnt.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.4"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (onenote.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["OneNote"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "onenote.exe" `
                | Select-Object -ExpandProperty "onenote.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.5"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (visio.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "visio.exe" `
                | Select-Object -ExpandProperty "visio.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.6"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (winproj.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "winproj.exe" `
                | Select-Object -ExpandProperty "winproj.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.7"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (winword.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "winword.exe" `
                | Select-Object -ExpandProperty "winword.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.8"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (outlook.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "outlook.exe" `
                | Select-Object -ExpandProperty "outlook.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "4.1.9"
    Task = "Ensure 'Restrict legacy JScript execution for Office' is set to 'Enabled' (msaccess.exe)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" `
                    -Name "msaccess.exe" `
                | Select-Object -ExpandProperty "msaccess.exe"

                if ($regValue -ne 69632) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:69632"
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
}
[AuditTest] @{
    Id   = "5.2.1"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (16.0, access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.2"
    Task = "Ensure 'VBA Macro Notification Settings: Require macros to be signed by a trusted publisher' is set to 'Enabled' (16.0, access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security" `
                    -Name "vbadigsigtrustedpublishers" `
                | Select-Object -ExpandProperty "vbadigsigtrustedpublishers"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.3"
    Task = "Ensure 'VBA Macro Notification Settings: Block certificates from trusted publishers that are only installed in the current user certificate store' is set to 'Disabled' (16.0, access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security" `
                    -Name "vbarequirelmtrustedpublisher" `
                | Select-Object -ExpandProperty "vbarequirelmtrustedpublisher"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.4"
    Task = "Ensure 'VBA Macro Notification Settings: Require Extended Key Usage (EKU) for certificates from trusted publishers' is set to 'Disabled' (16.0, access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security" `
                    -Name "vbarequiredigsigwithcodesigningeku" `
                | Select-Object -ExpandProperty "vbarequiredigsigwithcodesigningeku"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.5"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (16.0, excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.6"
    Task = "Ensure 'Enable Excel 4.0 macros when VBA macros are enabled' is Disabled (16.0, excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "xl4macrowarningfollowvba" `
                | Select-Object -ExpandProperty "xl4macrowarningfollowvba"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.7"
    Task = "Ensure 'VBA Macro Notification Settings: Require macros to be signed by a trusted publisher' is set to 'Enabled' (16.0, excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "vbadigsigtrustedpublishers" `
                | Select-Object -ExpandProperty "vbadigsigtrustedpublishers"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.8"
    Task = "Ensure 'VBA Macro Notification Settings: Block certificates from trusted publishers that are only installed in the current user certificate store' is set to 'Disabled' (16.0, excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "vbarequirelmtrustedpublisher" `
                | Select-Object -ExpandProperty "vbarequirelmtrustedpublisher"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.9"
    Task = "Ensure 'VBA Macro Notification Settings: Require Extended Key Usage (EKU) for certificates from trusted publishers' is set to 'Disabled' (16.0, excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "vbarequiredigsigwithcodesigningeku" `
                | Select-Object -ExpandProperty "vbarequiredigsigwithcodesigningeku"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.10"
    Task = "Ensure 'Prevent Excel from running XLM macros' is set to 'Enabled' (16.0, excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "xl4macrooff" `
                | Select-Object -ExpandProperty "xl4macrooff"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.11"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (ms project)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\ms project\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.12"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (16.0, powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.13"
    Task = "Ensure 'VBA Macro Notification Settings: Require macros to be signed by a trusted publisher' is set to 'Enabled' (16.0, powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "vbadigsigtrustedpublishers" `
                | Select-Object -ExpandProperty "vbadigsigtrustedpublishers"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.14"
    Task = "Ensure 'VBA Macro Notification Settings: Block certificates from trusted publishers that are only installed in the current user certificate store' is set to 'Enabled' (16.0, powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "vbarequirelmtrustedpublisher" `
                | Select-Object -ExpandProperty "vbarequirelmtrustedpublisher"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.15"
    Task = "Ensure 'VBA Macro Notification Settings: Require Extended Key Usage (EKU) for certificates from trusted publishers' is set to 'Disabled' (16.0, powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "vbarequiredigsigwithcodesigningeku" `
                | Select-Object -ExpandProperty "vbarequiredigsigwithcodesigningeku"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.16"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.17"
    Task = "Ensure 'VBA Macro Notification Settings: Require macros to be signed by a trusted publisher' is set to 'Enabled' (16.0, publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "vbadigsigtrustedpublishers" `
                | Select-Object -ExpandProperty "vbadigsigtrustedpublishers"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.18"
    Task = "Ensure 'VBA Macro Notification Settings: Block certificates from trusted publishers that are only installed in the current user certificate store' is set to 'Disabled' (16.0, publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "vbarequirelmtrustedpublisher" `
                | Select-Object -ExpandProperty "vbarequirelmtrustedpublisher"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.19"
    Task = "Ensure 'VBA Macro Notification Settings: Require Extended Key Usage (EKU) for certificates from trusted publishers' is set to 'Disabled' (16.0, publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "vbarequiredigsigwithcodesigningeku" `
                | Select-Object -ExpandProperty "vbarequiredigsigwithcodesigningeku"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.20"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (16.0, visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.21"
    Task = "Ensure 'VBA Macro Notification Settings: Require macros to be signed by a trusted publisher' is set to 'Enabled' (16.0, visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "vbadigsigtrustedpublishers" `
                | Select-Object -ExpandProperty "vbadigsigtrustedpublishers"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.22"
    Task = "Ensure 'VBA Macro Notification Settings: Block certificates from trusted publishers that are only installed in the current user certificate store' is set to 'Disabled' (16.0, visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "vbarequirelmtrustedpublisher" `
                | Select-Object -ExpandProperty "vbarequirelmtrustedpublisher"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.23"
    Task = "Ensure 'VBA Macro Notification Settings: Require Extended Key Usage (EKU) for certificates from trusted publishers' is set to 'Disabled' (16.0, visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "vbarequiredigsigwithcodesigningeku" `
                | Select-Object -ExpandProperty "vbarequiredigsigwithcodesigningeku"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.24"
    Task = "Ensure 'VBA Macro Notification Settings' is set to 'Disable all except digitally signed macros' (16.0, word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "vbawarnings" `
                | Select-Object -ExpandProperty "vbawarnings"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "5.2.25"
    Task = "Ensure 'VBA Macro Notification Settings: Require macros to be signed by a trusted publisher' is set to 'Enabled' (16.0, word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "vbadigsigtrustedpublishers" `
                | Select-Object -ExpandProperty "vbadigsigtrustedpublishers"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "5.2.26"
    Task = "Ensure 'VBA Macro Notification Settings: Block certificates from trusted publishers that are only installed in the current user certificate store' is set to 'Disabled' (16.0, word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "vbarequirelmtrustedpublisher" `
                | Select-Object -ExpandProperty "vbarequirelmtrustedpublisher"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "5.2.27"
    Task = "Ensure 'VBA Macro Notification Settings: Require Extended Key Usage (EKU) for certificates from trusted publishers' is set to 'Disabled' (16.0, word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "vbarequiredigsigwithcodesigningeku" `
                | Select-Object -ExpandProperty "vbarequiredigsigwithcodesigningeku"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.1"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins and block them' is set to 'Enabled' (16.0, access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.2"
    Task = "Ensure 'Block macros from running in Office files from the Internet' is set to 'Enabled' (16.0, access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security" `
                    -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.3"
    Task = "Ensure 'Allow Trusted Locations on the network' is set to 'Disabled' (access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\access\security\trusted locations" `
                    -Name "allownetworklocations" `
                | Select-Object -ExpandProperty "allownetworklocations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.4"
    Task = "Ensure 'Control how Office handles form-based sign-in prompts' is set to 'Block all prompts'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common" `
                    -Name "fbabehavior" `
                | Select-Object -ExpandProperty "fbabehavior"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.5"
    Task = "Ensure 'Control how Office handles form-based sign-in prompts' is set to ''."
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common" `
                    -Name "fbaenabledhosts" `
                | Select-Object -ExpandProperty "fbaenabledhosts"

                if ($regValue -ne "") {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: "
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
}
[AuditTest] @{
    Id   = "6.2.6"
    Task = "Ensure 'Specify encryption compatibility' is set to 'Use next generation format'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\drm" `
                    -Name "compatibleencryption" `
                | Select-Object -ExpandProperty "compatibleencryption"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.7"
    Task = "Ensure 'show Basic authentication sign-in prompts' is set to 'Blocked'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\identity" `
                    -Name "basicauthproxybehavior" `
                | Select-Object -ExpandProperty "basicauthproxybehavior"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.8"
    Task = "Ensure 'Disable the Office client from polling the SharePoint Server for published links' is set to 'Enabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\portal" `
                    -Name "linkpublishingdisabled" `
                | Select-Object -ExpandProperty "linkpublishingdisabled"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.9"
    Task = "Ensure 'Protect document metadata for rights managed Office Open XML Files' is set to 'Enabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\security" `
                    -Name "drmencryptproperty" `
                | Select-Object -ExpandProperty "drmencryptproperty"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.10"
    Task = "Ensure 'Encryption type for password protected Office Open XML files' is set to 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\security" `
                    -Name "openxmlencryption" `
                | Select-Object -ExpandProperty "openxmlencryption"

                if ($regValue -ne "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256") {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256"
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
}
[AuditTest] @{
    Id   = "6.2.11"
    Task = "Ensure 'Encryption type for password protected Office 97-2003 files' is set to 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\security" `
                    -Name "defaultencryption12" `
                | Select-Object -ExpandProperty "defaultencryption12"

                if ($regValue -ne "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256") {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256"
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
}
[AuditTest] @{
    Id   = "6.2.12"
    Task = "Ensure 'Macro Runtime Scan Scope' is set to 'Enable for all documents'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\security" `
                    -Name "macroruntimescanscope" `
                | Select-Object -ExpandProperty "macroruntimescanscope"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "6.2.13"
    Task = "Ensure 'Allow mix of policy and user locations' is set to 'Disabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\security\trusted locations" `
                    -Name "allow user locations" `
                | Select-Object -ExpandProperty "allow user locations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.14"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Access)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Access"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\access" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.15"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\excel" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.16"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in InfoPath)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\infopath" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.17"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\outlook" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.18"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in PowerPoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\powerpoint" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.19"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Project)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\project" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.20"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\publisher" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.21"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\visio" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.22"
    Task = "Ensure 'Disable UI Extending from Documents and Templates' is set to 'Enabled' (Disallow in Word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\toolbars\word" `
                    -Name "noextensibilitycustomizationfromdocument" `
                | Select-Object -ExpandProperty "noextensibilitycustomizationfromdocument"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.23"
    Task = "Ensure 'Disable All Trust Bar Notifications For Security Issues' is set to 'Disabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\common\trustcenter" `
                    -Name "trustbar" `
                | Select-Object -ExpandProperty "trustbar"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.24"
    Task = "Ensure 'Load pictures from Web pages not created in Excel' is set to 'Disabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\internet" `
                    -Name "donotloadpictures" `
                | Select-Object -ExpandProperty "donotloadpictures"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.25"
    Task = "Ensure 'Do not show data extraction options when opening corrupt workbooks' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\options" `
                    -Name "extractdatadisableui" `
                | Select-Object -ExpandProperty "extractdatadisableui"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.26"
    Task = "Ensure 'Disable AutoRepublish' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\options" `
                    -Name "disableautorepublish" `
                | Select-Object -ExpandProperty "disableautorepublish"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.27"
    Task = "Ensure 'Do not show AutoRepublish warning alert' is set to 'Disabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\options" `
                    -Name "disableautorepublishwarning" `
                | Select-Object -ExpandProperty "disableautorepublishwarning"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.28"
    Task = "Ensure 'Ask to update automatic links' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\options\binaryoptions" `
                    -Name "fupdateext_78_1" `
                | Select-Object -ExpandProperty "fupdateext_78_1"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.29"
    Task = "Ensure 'Force file extension to match file type' is set to 'Always match file type' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "extensionhardening" `
                | Select-Object -ExpandProperty "extensionhardening"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "6.2.30"
    Task = "Ensure 'Scan encrypted macros in Excel Open XML workbooks' is set to 'Scan encrypted macros (excel)'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "excelbypassencryptedmacroscan" `
                | Select-Object -ExpandProperty "excelbypassencryptedmacroscan"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.31"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins and block them' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.32"
    Task = "Ensure 'WEBSERVICE Function Notification Settings' is set to 'Disable all with notification' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "webservicefunctionwarnings" `
                | Select-Object -ExpandProperty "webservicefunctionwarnings"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.33"
    Task = "Ensure 'Block macros from running in Office files from the Internet' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.34"
    Task = "Ensure 'Require that application add-ins are signed by Trusted Publisher' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "requireaddinsig" `
                | Select-Object -ExpandProperty "requireaddinsig"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.35"
    Task = "Ensure 'Block untrusted XLL add-ins' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security" `
                    -Name "blockxllfrominternet" `
                | Select-Object -ExpandProperty "blockxllfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.36"
    Task = "Ensure 'Always prevent untrusted Microsoft Query files from opening' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\external content" `
                    -Name "enableblockunsecurequeryfiles" `
                | Select-Object -ExpandProperty "enableblockunsecurequeryfiles"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.37"
    Task = "Ensure 'Turn off file validation' is set to 'Disabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\filevalidation" `
                    -Name "enableonload" `
                | Select-Object -ExpandProperty "enableonload"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.38"
    Task = "Ensure 'Set document behavior if file validation fails' is set to 'Do not allow edit' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\filevalidation" `
                    -Name "disableeditfrompv" `
                | Select-Object -ExpandProperty "disableeditfrompv"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.39"
    Task = "Ensure 'Set document behavior if file validation fails' is set to 'Open in Protected View' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\filevalidation" `
                    -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.40"
    Task = "Ensure 'Turn off Protected View for attachments opened from Outlook' is set to 'Disabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\protectedview" `
                    -Name "disableattachmentsinpv" `
                | Select-Object -ExpandProperty "disableattachmentsinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.41"
    Task = "Ensure 'Do not open files from the Internet zone in Protected View' is set to 'Disabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\protectedview" `
                    -Name "disableinternetfilesinpv" `
                | Select-Object -ExpandProperty "disableinternetfilesinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.42"
    Task = "Ensure 'Do not open files in unsafe locations in Protected View' is set to 'Disabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\protectedview" `
                    -Name "disableunsafelocationsinpv" `
                | Select-Object -ExpandProperty "disableunsafelocationsinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.43"
    Task = "Ensure 'Always open untrusted database files in Protected View' is set to 'Enabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\protectedview" `
                    -Name "enabledatabasefileprotectedview" `
                | Select-Object -ExpandProperty "enabledatabasefileprotectedview"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.44"
    Task = "Ensure 'Allow Trusted Locations on the network' is set to 'Disabled' (excel)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Excel"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security\trusted locations" `
                    -Name "allownetworklocations" `
                | Select-Object -ExpandProperty "allownetworklocations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.45"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins and block them' is set to 'Enabled' (ms project)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\ms project\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.46"
    Task = "Ensure 'Require that application add-ins are signed by Trusted Publisher' is set to 'Enabled' (ms project)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\ms project\security" `
                    -Name "requireaddinsig" `
                | Select-Object -ExpandProperty "requireaddinsig"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.47"
    Task = "Ensure 'Allow Trusted Locations on the network' is set to 'Disabled' (ms project)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Project"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\ms project\security\trusted locations" `
                    -Name "allownetworklocations" `
                | Select-Object -ExpandProperty "allownetworklocations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.48"
    Task = "Ensure 'Prevent users from customizing attachment security settings' is set to 'Enabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook" `
                    -Name "disallowattachmentcustomization" `
                | Select-Object -ExpandProperty "disallowattachmentcustomization"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.49"
    Task = "Ensure 'Use Unicode format when dragging e-mail message to file system' is set to 'Disabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\options\general" `
                    -Name "msgformat" `
                | Select-Object -ExpandProperty "msgformat"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.50"
    Task = "Ensure 'Allow hyperlinks in suspected phishing e-mail messages' is set to 'Disabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\options\mail" `
                    -Name "junkmailenablelinks" `
                | Select-Object -ExpandProperty "junkmailenablelinks"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.51"
    Task = "Ensure 'Include Internet in Safe Zones for Automatic Picture Download' is set to 'Disabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\options\mail" `
                    -Name "internet" `
                | Select-Object -ExpandProperty "internet"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.52"
    Task = "Ensure 'Enable RPC encryption' is set to 'Enabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\rpc" `
                    -Name "enablerpcencryption" `
                | Select-Object -ExpandProperty "enablerpcencryption"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.53"
    Task = "Ensure 'Configure Outlook object model prompt When accessing the Formula property of a UserProperty object' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoomformulaaccess" `
                | Select-Object -ExpandProperty "promptoomformulaaccess"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.54"
    Task = "Ensure 'Configure Outlook object model prompt when executing Save As' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoomsaveas" `
                | Select-Object -ExpandProperty "promptoomsaveas"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.55"
    Task = "Ensure 'Configure Outlook object model prompt when accessing an address book' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoomaddressbookaccess" `
                | Select-Object -ExpandProperty "promptoomaddressbookaccess"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.56"
    Task = "Ensure 'Configure Outlook object model prompt when reading address information' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoomaddressinformationaccess" `
                | Select-Object -ExpandProperty "promptoomaddressinformationaccess"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.57"
    Task = "Ensure 'Configure Outlook object model prompt when responding to meeting and task requests' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoommeetingtaskrequestresponse" `
                | Select-Object -ExpandProperty "promptoommeetingtaskrequestresponse"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.58"
    Task = "Ensure 'Configure Outlook object model prompt when sending mail' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoomsend" `
                | Select-Object -ExpandProperty "promptoomsend"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.59"
    Task = "Ensure 'Minimum encryption settings' is set to '168'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "minenckey" `
                | Select-Object -ExpandProperty "minenckey"

                if ($regValue -ne 168) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 168"
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
}
[AuditTest] @{
    Id   = "6.2.60"
    Task = "Ensure 'Signature Warning' is set to 'Always warn about invalid signatures' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "warnaboutinvalid" `
                | Select-Object -ExpandProperty "warnaboutinvalid"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.61"
    Task = "Ensure 'Display Level 1 attachments' is set to 'Disabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "showlevel1attach" `
                | Select-Object -ExpandProperty "showlevel1attach"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.62"
    Task = "Ensure 'Set Outlook object model custom actions execution prompt' is set to 'Automatically Deny' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "promptoomcustomaction" `
                | Select-Object -ExpandProperty "promptoomcustomaction"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.63"
    Task = "Ensure 'Allow scripts in one-off Outlook forms' is set to 'Disabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "enableoneoffformscripts" `
                | Select-Object -ExpandProperty "enableoneoffformscripts"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.64"
    Task = "Ensure 'Allow Active X One Off Forms' is set to 'Load only Outlook Controls' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "allowactivexoneoffforms" `
                | Select-Object -ExpandProperty "allowactivexoneoffforms"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.65"
    Task = "Ensure 'Retrieving CRLs (Certificate Revocation Lists)' is set to 'When online always retreive the CRL' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "usecrlchasing" `
                | Select-Object -ExpandProperty "usecrlchasing"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.66"
    Task = "Ensure 'Do not allow Outlook object model scripts to run for public folders' is set to 'Enabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "publicfolderscript" `
                | Select-Object -ExpandProperty "publicfolderscript"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.67"
    Task = "Ensure 'Outlook Security Mode' is set to 'Use Outlook Security Group Policy' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "adminsecuritymode" `
                | Select-Object -ExpandProperty "adminsecuritymode"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "6.2.68"
    Task = "Ensure 'Allow users to demote attachments to Level 2' is set to 'Disabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "allowuserstolowerattachments" `
                | Select-Object -ExpandProperty "allowuserstolowerattachments"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.69"
    Task = "Ensure 'Do not allow Outlook object model scripts to run for shared folders' is set to 'Enabled' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "sharedfolderscript" `
                | Select-Object -ExpandProperty "sharedfolderscript"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.70"
    Task = "Ensure 'Authentication with Exchange Server' is set to 'Kerberos Password Authentication' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "authenticationservice" `
                | Select-Object -ExpandProperty "authenticationservice"

                if ($regValue -ne 16) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 16"
                        Status  = "False"
                    }
                }
            }
            catch [System.Management.Automation.PSArgumentException] {
                returnS @{
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
}
[AuditTest] @{
    Id   = "6.2.71"
    Task = "Ensure 'Security setting for macros' is set to 'Warn for signed, disable unsigned' (outlook)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Outlook"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "level" `
                | Select-Object -ExpandProperty "level"

                if ($regValue -ne 3) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:3"
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
}
[AuditTest] @{
    Id   = "6.2.72"
    Task = "Ensure 'Remove file extensions blocked as Level 1' is set to '[Equaling `";`"]'."
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "fileextensionsremovelevel1" `
                | Select-Object -ExpandProperty "fileextensionsremovelevel1"

                if ($regValue -ne ";") {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: ;"
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
}
[AuditTest] @{
    Id   = "6.2.73"
    Task = "Ensure 'Remove file extensions blocked as Level 2' is set to '[Equaling `";`"]'."
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\outlook\security" `
                    -Name "fileextensionsremovelevel2" `
                | Select-Object -ExpandProperty "fileextensionsremovelevel2"

                if ($regValue -ne ";") {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: ;"
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
}
[AuditTest] @{
    Id   = "6.2.74"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins and block them' is set to 'Enabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.75"
    Task = "Ensure 'Scan encrypted macros in PowerPoint Open XML presentations' is set to 'Scan encrypted macros (powerpoint)'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "powerpointbypassencryptedmacroscan" `
                | Select-Object -ExpandProperty "powerpointbypassencryptedmacroscan"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.76"
    Task = "Ensure 'Run Programs' is set to 'disable (don't run any programs) (powerpoint)'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "runprograms" `
                | Select-Object -ExpandProperty "runprograms"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.77"
    Task = "Ensure 'Block macros from running in Office files from the Internet' is set to 'Enabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.78"
    Task = "Ensure 'Require that application add-ins are signed by Trusted Publisher' is set to 'Enabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security" `
                    -Name "requireaddinsig" `
                | Select-Object -ExpandProperty "requireaddinsig"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.79"
    Task = "Ensure 'Turn off file validation' is set to 'Disabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation" `
                    -Name "enableonload" `
                | Select-Object -ExpandProperty "enableonload"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.80"
    Task = "Ensure 'Set document behavior if file validation fails' is set to 'Do not allow edit' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation" `
                    -Name "disableeditfrompv" `
                | Select-Object -ExpandProperty "disableeditfrompv"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.81"
    Task = "Ensure 'Set document behavior if file validation fails' is set to 'Open in Protected View' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation" `
                    -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.82"
    Task = "Ensure 'Do not open files from the Internet zone in Protected View' is set to 'Disabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" `
                    -Name "disableinternetfilesinpv" `
                | Select-Object -ExpandProperty "disableinternetfilesinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.83"
    Task = "Ensure 'Do not open files in unsafe locations in Protected View' is set to 'Disabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" `
                    -Name "disableunsafelocationsinpv" `
                | Select-Object -ExpandProperty "disableunsafelocationsinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.84"
    Task = "Ensure 'Turn off Protected View for attachments opened from Outlook' is set to 'Disabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" `
                    -Name "disableattachmentsinpv" `
                | Select-Object -ExpandProperty "disableattachmentsinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.85"
    Task = "Ensure 'Allow Trusted Locations on the network' is set to 'Disabled' (powerpoint)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["PowerPoint"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations" `
                    -Name "allownetworklocations" `
                | Select-Object -ExpandProperty "allownetworklocations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.86"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins' is set to 'Enabled' (publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.87"
    Task = "Ensure 'Require that application add-ins are signed by Trusted Publisher' is set to 'Enabled' (publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "requireaddinsig" `
                | Select-Object -ExpandProperty "requireaddinsig"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.88"
    Task = "Ensure 'Block macros from running in Office files from the Internet' is set to 'Enabled' (publisher)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Publisher"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\publisher\security" `
                    -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.89"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins and block them' is set to 'Enabled' (visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.90"
    Task = "Ensure 'Block macros from running in Office files from the Internet' is set to 'Enabled' (visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.91"
    Task = "Ensure 'Require that application add-ins are signed by Trusted Publisher' is set to 'Enabled' (Visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security" `
                    -Name "requireaddinsig" `
                | Select-Object -ExpandProperty "requireaddinsig"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.92"
    Task = "Ensure 'Allow Trusted Locations on the network' is set to 'Disabled' (visio)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Visio"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\visio\security\trusted locations" `
                    -Name "allownetworklocations" `
                | Select-Object -ExpandProperty "allownetworklocations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.93"
    Task = "Ensure 'Disable Trust Bar Notification for unsigned application add-ins and block them' is set to 'Enabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "notbpromptunsignedaddin" `
                | Select-Object -ExpandProperty "notbpromptunsignedaddin"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.94"
    Task = "Ensure 'Scan encrypted macros in Word Open XML documents' is set to 'Scan encrypted macros (word)'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "wordbypassencryptedmacroscan" `
                | Select-Object -ExpandProperty "wordbypassencryptedmacroscan"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.95"
    Task = "Ensure 'Block macros from running in Office files from the Internet' is set to 'Enabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "blockcontentexecutionfrominternet" `
                | Select-Object -ExpandProperty "blockcontentexecutionfrominternet"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.96"
    Task = "Ensure 'Require that application add-ins are signed by Trusted Publisher' is set to 'Enabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security" `
                    -Name "requireaddinsig" `
                | Select-Object -ExpandProperty "requireaddinsig"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.97"
    Task = "Ensure 'Set document behavior if file validation fails' is set to 'Open in Protected View' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\filevalidation" `
                    -Name "openinprotectedview" `
                | Select-Object -ExpandProperty "openinprotectedview"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.98"
    Task = "Ensure 'Set document behavior if file validation fails' is set to 'Unchecked: Do not allow edit' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\filevalidation" `
                    -Name "disableeditfrompv" `
                | Select-Object -ExpandProperty "disableeditfrompv"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.99"
    Task = "Ensure 'Turn off file validation' is set to 'Disabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\filevalidation" `
                    -Name "enableonload" `
                | Select-Object -ExpandProperty "enableonload"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.100"
    Task = "Ensure 'Turn off Protected View for attachments opened from Outlook' is set to 'Disabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\protectedview" `
                    -Name "disableattachmentsinpv" `
                | Select-Object -ExpandProperty "disableattachmentsinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.101"
    Task = "Ensure 'Do not open files from the Internet zone in Protected View' is set to 'Disabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\protectedview" `
                    -Name "disableinternetfilesinpv" `
                | Select-Object -ExpandProperty "disableinternetfilesinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.102"
    Task = "Ensure 'Do not open files in unsafe locations in Protected View' is set to 'Disabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\protectedview" `
                    -Name "disableunsafelocationsinpv" `
                | Select-Object -ExpandProperty "disableunsafelocationsinpv"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.103"
    Task = "Ensure 'Allow Trusted Locations on the network' is set to 'Disabled' (word)"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        elseif (-not $installedOfficeApps["Word"]) {
            return @{
                Message = "Application not installed, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security\trusted locations" `
                    -Name "allownetworklocations" `
                | Select-Object -ExpandProperty "allownetworklocations"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.104"
    Task = "Ensure 'Automation Security' is set to 'Use application macro security level'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\common\security" `
                    -Name "automationsecurity" `
                | Select-Object -ExpandProperty "automationsecurity"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "6.2.105"
    Task = "Ensure 'Publisher Automation Security Level' is set to 'By UI (prompted)'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\common\security" `
                    -Name "automationsecuritypublisher" `
                | Select-Object -ExpandProperty "automationsecuritypublisher"

                if ($regValue -ne 2) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:2"
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
}
[AuditTest] @{
    Id   = "6.2.106"
    Task = "Ensure 'ActiveX Control Initialization' is set to 'prompt user for UFI controls'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\common\security" `
                    -Name "uficontrols" `
                | Select-Object -ExpandProperty "uficontrols"

                if (($regValue -ne 6)) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:6"
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
}
[AuditTest] @{
    Id   = "6.2.107"
    Task = "Ensure 'Disable Smart Document's use of manifests' is set to 'Enabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\common\smart tag" `
                    -Name "neverloadmanifests" `
                | Select-Object -ExpandProperty "neverloadmanifests"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.108"
    Task = "Ensure 'Load Controls in Forms3' is set to 'Disabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\vba\security" `
                    -Name "loadcontrolsinforms" `
                | Select-Object -ExpandProperty "loadcontrolsinforms"

                if ($regValue -ne 1) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected: 1"
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
}
[AuditTest] @{
    Id   = "6.2.109"
    Task = "Ensure 'Allow VBA to load typelib references by path from untrusted intranet locations' is set to 'Disabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\vba\security" `
                    -Name "allowvbaintranetreferences" `
                | Select-Object -ExpandProperty "allowvbaintranetreferences"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
[AuditTest] @{
    Id   = "6.2.110"
    Task = "Ensure 'Disable additional security checks on VBA library references that may refer to unsafe locations on the local machine' is set to 'Disabled'"
    Test = {
        # new logic: 
        # - if no Office installed at all -> skip test 
        # - if Office installed but app not installed -> skip test
        # - else run test as normal

        if (-not $OfficeInstalled) {
            return @{
                Message = "No Office installation detected, skipping test."
                Status  = "None"
            }
        }
        else {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\vba\security" `
                    -Name "disablestrictvbarefssecurity" `
                | Select-Object -ExpandProperty "disablestrictvbarefssecurity"

                if ($regValue -ne 0) {
                    return @{
                        Message = "Registry value is '$regValue'. Expected:0"
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
}
