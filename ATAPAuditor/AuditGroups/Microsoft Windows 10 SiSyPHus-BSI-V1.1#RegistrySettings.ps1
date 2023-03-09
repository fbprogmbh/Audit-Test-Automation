$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$avstatus = CheckForActiveAV
$windefrunning = CheckWindefRunning
if((Get-WmiObject -class Win32_OperatingSystem).Caption -eq "Microsoft Windows 10 Enterprise Evaluation" -or 
(Get-WmiObject -class Win32_OperatingSystem).Caption -eq "Microsoft Windows 10 Enterprise"){
    [AuditTest] @{
        Id = "3.1.1"
        Task = "Configuration of the lowest possible telemetry-level (Enterprise Windows 10)"
        Test = {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" `
                    -Name "AllowTelemetry" `
                    | Select-Object -ExpandProperty "AllowTelemetry"
            
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
}
else{
    [AuditTest] @{
        Id = "3.1.1"
        Task = "Configuration of the lowest possible telemetry-level (Non-Enterprise Windows 10)"
        Test = {
            try {
                $regValue = Get-ItemProperty -ErrorAction Stop `
                    -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" `
                    -Name "AllowTelemetry" `
                    | Select-Object -ExpandProperty "AllowTelemetry"
            
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
}
[AuditTest] @{
    Id = "3.1.2.1"
    Task = "Deactivation of the telemetry service and ETW-sessions - disable service DiagTrack"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" `
                -Name "Start" `
                | Select-Object -ExpandProperty "Start"
        
            if ($regValue -ne 4) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 4"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "3.1.2.2"
    Task = "Deactivation of the telemetry service and ETW-sessions - disable service Autologger-Diatrack-Listener"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" `
                -Name "Start" `
                | Select-Object -ExpandProperty "Start"
        
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
    Id = "3.1.3.1.1"
    Task = "Deactivation of telemetry according to Microsoft - Disable Windows Update Service"
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" `
                -Name "Start" `
                | Select-Object -ExpandProperty "Start"
        
            if ($regValue -ne 4) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 4"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "3.1.3.1.2"
    Task = "Deactivation of telemetry according to Microsoft - Cloud-Based-Protection: disable MAPS"
    Test = {
        try {
            if($avstatus){
                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status = "None"
                    }
                }         
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "SpynetReporting" `
                | Select-Object -ExpandProperty "SpynetReporting"
        
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
    Id = "3.1.3.1.3"
    Task = "Deactivation of telemetry according to Microsoft - Cloud-Based-Protection: never send sample files"
    Test = {
        try {
            if($avstatus){
                if ((-not $windefrunning)) {
                    return @{
                        Message = "This rule requires Windows Defender Antivirus to be enabled."
                        Status = "None"
                    }
                }         
            }
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" `
                -Name "SubmitSamplesConsent" `
                | Select-Object -ExpandProperty "SubmitSamplesConsent"
        
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
