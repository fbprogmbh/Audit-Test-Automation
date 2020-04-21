[AuditTest] @{
    Id = "WN16-00-000350"
    Task = "The Fax Server role must not be installed."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "Fax").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000360"
    Task = "The Microsoft FTP service must not be installed unless required."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "Web-Ftp-Service").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000370"
    Task = "The Peer Name Resolution Protocol must not be installed."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "PNRP").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000380"
    Task = "Simple TCP/IP Services must not be installed."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "Simple-TCPIP").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000390"
    Task = "The Telnet Client must not be installed."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "Telnet-Client").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000400"
    Task = "The TFTP Client must not be installed."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "TFTP-Client").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000410"
    Task = "The Server Message Block (SMB) v1 protocol must be uninstalled."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "FS-SMB1").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN16-00-000420"
    Task = "Windows PowerShell 2.0 must not be installed."
    Test = {
        $installState = (Get-WindowsFeature | Where-Object Name -eq "PowerShell-v2").InstallState
        
        if ($installState -eq "Installed") {
            return @{
                Status = "False"
                Message = "The feature is installed."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
