[AuditTest] @{
    Id = "WN19-00-000320"
    Task = "Windows Server 2019 must not have the Fax Server role installed."
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
    Id = "WN19-00-000330"
    Task = "Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization."
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
    Id = "WN19-00-000340"
    Task = "Windows Server 2019 must not have the Peer Name Resolution Protocol installed."
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
    Id = "WN19-00-000350"
    Task = "Windows Server 2019 must not have Simple TCP/IP Services installed."
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
    Id = "WN19-00-000360"
    Task = "Windows Server 2019 must not have the Telnet Client installed."
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
    Id = "WN19-00-000370"
    Task = "Windows Server 2019 must not have the TFTP Client installed."
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
    Id = "WN19-00-000380"
    Task = "Windows Server 2019 must not the Server Message Block (SMB) v1 protocol installed."
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
    Id = "WN19-00-000410"
    Task = "Windows Server 2019 must not have Windows PowerShell 2.0 installed."
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
