[AuditTest] @{
    Id = "WN10-00-000100"
    Task = "Internet Information System (IIS) or its subcomponents must not be installed on a workstation."
    Test = {
        $installState = (Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer").State
        
        if ($installState -ne "Disabled") {
            return @{
                Status = "False"
                Message = "The feature is not disabled."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN10-00-000110"
    Task = "Simple TCP/IP Services must not be installed on the system."
    Test = {
        $installState = (Get-WindowsOptionalFeature -Online -FeatureName "SimpleTCP").State
        
        if ($installState -ne "Disabled") {
            return @{
                Status = "False"
                Message = "The feature is not disabled."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN10-00-000115"
    Task = "The Telnet Client must not be installed on the system."
    Test = {
        $installState = (Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient").State
        
        if ($installState -ne "Disabled") {
            return @{
                Status = "False"
                Message = "The feature is not disabled."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN10-00-000120"
    Task = "The TFTP Client must not be installed on the system."
    Test = {
        $installState = (Get-WindowsOptionalFeature -Online -FeatureName "TFTP").State
        
        if ($installState -ne "Disabled") {
            return @{
                Status = "False"
                Message = "The feature is not disabled."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
