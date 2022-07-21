[AuditTest] @{
    Id = "V-73309"
    Task = "Windows 2016 account lockout duration must be configured to 15 minutes or greater."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["LockoutDuration"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -lt 15) -and ($setPolicy -ne 0)) {
            return @{
                Message = "'LockoutDuration' currently set to: $setPolicy. Expected: x >= 15 or x == 0"
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
    Id = "V-73311"
    Task = "Windows Server 2016 must have the number of allowed bad logon attempts configured to three or less."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["LockoutBadCount"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -lt 3 -or $setPolicy -eq 0)) {
            return @{
                Message = "'LockoutBadCount' currently set to: $setPolicy. Expected: x >= 3 and x != 0"
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
    Id = "V-73313"
    Task = "Windows Server 2016 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["ResetLockoutCount"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -lt 15)) {
            return @{
                Message = "'ResetLockoutCount' currently set to: $setPolicy. Expected: x >= 15"
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
    Id = "V-73315"
    Task = "Windows Server 2016 password history must be configured to 24 passwords remembered."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["PasswordHistorySize"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -lt 24)) {
            return @{
                Message = "'PasswordHistorySize' currently set to: $setPolicy. Expected: x >= 24"
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
    Id = "V-73317"
    Task = "Windows Server 2016 maximum password age must be configured to 60 days or less."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["MaximumPasswordAge"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -gt 60 -or $setPolicy -eq 0)) {
            return @{
                Message = "'MaximumPasswordAge' currently set to: $setPolicy. Expected: x <= 60 and x != 0"
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
    Id = "V-73319"
    Task = "Windows Server 2016 minimum password age must be configured to at least one day."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["MinimumPasswordAge"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -eq 0)) {
            return @{
                Message = "'MinimumPasswordAge' currently set to: $setPolicy. Expected: x != 0"
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
    Id = "V-73321"
    Task = "Windows Server 2016 minimum password length must be configured to 14 characters."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["MinimumPasswordLength"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if (($setPolicy -lt 14)) {
            return @{
                Message = "'MinimumPasswordLength' currently set to: $setPolicy. Expected: x >= 14"
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
    Id = "V-73323"
    Task = "Windows Server 2016 must have the built-in Windows password complexity policy enabled."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["PasswordComplexity"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if ($setPolicy -ne 1) {
            return @{
                Message = "'PasswordComplexity' currently set to: $setPolicy. Expected: 1"
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
    Id = "V-73325"
    Task = "Windows Server 2016 reversible password encryption must be disabled."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $setPolicy = $securityPolicy['System Access']["ClearTextPassword"]
        
        if ($null -eq $setPolicy) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        $setPolicy = [long]$setPolicy
        
        if ($setPolicy -ne 0) {
            return @{
                Message = "'ClearTextPassword' currently set to: $setPolicy. Expected: 0"
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
