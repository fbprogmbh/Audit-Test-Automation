[AuditTest] @{
    Id = "WN10-AC-000005"
    Task = "Windows 10 account lockout duration must be configured to 15 minutes or greater."
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
        
        if (($setPolicy -lt 15)) {
            return @{
                Message = "'LockoutDuration' currently set to: $setPolicy. Expected: x >= 15"
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
    Id = "WN10-AC-000010"
    Task = "The number of allowed bad logon attempts must be configured to 3 or less."
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
        
        if (($setPolicy -gt 3 -or $setPolicy -eq 0)) {
            return @{
                Message = "'LockoutBadCount' currently set to: $setPolicy. Expected: x <= 3 and x != 0"
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
    Id = "WN10-AC-000015"
    Task = "The period of time before the bad logon counter is reset must be configured to 15 minutes."
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
    Id = "WN10-AC-000020"
    Task = "The password history must be configured to 24 passwords remembered."
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
        
        if (($setPolicy -gt 24 -or $setPolicy -lt 0)) {
            return @{
                Message = "'PasswordHistorySize' currently set to: $setPolicy. Expected: x <= 24 and x >= 0"
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
    Id = "WN10-AC-000025"
    Task = "The maximum password age must be configured to 60 days or less."
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
        
        if (($setPolicy -gt 60)) {
            return @{
                Message = "'MaximumPasswordAge' currently set to: $setPolicy. Expected: x <= 60"
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
    Id = "WN10-AC-000030"
    Task = "The minimum password age must be configured to at least 1 day."
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
        
        if (($setPolicy -lt 1)) {
            return @{
                Message = "'MinimumPasswordAge' currently set to: $setPolicy. Expected: x >= 1"
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
    Id = "WN10-AC-000035"
    Task = "Passwords must, at a minimum, be 14 characters."
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
    Id = "WN10-AC-000040"
    Task = "The built-in Microsoft password complexity filter must be enabled."
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
    Id = "WN10-AC-000045"
    Task = "Reversible password encryption must be disabled."
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
