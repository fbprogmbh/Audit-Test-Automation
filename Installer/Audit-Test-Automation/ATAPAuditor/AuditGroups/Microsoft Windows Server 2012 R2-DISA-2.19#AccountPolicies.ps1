[AuditTest] @{
    Id = "V-1097"
    Task = "The number of allowed bad logon attempts must meet minimum requirements."
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
    Id = "V-1098"
    Task = "The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 2012."
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
    Id = "V-1099"
    Task = "Windows 2012 account lockout duration must be configured to 15 minutes or greater."
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
    Id = "V-1104"
    Task = "The maximum password age must meet requirements."
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
    Id = "V-1105"
    Task = "The minimum password age must meet requirements."
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
    Id = "V-1107"
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
    Id = "V-1150"
    Task = "The built-in Windows password complexity policy must be enabled."
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
    Id = "V-2372"
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
[AuditTest] @{
    Id = "V-6836"
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
