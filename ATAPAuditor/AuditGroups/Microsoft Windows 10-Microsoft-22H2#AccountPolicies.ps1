[AuditTest] @{
    Id   = "8.3.1"
    Task = "Ensure 'Minimum password length' is set to '14 characters'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["MinimumPasswordLength"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
                if ($setPolicy -ne 14) {
                    return @{
                        Message = "'MinimumPasswordLength' currently set to: $setPolicy. Compliant value: 14"
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
    Id   = "8.3.2"
    Task = "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["PasswordComplexity"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
                if ($setPolicy -ne 1) {
                    return @{
                        Message = "'PasswordComplexity' currently set to: $setPolicy. Compliant value: 1"
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
    Id   = "8.3.3"
    Task = "Ensure 'Enforce password history' is set to '24' password(s)"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["PasswordHistorySize"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
                if ($setPolicy -ne 24) {
                    return @{
                        Message = "'PasswordHistorySize' currently set to: $setPolicy. Compliant value: 24"
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
    Id   = "8.3.4"
    Task = "Ensure 'Account lockout threshold' is set to '10' invalid logon attempt(s)"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["LockoutBadCount"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
        if (($setPolicy -gt 10 -or $setPolicy -le 0)) {
                    return @{
                        Message = "'LockoutBadCount' currently set to: $setPolicy. Compliant values between 1 and 10"
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
    Id   = "8.3.5"
    Task = "Ensure 'Reset account lockout counter after' is set to '10 minutes'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["ResetLockoutCount"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
                if ($setPolicy -ne 10) {
                    return @{
                        Message = "'ResetLockoutCount' currently set to: $setPolicy. Compliant value: 10"
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
    Id   = "8.3.6"
    Task = "Ensure 'Account lockout duration' is set to '10 minutes'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["LockoutDuration"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
                if ($setPolicy -ne 10) {
                    return @{
                        Message = "'LockoutDuration' currently set to: $setPolicy. Compliant value: 10"
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
    Id   = "8.3.8"
    Task = "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
                $setPolicy = $securityPolicy['System Access']["ClearTextPassword"]
        
                if ($null -eq $setPolicy) {
                    return @{
                        Message = "Currently not set."
                        Status  = "False"
                    }
                }
                $setPolicy = [long]$setPolicy
        
                if ($setPolicy -ne 0) {
                    return @{
                        Message = "'ClearTextPassword' currently set to: $setPolicy. Compliant value: 0"
                        Status  = "False"
                    }
                }
        
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
    }
}
