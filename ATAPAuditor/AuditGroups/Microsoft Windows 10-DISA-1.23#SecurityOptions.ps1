[AuditTest] @{
    Id = "V-63601"
    Task = "The built-in administrator account must be disabled."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["EnableAdminAccount"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -ne 0) {
            return @{
                Message = "'EnableAdminAccount' currently set to: $setOption. Expected: 0"
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
    Id = "V-63611"
    Task = "The built-in guest account must be disabled."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["EnableGuestAccount"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -ne 0) {
            return @{
                Message = "'EnableGuestAccount' currently set to: $setOption. Expected: 0"
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
    Id = "V-63619"
    Task = "The built-in administrator account must be renamed."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["NewAdministratorName"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -notmatch "^(?!(Administrator|`"Administrator`")).*$") {
            return @{
                Message = "'NewAdministratorName' currently set to: $setOption. Expected: ^(?!(Administrator|`"Administrator`")).*$"
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
    Id = "V-63625"
    Task = "The built-in guest account must be renamed."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["NewGuestName"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -notmatch "^(?!(Guest|`"Guest`"|Gast|`"Gast`")).*$") {
            return @{
                Message = "'NewGuestName' currently set to: $setOption. Expected: ^(?!(Guest|`"Guest`"|Gast|`"Gast`")).*$"
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
    Id = "V-63739"
    Task = "Anonymous SID/Name translation must not be allowed."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["LSAAnonymousNameLookup"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -ne 0) {
            return @{
                Message = "'LSAAnonymousNameLookup' currently set to: $setOption. Expected: 0"
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
