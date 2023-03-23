[AuditTest] @{
    Id = "V-254445"
    Task = "Windows Server 2022 must have the built-in guest account disabled."
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
    Id = "V-254447"
    Task = "Windows Server 2022 built-in administrator account must be renamed."
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
    Id = "V-254448"
    Task = "Windows Server 2022 built-in guest account must be renamed."
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
    Id = "V-254465"
    Task = "Windows Server 2022 must not allow anonymous SID/Name translation."
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
