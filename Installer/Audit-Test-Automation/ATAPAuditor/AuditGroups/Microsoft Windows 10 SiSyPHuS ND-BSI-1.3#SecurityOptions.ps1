﻿[AuditTest] @{
    Id = "235"
    Task = "(ND, NE) Configure 'Accounts: Rename administrator account'."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityOption"
        $setOption = $securityOption['System Access']["NewAdministratorName"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if (($setOption -replace '"') -ne "OldAdmin") {
            return @{
                Message = "'NewAdministratorName' currently set to: $setOption. Expected: OldAdmin"
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
    Id = "236"
    Task = "(ND, NE) Ensure 'Accounts: Administrator account status' is set to 'Disabled'."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityOption"
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
    Id = "237"
    Task = "(ND, NE) Ensure 'Accounts: Guest account status' is set to 'Disabled'. "
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityOption"
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
    Id = "238"
    Task = "(ND, NE) Configure 'Accounts: Rename guest account'."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityOption"
        $setOption = $securityOption['System Access']["NewGuestName"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if (($setOption -replace '"') -ne "OldGuest") {
            return @{
                Message = "'NewGuestName' currently set to: $setOption. Expected: OldGuest"
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
    Id = "249"
    Task = "(ND) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'."
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityOption"
        $setOption = $securityOption['System Access']["ForceLogoffWhenHourExpire"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -ne 1) {
            return @{
                Message = "'ForceLogoffWhenHourExpire' currently set to: $setOption. Expected: 1"
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
