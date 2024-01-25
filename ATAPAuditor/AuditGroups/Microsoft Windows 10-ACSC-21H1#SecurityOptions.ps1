[AuditTest] @{
    Id = "High-032"
    Task = "Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
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
    Id = "Medium-069"
    Task = "Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
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
    Id = "Medium-208"
    Task = "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
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
