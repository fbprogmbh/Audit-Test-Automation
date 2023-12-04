[AuditTest] @{
    Id = "2.3.1.2"
    Task = "(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)"
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
    Id = "2.3.1.4"
    Task = "(L1) Configure 'Accounts: Rename administrator account'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["NewAdministratorName"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -notmatch "^(?!.*\bAdministrator\b).*$") {
            return @{
                Message = "'NewAdministratorName' currently set to: $setOption."
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
    Id = "2.3.1.5"
    Task = "(L1) Configure 'Accounts: Rename guest account'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["NewGuestName"]
        
        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status = "False"
            }
        }
        if ($setOption -notmatch "^(?i)(?!.*\b(?:Guest|Gast)\b).*$") {
            return @{
                Message = "'NewGuestName' currently set to: $setOption."
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
    Id = "2.3.11.6"
    Task = "(L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
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
