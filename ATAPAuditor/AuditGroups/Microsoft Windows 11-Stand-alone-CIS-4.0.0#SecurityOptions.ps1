[AuditTest] @{
    Id   = "2.3.1.1"
    Task = "(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["EnableGuestAccount"]

        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status  = "False"
            }
        }
        if ($setOption -ne 0) {
            return @{
                Message = "'EnableGuestAccount' currently set to: $setOption. Expected: 0"
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
    Id   = "2.3.1.3"
    Task = "(L1) Configure 'Accounts: Rename administrator account'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["NewAdministratorName"]

        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status  = "False"
            }
        }
        if ($setOption -notmatch "^(?=.{1,20}$)(?i)(?!.*\b(?:Administrator)\b).*$") {
            return @{
                Message = "'NewAdministratorName' currently set to: $setOption. Expected: ^(?=.{1,20}$)(?i)(?!.*\b(?:Administrator)\b).*$"
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
    Id   = "2.3.1.4"
    Task = "(L1) Configure 'Accounts: Rename guest account'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["NewGuestName"]

        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status  = "False"
            }
        }
        if ($setOption -notmatch "^(?=.{1,20}$)(?i)(?!.*\b(?:Guest|Gast)\b).*$") {
            return @{
                Message = "'NewGuestName' currently set to: $setOption. Expected: ^(?=.{1,20}$)(?i)(?!.*\b(?:Guest|Gast)\b).*$"
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
    Id   = "2.3.10.1"
    Task = "(L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["LSAAnonymousNameLookup"]

        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status  = "False"
            }
        }
        if ($setOption -ne 0) {
            return @{
                Message = "'LSAAnonymousNameLookup' currently set to: $setOption. Expected: 0"
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
    Id   = "2.3.11.6"
    Task = "(L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["ForceLogoffWhenHourExpire"]

        if ($null -eq $setOption) {
            return @{
                Message = "Currently not set."
                Status  = "False"
            }
        }
        if ($setOption -ne 1) {
            return @{
                Message = "'ForceLogoffWhenHourExpire' currently set to: $setOption. Expected: 1"
                Status  = "False"
            }
        }

        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
