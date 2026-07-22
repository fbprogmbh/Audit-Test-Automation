[AuditTest] @{
    Id   = "3.3.1"
    Task = "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
    Test = {
        $securityOption = Get-AuditResource "WindowsSecurityPolicy"
        $setOption = $securityOption['System Access']["LSAAnonymousNameLookup"]
        
        if ($null -eq $setOption) {
            return @{
                Status  = "False"
                Message = "Currently not set."
            }
        }
        if ($setOption -ne 0) {
            return @{
                Message = "'LSAAnonymousNameLookup' currently set to: $setOption. Compliant value: 0"
                Status  = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
