[AuditTest] @{
    Id = "SecurityOption-142"
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
