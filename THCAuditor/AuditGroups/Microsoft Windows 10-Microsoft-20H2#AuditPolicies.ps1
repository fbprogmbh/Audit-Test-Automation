# Common
function Get-AuditPolicySubcategoryGUID {
	Param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
		[string] $Subcategory
    )

    $map = @{
        "Security State Change"                  = "{0CCE9210-69AE-11D9-BED3-505054503030}"
        "Security System Extension"              = "{0CCE9211-69AE-11D9-BED3-505054503030}"
        "System Integrity"                       = "{0CCE9212-69AE-11D9-BED3-505054503030}"
        "IPsec Driver"                           = "{0CCE9213-69AE-11D9-BED3-505054503030}"
        "Other System Events"                    = "{0CCE9214-69AE-11D9-BED3-505054503030}"
        "Logon"                                  = "{0CCE9215-69AE-11D9-BED3-505054503030}"
        "Logoff"                                 = "{0CCE9216-69AE-11D9-BED3-505054503030}"
        "Account Lockout"                        = "{0CCE9217-69AE-11D9-BED3-505054503030}"
        "IPsec Main Mode"                        = "{0CCE9218-69AE-11D9-BED3-505054503030}"
        "IPsec Quick Mode"                       = "{0CCE9219-69AE-11D9-BED3-505054503030}"
        "IPsec Extended Mode"                    = "{0CCE921A-69AE-11D9-BED3-505054503030}"
        "Special Logon"                          = "{0CCE921B-69AE-11D9-BED3-505054503030}"
        "Other Logon/Logoff Events"              = "{0CCE921C-69AE-11D9-BED3-505054503030}"
        "Network Policy Server"                  = "{0CCE9243-69AE-11D9-BED3-505054503030}"
        "User / Device Claims"                   = "{0CCE9247-69AE-11D9-BED3-505054503030}"
        "Group Membership"                       = "{0CCE9249-69AE-11D9-BED3-505054503030}"
        "File System"                            = "{0CCE921D-69AE-11D9-BED3-505054503030}"
        "Registry"                               = "{0CCE921E-69AE-11D9-BED3-505054503030}"
        "Kernel Object"                          = "{0CCE921F-69AE-11D9-BED3-505054503030}"
        "SAM"                                    = "{0CCE9220-69AE-11D9-BED3-505054503030}"
        "Certification Services"                 = "{0CCE9221-69AE-11D9-BED3-505054503030}"
        "Application Generated"                  = "{0CCE9222-69AE-11D9-BED3-505054503030}"
        "Handle Manipulation"                    = "{0CCE9223-69AE-11D9-BED3-505054503030}"
        "File Share"                             = "{0CCE9224-69AE-11D9-BED3-505054503030}"
        "Filtering Platform Packet Drop"         = "{0CCE9225-69AE-11D9-BED3-505054503030}"
        "Filtering Platform Connection"          = "{0CCE9226-69AE-11D9-BED3-505054503030}"
        "Other Object Access Events"             = "{0CCE9227-69AE-11D9-BED3-505054503030}"
        "Detailed File Share"                    = "{0CCE9244-69AE-11D9-BED3-505054503030}"
        "Removable Storage"                      = "{0CCE9245-69AE-11D9-BED3-505054503030}"
        "Central Policy Staging"                 = "{0CCE9246-69AE-11D9-BED3-505054503030}"
        "Sensitive Privilege Use"                = "{0CCE9228-69AE-11D9-BED3-505054503030}"
        "Non Sensitive Privilege Use"            = "{0CCE9229-69AE-11D9-BED3-505054503030}"
        "Other Privilege Use Events"             = "{0CCE922A-69AE-11D9-BED3-505054503030}"
        "Process Creation"                       = "{0CCE922B-69AE-11D9-BED3-505054503030}"
        "Process Termination"                    = "{0CCE922C-69AE-11D9-BED3-505054503030}"
        "DPAPI Activity"                         = "{0CCE922D-69AE-11D9-BED3-505054503030}"
        "RPC Events"                             = "{0CCE922E-69AE-11D9-BED3-505054503030}"
        "Plug and Play Events"                   = "{0CCE9248-69AE-11D9-BED3-505054503030}"
        "Token Right Adjusted Events"            = "{0CCE924A-69AE-11D9-BED3-505054503030}"
        "Audit Policy Change"                    = "{0CCE922F-69AE-11D9-BED3-505054503030}"
        "Authentication Policy Change"           = "{0CCE9230-69AE-11D9-BED3-505054503030}"
        "Authorization Policy Change"            = "{0CCE9231-69AE-11D9-BED3-505054503030}"
        "MPSSVC Rule-Level Policy Change"        = "{0CCE9232-69AE-11D9-BED3-505054503030}"
        "Filtering Platform Policy Change"       = "{0CCE9233-69AE-11D9-BED3-505054503030}"
        "Other Policy Change Events"             = "{0CCE9234-69AE-11D9-BED3-505054503030}"
        "User Account Management"                = "{0CCE9235-69AE-11D9-BED3-505054503030}"
        "Computer Account Management"            = "{0CCE9236-69AE-11D9-BED3-505054503030}"
        "Security Group Management"              = "{0CCE9237-69AE-11D9-BED3-505054503030}"
        "Distribution Group Management"          = "{0CCE9238-69AE-11D9-BED3-505054503030}"
        "Application Group Management"           = "{0CCE9239-69AE-11D9-BED3-505054503030}"
        "Other Account Management Events"        = "{0CCE923A-69AE-11D9-BED3-505054503030}"
        "Directory Service Access"               = "{0CCE923B-69AE-11D9-BED3-505054503030}"
        "Directory Service Changes"              = "{0CCE923C-69AE-11D9-BED3-505054503030}"
        "Directory Service Replication"          = "{0CCE923D-69AE-11D9-BED3-505054503030}"
        "Detailed Directory Service Replication" = "{0CCE923E-69AE-11D9-BED3-505054503030}"
        "Credential Validation"                  = "{0CCE923F-69AE-11D9-BED3-505054503030}"
        "Kerberos Service Ticket Operations"     = "{0CCE9240-69AE-11D9-BED3-505054503030}"
        "Other Account Logon Events"             = "{0CCE9241-69AE-11D9-BED3-505054503030}"
        "Kerberos Authentication Service"        = "{0CCE9242-69AE-11D9-BED3-505054503030}"
    }

    if ($map.ContainsKey($Subcategory)) {
        return $map[$Subcategory]
    }
    return ""
}

# Tests
[AuditTest] @{
    Id = "AuditPolicy-001"
    Task = "Ensure 'Credential Validation' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Credential Validation
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Credential Validation"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Credential Validation'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-002"
    Task = "Ensure 'Security Group Management' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Security Group Management
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Security Group Management"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Security Group Management'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-003"
    Task = "Ensure 'User Account Management' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory User Account Management
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "User Account Management"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'User Account Management'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-004"
    Task = "Ensure 'PNP Activity' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory PNP Activity
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "PNP Activity"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'PNP Activity'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-005"
    Task = "Ensure 'Process Creation' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Process Creation
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Process Creation"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Process Creation'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-006"
    Task = "Ensure 'Account Lockout' is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Account Lockout
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Account Lockout"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Account Lockout'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Failure" -and $setting -ne "Success and Failure" -And $setting -ne "Fehler" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-007"
    Task = "Ensure 'Group Membership' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Group Membership
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Group Membership"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Group Membership'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-008"
    Task = "Ensure 'Logon' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Logon
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Logon"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Logon'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-009"
    Task = "Ensure 'Other Logon/Logoff Events' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Other Logon/Logoff Events
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Other Logon/Logoff Events"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Other Logon/Logoff Events'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-010"
    Task = "Ensure 'Special Logon' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Special Logon
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Special Logon"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Special Logon'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-011"
    Task = "Ensure 'Detailed File Share' is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Detailed File Share
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Detailed File Share"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Detailed File Share'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Failure" -and $setting -ne "Success and Failure" -And $setting -ne "Fehler" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-012"
    Task = "Ensure 'File Share' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory File Share
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "File Share"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'File Share'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-013"
    Task = "Ensure 'Other Object Access Events' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Other Object Access Events
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Other Object Access Events"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Other Object Access Events'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-014"
    Task = "Ensure 'Removable Storage' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Removable Storage
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Removable Storage"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Removable Storage'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-015"
    Task = "Ensure 'Audit Policy Change' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Audit Policy Change
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Audit Policy Change"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Audit Policy Change'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-016"
    Task = "Ensure 'Authentication Policy Change' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Authentication Policy Change
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Authentication Policy Change"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Authentication Policy Change'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-017"
    Task = "Ensure 'MPSSVC Rule-Level Policy Change' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory MPSSVC Rule-Level Policy Change
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "MPSSVC Rule-Level Policy Change"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'MPSSVC Rule-Level Policy Change'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-018"
    Task = "Ensure 'Other Policy Change Events' is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Other Policy Change Events
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Other Policy Change Events"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Other Policy Change Events'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Failure" -and $setting -ne "Success and Failure" -And $setting -ne "Fehler" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-019"
    Task = "Ensure 'Sensitive Privilege Use' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Sensitive Privilege Use
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Sensitive Privilege Use"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Sensitive Privilege Use'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-020"
    Task = "Ensure 'Other System Events' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory Other System Events
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Other System Events"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Other System Events'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-021"
    Task = "Ensure 'Security State Change' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Security State Change
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Security State Change"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Security State Change'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-022"
    Task = "Ensure 'Security System Extension' is set to 'Success'."
    Test = {
        # Get the audit policy for the subcategory Security System Extension
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Security System Extension"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Security System Extension'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success" -and $setting -ne "Success and Failure" -And $setting -ne "Erfolg" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "AuditPolicy-023"
    Task = "Ensure 'System Integrity' is set to 'Success' and is set to 'Failure'."
    Test = {
        # Get the audit policy for the subcategory System Integrity
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "System Integrity"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'System Integrity'"
                Status = "None"
            }
        }
        
        $auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"
        
        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($LASTEXITCODE -ne 0) {
            $errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
            throw [System.ArgumentException] $errorString
            Write-Error -Message $errorString
        }
        
        if ($null -eq $auditPolicyString) {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting. Auditpol returned nothing."
            }
        }
        
        # Remove empty lines and headers
        $line = $auditPolicyString `
            | Where-Object { $_ } `
            | Select-Object -Skip 3
        
        if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure|Keine Überwachung|Erfolg und Fehler|Erfolg|Fehler)$") {
            return @{
                Status = "Warning"
                Message = "Couldn't get setting."
            }
        }
        
        $setting = $Matches[0]
        
        if ($setting -ne "Success and Failure" -And $setting -ne "Erfolg und Fehler") {
            return @{
                Status = "False"
                Message = "Set to: $setting"
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
