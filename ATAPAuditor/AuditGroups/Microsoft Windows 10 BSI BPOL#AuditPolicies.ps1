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
    Id = "0008"
    Task = " Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0011"
    Task = " Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0012"
    Task = " Ensure 'Audit Security Group Management' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0013"
    Task = " Ensure 'Audit account management' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0014"
    Task = " Ensure 'Advanced security audit policy settings' is set to 'SuccessAndNotFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0015"
    Task = " Ensure 'Audit Process Creation' is set to 'SuccessAndNotFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0016"
    Task = " Ensure 'Audit Other Logon/Logoff Events' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0017"
    Task = " Ensure 'Audit Account Lockout' is set to 'SuccessAndNotFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0018"
    Task = " Ensure 'How to track users logon/logoff' is set to 'SuccessAndNotFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0019"
    Task = " Ensure 'Audit Policy: Logon-Logoff: Logon' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0020"
    Task = " Ensure 'Audit Policy: Logon-Logoff: Special Logon' is set to 'Enabled'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0021"
    Task = " Ensure 'Audit Policy: Object Access:Removable Storage' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0022"
    Task = " Ensure 'Audit Policy: Policy Change: Audit Policy Change' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0023"
    Task = " Ensure 'Audit Policy: Policy Change: Authentication Policy Change' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0025"
    Task = " Ensure 'Audit Policy: System: IPsecDriver' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0026"
    Task = " Ensure 'Audit Policy: System: OtherSystem Events' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0027"
    Task = " Ensure 'Audit Policy: System: Security State Change' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0028"
    Task = " Ensure 'Audit Policy: System: Security System Extension' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
    Id = "0029"
    Task = " Ensure 'Audit Policy: System: System Integrity' is set to 'SuccessAndFailure'"
    Test = {
        # Get the audit policy for the subcategory 
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory ""
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory ''"
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
