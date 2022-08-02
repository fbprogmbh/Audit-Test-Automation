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
    Id = "V-92967 + V-92969"
    Task = "Windows Server 2019 must be configured to audit logon successes. Windows Server 2019 must be configured to audit logon failures."
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
    Id = "V-92979"
    Task = "Windows Server 2019 must be configured to audit Account Management - Security Group Management successes."
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
    Id = "V-92981 + V-92983"
    Task = "Windows Server 2019 must be configured to audit Account Management - User Account Management successes. Windows Server 2019 must be configured to audit Account Management - User Account Management failures."
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
    Id = "V-92985"
    Task = "Windows Server 2019 must be configured to audit Account Management - Computer Account Management successes."
    Test = {
        # Get the audit policy for the subcategory Computer Account Management
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Computer Account Management"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Computer Account Management'"
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
    Id = "V-92987 + V-92989"
    Task = "Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout successes. Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout failures."
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
    Id = "V-93089"
    Task = "Windows Server 2019 must be configured to audit Account Management - Other Account Management Events successes."
    Test = {
        # Get the audit policy for the subcategory Other Account Management Events
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Other Account Management Events"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Other Account Management Events'"
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
    Id = "V-93091"
    Task = "Windows Server 2019 must be configured to audit Detailed Tracking - Process Creation successes."
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
    Id = "V-93093 + V-93095"
    Task = "Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change successes. Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change failures."
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
    Id = "V-93097"
    Task = "Windows Server 2019 must be configured to audit Policy Change - Authentication Policy Change successes."
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
    Id = "V-93099"
    Task = "Windows Server 2019 must be configured to audit Policy Change - Authorization Policy Change successes."
    Test = {
        # Get the audit policy for the subcategory Authorization Policy Change
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Authorization Policy Change"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Authorization Policy Change'"
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
    Id = "V-93101 + V-93103"
    Task = "Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use successes. Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use failures."
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
    Id = "V-93105 + V-93107"
    Task = "Windows Server 2019 must be configured to audit System - IPsec Driver successes. Windows Server 2019 must be configured to audit System - IPsec Driver failures."
    Test = {
        # Get the audit policy for the subcategory IPsec Driver
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "IPsec Driver"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'IPsec Driver'"
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
    Id = "V-93109 + V-93111"
    Task = "Windows Server 2019 must be configured to audit System - Other System Events successes. Windows Server 2019 must be configured to audit System - Other System Events failures."
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
    Id = "V-93113"
    Task = "Windows Server 2019 must be configured to audit System - Security State Change successes."
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
    Id = "V-93115"
    Task = "Windows Server 2019 must be configured to audit System - Security System Extension successes."
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
    Id = "V-93117 + V-93119"
    Task = "Windows Server 2019 must be configured to audit System - System Integrity successes. Windows Server 2019 must be configured to audit System - System Integrity failures."
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
[AuditTest] @{
    Id = "V-93133 + V-93135"
    Task = "Windows Server 2019 must be configured to audit DS Access - Directory Service Access successes. Windows Server 2019 must be configured to audit DS Access - Directory Service Access failures."
    Test = {
        # Get the audit policy for the subcategory Directory Service Access
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Directory Service Access"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Directory Service Access'"
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
    Id = "V-93137 + V-93139"
    Task = "Windows Server 2019 must be configured to audit DS Access - Directory Service Changes successes. Windows Server 2019 must be configured to audit DS Access - Directory Service Changes failures."
    Test = {
        # Get the audit policy for the subcategory Directory Service Changes
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Directory Service Changes"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Directory Service Changes'"
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
    Id = "V-93153 + V-93155"
    Task = "Windows Server 2019 must be configured to audit Account Logon - Credential Validation successes. Windows Server 2019 must be configured to audit Account Logon - Credential Validation failures."
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
    Id = "V-93157"
    Task = "Windows Server 2019 must be configured to audit Detailed Tracking - Plug and Play Events successes."
    Test = {
        # Get the audit policy for the subcategory Plug and Play Events
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Plug and Play Events"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Plug and Play Events'"
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
    Id = "V-93159"
    Task = "Windows Server 2019 must be configured to audit Logon/Logoff - Group Membership successes."
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
    Id = "V-93161"
    Task = "Windows Server 2019 must be configured to audit Logon/Logoff - Special Logon successes."
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
    Id = "V-93163 + V-93165"
    Task = "Windows Server 2019 must be configured to audit Object Access - Other Object Access Events successes. Windows Server 2019 must be configured to audit Object Access - Other Object Access Events failures."
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
    Id = "V-93167 + V-93169"
    Task = "Windows Server 2019 must be configured to audit Object Access - Removable Storage successes. Windows Server 2019 must be configured to audit Object Access - Removable Storage failures."
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
    Id = "V-93171"
    Task = "Windows Server 2019 must be configured to audit logoff successes."
    Test = {
        # Get the audit policy for the subcategory Logoff
        $subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory "Logoff"
        
        if ([string]::IsNullOrEmpty($subCategoryGUID)) {
            return @{
                Message = "Cannot get Subcategory 'Logoff'"
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
