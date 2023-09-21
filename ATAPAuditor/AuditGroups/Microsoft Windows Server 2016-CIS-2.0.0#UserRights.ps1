$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
$hyperVStatus = CheckHyperVStatus
# Common
function ConvertTo-NTAccountUser {
	[CmdletBinding()]
	[OutputType([hashtable])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[string] $Name
	)

	process {
        try {
            # Convert Domaingroups to german
            $language = Get-UICulture
            if ($language.Name -match "de-DE"){
                if ($name -eq "Enterprise Admins"){
                    $name = "Organisations-Admins"
                }
                elseif ($name -eq "Domain Admins"){
                    $name = "Domänen-Admins"
                }
            }

            # Convert friendlynames to SID
            $map = @{
                "Administrators" = "S-1-5-32-544"
                "Guests" = "S-1-5-32-546"
                "Local account" = "S-1-5-113"
                "Local Service" = "S-1-5-19"
                "Network Service" = "S-1-5-20"
                "NT AUTHORITY\Authenticated Users" = "S-1-5-11"
                "Remote Desktop Users" = "S-1-5-32-555"
                "Service" = "S-1-5-6"
                "Users" = "S-1-5-32-545"
                "NT VIRTUAL MACHINE\Virtual Machines" = "S-1-5-83-0"
            }

            if ($map.ContainsKey($name)) {
                $name = $map[$name]
            }

            # Identity doesn't exist on when Hyper-V isn't installed
            if ($Name -eq "S-1-5-83-0" -and $hyperVStatus -ne "Enabled") {
                return $null
            }

            Write-Verbose "[ConvertTo-NTAccountUser] Converting identity '$Name' to NTAccount"
            if ($Name -match "^(S-[0-9-]{3,})") {
                $sidAccount = [System.Security.Principal.SecurityIdentifier]$Name
            }
            else {
                $sidAccount = ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier])
            }
           if ($sidAccount.Translate([System.Security.Principal.NTAccount]) -eq "NULL SID") {
                return @{
                    Account = $null
                    Sid = $sidAccount.Value
                }
            } else {
                return @{
                    Account = $sidAccount.Translate([System.Security.Principal.NTAccount])
                    Sid = $sidAccount.Value
                }
            }
        }
        catch {
            return @{
                Account = "Orphaned Account"
                Sid     = $Name
            }
        }
	}
}

# Tests
[AuditTest] @{
    Id = "2.2.1"
    Task = "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeTrustedCredManAccessPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeTrustedCredManAccessPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeTrustedCredManAccessPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.2"
    Task = "(L1) Ensure 'Access this computer from the network' is set to  'Administrators, Authenticated Users, ENTERPRISE DOMAIN  CONTROLLERS' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeNetworkLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-11"
            "S-1-5-9"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeNetworkLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeNetworkLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.3"
    Task = "(L1) Ensure 'Access this computer from the network' is set to  'Administrators, Authenticated Users' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeNetworkLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-11"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeNetworkLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeNetworkLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.4"
    Task = "(L1) Ensure 'Act as part of the operating system' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeTcbPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeTcbPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeTcbPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.5"
    Task = "(L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeMachineAccountPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeMachineAccountPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeMachineAccountPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.6"
    Task = "(L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeIncreaseQuotaPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-19"
            "S-1-5-20"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeIncreaseQuotaPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeIncreaseQuotaPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.7"
    Task = "(L1) Ensure 'Allow log on locally' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeInteractiveLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeInteractiveLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.8"
    Task = "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeRemoteInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeRemoteInteractiveLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.9"
    Task = "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-32-555"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        if ($unexpectedUsers.Count -gt 0) {
            $messages = @()
            $messages += "The user right 'SeRemoteInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            $message = $messages -join [System.Environment]::NewLine
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.10"
    Task = "(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeBackupPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeBackupPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeBackupPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.11"
    Task = "(L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSystemtimePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-19"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSystemtimePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSystemtimePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.12"
    Task = "(L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeTimeZonePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-19"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeTimeZonePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeTimeZonePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.13"
    Task = "(L1) Ensure 'Create a pagefile' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreatePagefilePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeCreatePagefilePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeCreatePagefilePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.14"
    Task = "(L1) Ensure 'Create a token object' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateTokenPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeCreateTokenPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeCreateTokenPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.15"
    Task = "(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateGlobalPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-19"
            "S-1-5-20"
            "S-1-5-6"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeCreateGlobalPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeCreateGlobalPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.16"
    Task = "(L1) Ensure 'Create permanent shared objects' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreatePermanentPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeCreatePermanentPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeCreatePermanentPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.17"
    Task = "(L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateSymbolicLinkPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeCreateSymbolicLinkPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeCreateSymbolicLinkPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
if($hyperVStatus -ne "Enabled"){
    [AuditTest] @{
        Id = "2.2.18"
        Task = "(L1) Ensure 'Create symbolic links' is set to 'Administrators [Hyper-V-Feature NOT installed] (MS only)"
        Constraints = @(
            @{ "Property" = "DomainRole"; "Values" = "Member Server" }
        )
        Test = {
            $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
            $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateSymbolicLinkPrivilege"]
            $identityAccounts = @(
                "S-1-5-32-544"
            ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
            
            $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
            $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
            
            if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
                $messages = @()
                if ($unexpectedUsers.Count -gt 0) {
                    $messages += "The user right 'SeCreateSymbolicLinkPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
                }
                if ($missingUsers.Count -gt 0) {
                    $messages += "The user 'SeCreateSymbolicLinkPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
                }
                $message = $messages -join [System.Environment]::NewLine
            
                return @{
                    Status = "False"
                    Message = $message
                }
            }
            
            return @{
                Status = "True"
                Message = "Compliant"
            }
        }
    }
}
else{
    [AuditTest] @{
        Id = "2.2.18"
        Task = "(L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' [Hyper-V-Feature installed] (MS only)"
        Constraints = @(
            @{ "Property" = "DomainRole"; "Values" = "Member Server" }
        )
        Test = {
            $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
            $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateSymbolicLinkPrivilege"]
            $identityAccounts = @(
                "S-1-5-32-544"
                "S-1-5-83-0"
            ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }

            if ($null -eq (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V)) {
                return @{
                    Status = "None"
                    Message = "Hyper-V not installed."
                }
            }
            
            $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
            $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
            
            if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
                $messages = @()
                if ($unexpectedUsers.Count -gt 0) {
                    $messages += "The user right 'SeCreateSymbolicLinkPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
                }
                if ($missingUsers.Count -gt 0) {
                    $messages += "The user 'SeCreateSymbolicLinkPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
                }
                $message = $messages -join [System.Environment]::NewLine
            
                return @{
                    Status = "False"
                    Message = $message
                }
            }
            
            return @{
                Status = "True"
                Message = "Compliant"
            }
        }
    }
}
[AuditTest] @{
    Id = "2.2.19"
    Task = "(L1) Ensure 'Debug programs' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDebugPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        
        if ($unexpectedUsers.Count -gt 0) {
            $messages = @()
            $messages += "The user right 'SeDebugPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            $message = $messages -join [System.Environment]::NewLine
            return @{
                Status = "False"
                Message = $message
            }
        } 
        #No UserRights on System comparing to publisher recommendation
        if($null -eq $currentUserRights -and $identityAccounts.Count -gt 0){
            return @{
                Status = "True"
                Message = "Compliant - No UserRights are assigned to this policy. This configuration is even more secure than publisher recommendation."
            }
        }
        #Less UserRights on System comparing to publisher recommendation
        if($currentUserRights.Count -lt $identityAccounts.Count){
            $users = ""
            foreach($currentUser in $currentUserRights){
                $users += $currentUser.Values
            }
            return @{
                Status = "True"
                Message = "Compliant - Positive Deviation to publisher. Less UserRights are assigned to this policy than expected: $($users)"
            }
        }
        #Same UserRights on System comparing to publisher recommendation
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.20"
    Task = "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyNetworkLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyNetworkLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.21"
    Task = "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyNetworkLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
            "S-1-2-0"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyNetworkLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.22"
    Task = "(L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyBatchLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyBatchLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.23"
    Task = "(L1) Ensure 'Deny log on as a service' to include 'Guests'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyServiceLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyServiceLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.24"
    Task = "(L1) Ensure 'Deny log on locally' to include 'Guests'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyInteractiveLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyInteractiveLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.25"
    Task = "(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyRemoteInteractiveLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.26"
    Task = "(L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-546"
            "S-1-5-113"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDenyRemoteInteractiveLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.27"
    Task = "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeEnableDelegationPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeEnableDelegationPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeEnableDelegationPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.28"
    Task = "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeEnableDelegationPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeEnableDelegationPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeEnableDelegationPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.29"
    Task = "(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRemoteShutdownPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeRemoteShutdownPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeRemoteShutdownPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.30 A"
    Task = "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE' [ADFS-ROLE NOT installed]"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeAuditPrivilege"]
        $identityAccounts = @(
            "S-1-5-19"
            "S-1-5-20"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeAuditPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeAuditPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.30 B"
    Task = "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'  [ADFS-ROLE installed]"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeAuditPrivilege"]
        $identityAccounts = @(
            "S-1-5-19"
            "S-1-5-20"
            "S-1-5-80-2246541699-21809830-3603976364-117610243-975697593"
            "S-1-5-80-1321940109-3370001082-3650459431-215109509-2472514016"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeAuditPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeAuditPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.31"
    Task = "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeImpersonatePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-19"
            "S-1-5-20"
            "S-1-5-6"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeImpersonatePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeImpersonatePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
if ((Get-WindowsFeature -Name web-server).installed -ne $true) {
    [AuditTest] @{
        Id = "2.2.32 A"
        Task = "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' [IIS Role NOT installed] (MS only)"
        Constraints = @(
            @{ "Property" = "DomainRole"; "Values" = "Member Server" }
        )
        Test = {
            $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
            $currentUserRights = $securityPolicy["Privilege Rights"]["SeImpersonatePrivilege"]
            $identityAccounts = @(
                "S-1-5-32-544"
                "S-1-5-19"
                "S-1-5-20"
                "S-1-5-6"
            ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
            
            $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
            $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
            
            if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
                $messages = @()
                if ($unexpectedUsers.Count -gt 0) {
                    $messages += "The user right 'SeImpersonatePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
                }
                if ($missingUsers.Count -gt 0) {
                    $messages += "The user 'SeImpersonatePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
                }
                $message = $messages -join [System.Environment]::NewLine
            
                return @{
                    Status = "False"
                    Message = $message
                }
            }
            
            return @{
                Status = "True"
                Message = "Compliant"
            }
        }
    }
}
else{
    [AuditTest] @{
        Id = "2.2.32 B"
        Task = "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, IIS_IUSRS' [IIS Role installed] (MS only)"
        Constraints = @(
            @{ "Property" = "DomainRole"; "Values" = "Member Server" }
        )
        Test = {
            $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
            $currentUserRights = $securityPolicy["Privilege Rights"]["SeImpersonatePrivilege"]
            $identityAccounts = @(
                "S-1-5-32-544"
                "S-1-5-19"
                "S-1-5-20"
                "S-1-5-6"
                "S-1-5-32-568"
            ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
            
            $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
            $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
            
            if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
                $messages = @()
                if ($unexpectedUsers.Count -gt 0) {
                    $messages += "The user right 'SeImpersonatePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
                }
                if ($missingUsers.Count -gt 0) {
                    $messages += "The user 'SeImpersonatePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
                }
                $message = $messages -join [System.Environment]::NewLine
            
                return @{
                    Status = "False"
                    Message = $message
                }
            }
            
            return @{
                Status = "True"
                Message = "Compliant"
            }
        }
    }
}
[AuditTest] @{
    Id = "2.2.33"
    Task = "(L1) Ensure 'Increase scheduling priority' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeIncreaseBasePriorityPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeIncreaseBasePriorityPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeIncreaseBasePriorityPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.34"
    Task = "(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeLoadDriverPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeLoadDriverPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeLoadDriverPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.35"
    Task = "(L1) Ensure 'Lock pages in memory' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeLockMemoryPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeLockMemoryPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeLockMemoryPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.36"
    Task = "(L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeBatchLogonRight"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeBatchLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeBatchLogonRight' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.37"
    Task = "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators' and (when Exchange is running in the environment) 'Exchange Servers' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSecurityPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSecurityPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSecurityPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.38"
    Task = "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Member Server" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSecurityPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSecurityPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSecurityPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.39"
    Task = "(L1) Ensure 'Modify an object label' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRelabelPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeRelabelPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeRelabelPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.40"
    Task = "(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSystemEnvironmentPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSystemEnvironmentPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSystemEnvironmentPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.41"
    Task = "(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeManageVolumePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeManageVolumePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeManageVolumePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.42"
    Task = "(L1) Ensure 'Profile single process' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeProfileSingleProcessPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeProfileSingleProcessPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeProfileSingleProcessPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.43"
    Task = "(L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSystemProfilePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
            "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSystemProfilePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSystemProfilePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.44"
    Task = "(L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeAssignPrimaryTokenPrivilege"]
        $identityAccounts = @(
            "S-1-5-19"
            "S-1-5-20"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeAssignPrimaryTokenPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeAssignPrimaryTokenPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.45"
    Task = "(L1) Ensure 'Restore files and directories' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRestorePrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeRestorePrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeRestorePrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.46"
    Task = "(L1) Ensure 'Shut down the system' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeShutdownPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeShutdownPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeShutdownPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.47"
    Task = "(L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)"
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "Primary Domain Controller", "Backup Domain Controller" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSyncAgentPrivilege"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeSyncAgentPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeSyncAgentPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "2.2.48"
    Task = "(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeTakeOwnershipPrivilege"]
        $identityAccounts = @(
            "S-1-5-32-544"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeTakeOwnershipPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeTakeOwnershipPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
            }
            $message = $messages -join [System.Environment]::NewLine
        
            return @{
                Status = "False"
                Message = $message
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
