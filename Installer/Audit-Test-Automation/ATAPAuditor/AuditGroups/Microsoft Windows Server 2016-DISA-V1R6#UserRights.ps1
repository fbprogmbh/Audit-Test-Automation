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
            if ($Name -eq "S-1-5-83-0" -and
                (Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V").State -ne "Enabled") {
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
    Id = "WN16-UR-000010"
    Task = "The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."
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
    Id = "WN16-DC-000340"
    Task = "The Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeNetworkLogonRight"]
        $identityAccounts = @(
            "Administrators"
            "NT AUTHORITY\Authenticated Users"
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
    Id = "WN16-MS-000340"
    Task = "The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer", "StandaloneServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeNetworkLogonRight"]
        $identityAccounts = @(
            "Administrators"
            "NT AUTHORITY\Authenticated Users"
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
    Id = "WN16-UR-000030"
    Task = "The Act as part of the operating system user right must not be assigned to any groups or accounts."
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
    Id = "WN16-DC-000350"
    Task = "The Add workstations to domain user right must only be assigned to the Administrators group."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeMachineAccountPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000050"
    Task = "The Allow log on locally user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeInteractiveLogonRight"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-DC-000360"
    Task = "The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000070"
    Task = "The Back up files and directories user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeBackupPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000080"
    Task = "The Create a pagefile user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreatePagefilePrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000090"
    Task = "The Create a token object user right must not be assigned to any groups or accounts."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateTokenPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000100"
    Task = "The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateGlobalPrivilege"]
        $identityAccounts = @(
            "Administrators"
            "Service"
            "Local Service"
            "Network Service"
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
    Id = "WN16-UR-000110"
    Task = "The Create permanent shared objects user right must not be assigned to any groups or accounts."
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
    Id = "WN16-UR-000120"
    Task = "The Create symbolic links user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeCreateSymbolicLinkPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
[AuditTest] @{
    Id = "WN16-UR-000130"
    Task = "The Debug programs user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDebugPrivilege"]
        $identityAccounts = @(
            "Administrators"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDebugPrivilege' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
            if ($missingUsers.Count -gt 0) {
                $messages += "The user 'SeDebugPrivilege' setting does not contain the following users: " + ($missingUsers -join ", ")
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
    Id = "WN16-DC-000370"
    Task = "The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyNetworkLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyNetworkLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000370 MS"
    Task = "The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyNetworkLogonRight"]
        $identityAccounts = @(
            "Enterprise Admins"
            "Domain Admins"
            "Administrators"
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyNetworkLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000370 SS"
    Task = "The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "StandaloneServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyNetworkLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyNetworkLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-DC-000380"
    Task = "The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyBatchLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyBatchLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000380 MS"
    Task = "The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyBatchLogonRight"]
        $identityAccounts = @(
            "Enterprise Admins"
            "Domain Admins"
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyBatchLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000380 SS"
    Task = "The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "StandaloneServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyBatchLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyBatchLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-DC-000390"
    Task = "The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyServiceLogonRight"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyServiceLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000390 MS"
    Task = "The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyServiceLogonRight"]
        $identityAccounts = @(
            "Enterprise Admins"
            "Domain Admins"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyServiceLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000390 SS"
    Task = "The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "StandaloneServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyServiceLogonRight"]
        $identityAccounts = @(
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyServiceLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-DC-000400"
    Task = "The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyInteractiveLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000400 MS"
    Task = "The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyInteractiveLogonRight"]
        $identityAccounts = @(
            "Enterprise Admins"
            "Domain Admins"
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000400 SS"
    Task = "The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "StandaloneServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyInteractiveLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-DC-000410"
    Task = "The Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyRemoteInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000410 MS"
    Task = "The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "Enterprise Admins"
            "Domain Admins"
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyRemoteInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-MS-000410 SS"
    Task = "The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "StandaloneServer" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDenyRemoteInteractiveLogonRight"]
        $identityAccounts = @(
            "Guests"
        ) | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
        $unexpectedUsers = $currentUserRights.Account | Where-Object { $_ -notin $identityAccounts.Account }
        $missingUsers = $identityAccounts.Account | Where-Object { $_ -notin $currentUserRights.Account }
        
        if (($unexpectedUsers.Count -gt 0) -or ($missingUsers.Count -gt 0)) {
            $messages = @()
            if ($unexpectedUsers.Count -gt 0) {
                $messages += "The user right 'SeDenyRemoteInteractiveLogonRight' contains following unexpected users: " + ($unexpectedUsers -join ", ")
            }
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
    Id = "WN16-DC-000420"
    Task = "The Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "PrimaryDomainController" }
    )
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeEnableDelegationPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-MS-000420"
    Task = "The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on member servers."
    Constraints = @(
        @{ "Property" = "DomainRole"; "Values" = "MemberServer", "StandaloneServer" }
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
    Id = "WN16-UR-000200"
    Task = "The Force shutdown from a remote system user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRemoteShutdownPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000210"
    Task = "The Generate security audits user right must only be assigned to Local Service and Network Service."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeAuditPrivilege"]
        $identityAccounts = @(
            "Local Service"
            "Network Service"
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
    Id = "WN16-UR-000220"
    Task = "The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeImpersonatePrivilege"]
        $identityAccounts = @(
            "Administrators"
            "Service"
            "Local Service"
            "Network Service"
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
[AuditTest] @{
    Id = "WN16-UR-000230"
    Task = "The Increase scheduling priority user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeIncreaseBasePriorityPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000240"
    Task = "The Load and unload device drivers user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeLoadDriverPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000250"
    Task = "The Lock pages in memory user right must not be assigned to any groups or accounts."
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
    Id = "WN16-UR-000260"
    Task = "The Manage auditing and security log user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSecurityPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000270"
    Task = "The Modify firmware environment values user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeSystemEnvironmentPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000280"
    Task = "The Perform volume maintenance tasks user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeManageVolumePrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000290"
    Task = "The Profile single process user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeProfileSingleProcessPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000300"
    Task = "The Restore files and directories user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeRestorePrivilege"]
        $identityAccounts = @(
            "Administrators"
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
    Id = "WN16-UR-000310"
    Task = "The Take ownership of files or other objects user right must only be assigned to the Administrators group."
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeTakeOwnershipPrivilege"]
        $identityAccounts = @(
            "Administrators"
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
