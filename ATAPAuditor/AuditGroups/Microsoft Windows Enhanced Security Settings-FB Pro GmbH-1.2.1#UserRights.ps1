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
            return @{
                Account = $sidAccount.Translate([System.Security.Principal.NTAccount])
                Sid = $sidAccount.Value
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
    Id = "1.0"
    Task = "Ensure 'Debug programs' is set to 'No One'"
    Test = {
        $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
        $currentUserRights = $securityPolicy["Privilege Rights"]["SeDebugPrivilege"]
        $identityAccounts = @(
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
