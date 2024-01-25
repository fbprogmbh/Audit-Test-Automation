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
        $identityAccounts = @() | ConvertTo-NTAccountUser | Where-Object { $null -ne $_ }
        
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
    Id = "2.1"
    Task = "Ensure 'Enable DCOM Hardening' is set to 'Enabled'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" `
                -Name "RequireIntegrityActivationAuthenticationLevel" `
                | Select-Object -ExpandProperty "RequireIntegrityActivationAuthenticationLevel"
        
            if ($regValue -ne 0x00000001) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0x00000001"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
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
    Id = "2.2"
    Task = "Ensure 'Raise Authentication Level' is set to 'Raise the authentication level for all non-anonymous activation requests from Windows-based DCOM clients'."
    Test = {
        try {
            $regValue = Get-ItemProperty -ErrorAction Stop `
                -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" `
                -Name "RaiseActivationAuthenticationLevel" `
                | Select-Object -ExpandProperty "RaiseActivationAuthenticationLevel"
        
            if ($regValue -ne 0x00000002) {
                return @{
                    Message = "Registry value is '$regValue'. Expected: 0x00000002"
                    Status = "False"
                }
            }
        }
        catch [System.Management.Automation.PSArgumentException] {
            return @{
                Message = "Registry value not found."
                Status = "False"
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return @{
                Message = "Registry key not found."
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}