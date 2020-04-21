function ConvertTo-NTAccountUser {
	[CmdletBinding()]
	[OutputType([hashtable])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[string] $Name
	)

	process {
		# Identity doesn't exist on when Hyper-V isn't installed
		if ($Name -eq "NT VIRTUAL MACHINE\Virtual Machines" -and
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
}
