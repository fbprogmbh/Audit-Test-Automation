using module .\..\Helpers\SecurityPolicy.psm1

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if(-not $isAdministrator){
	throw "Administrator privileges are required!"
}

# get a temporary file to save and process the secedit settings
$securityPolicyPath = Join-Path -Path $env:TEMP -ChildPath 'SecurityPolicy.inf'

# export the secedit settings to this temporary file
Write-Verbose "[WindowsSecurityPolicy] Exporting local security policies from secedit into tempory file: $securityPolicyPath"
secedit.exe /export /cfg $securityPolicyPath | Out-Null

$config = @{}
switch -regex -file $securityPolicyPath {
	"^\[(.+)\]" { # Section
		$section = $matches[1]
		$config[$section] = @{}
	}
	"(.+?)\s*=(.*)" { # Key
		$name = $matches[1]
		$value = $matches[2] -replace "\*"
		$config[$section][$name] = $value
	}
}

Write-Verbose "[WindowsSecurityPolicy] Converting identities in 'Privilege Rights' section"
$privilegeRights = @{}
foreach ($key in $config["Privilege Rights"].Keys) {
	# Make all accounts SIDs
	$accounts = $($config["Privilege Rights"][$key] -split ",").Trim() `
		| ConvertTo-NTAccountUser -Verbose:$VerbosePreference `
		| Where-Object { $null -ne $_ }
	$privilegeRights[$key] = $accounts
}
$config["Privilege Rights"] = $privilegeRights

# sanitize input
$systemAccess = @{}
foreach ($key in $config["System Access"].Keys) {
	$systemAccess[$key] = $config["System Access"][$key].Trim()
}
$config["System Access"] = $systemAccess

return $config