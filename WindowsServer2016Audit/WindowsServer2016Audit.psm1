#Requires -RunAsAdministrator

<#
BSD 3-Clause License

Copyright (c) 2019, FB Pro GmbH
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

using module ATAPHtmlReport
using namespace Microsoft.PowerShell.Commands
using namespace System.Security.AccessControl

# Import setting from file
$Settings = Import-LocalizedData -FileName "Settings.psd1"

#region Import tests
$DisaRequirements = Import-LocalizedData -FileName "DisaRequirements.psd1"
$CisBenchmarks    = Import-LocalizedData -FileName "CisBenchmarks.psd1"
#endregion


#region Logging functions
function Set-LogFile {
	[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
	Param(
		[Parameter(Mandatory = $true)]
		[Alias('LogPath')]
		[string]$Path,
		[Parameter(Mandatory = $true)]
		[Alias('Logname')]
		[string]$Name
	)

	$FullPath = Get-FullPath $Path $Name

	# Create file if it does not already exists
	if (!(Test-Path -Path $FullPath)) {

		# Create file and start logging
		New-Item -Path $FullPath -ItemType File -Force | Out-Null

		Add-Content -Path $FullPath -Value "***************************************************************************************************"
		Add-Content -Path $FullPath -Value " Logfile created at [$([DateTime]::Now)]"
		Add-Content -Path $FullPath -Value "***************************************************************************************************"
		Add-Content -Path $FullPath -Value ""
		Add-Content -Path $FullPath -Value ""
	}
}

function Write-LogFile {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[Alias('LogMessage')]
		[string]$Message,

		[Parameter(Mandatory = $true)]
		[Alias('LogPath')]
		[string]$Path,

		[Parameter(Mandatory = $true)]
		[Alias('Logname')]
		[string]$Name,

		[ValidateSet("Error", "Warning", "Info")]
		[string]$Level = "Info"
	)


	Set-LogFile $Path $Name
	$FullPath = Get-FullPath $Path $Name

	# Format date for log file
	$FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	switch ($Level) {
		'Error' {
			# Write-Error $Message
			$LevelText = '[ERROR]:'
		}
		'Warning' {
			# Write-Warning $Message
			$LevelText = '[WARNING]:'
		}
		'Info' {
			# Write-Verbose $Message
			$LevelText = '[INFO]:'
		}
	}
	Add-Content $FullPath "$FormattedDate $LevelText"
	Add-Content $FullPath "$Message"
	Add-Content $FullPath "--------------------------"
	Add-Content $FullPath ""
}

function Get-FullPath {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[string]$Path,
		[Parameter(Mandatory = $true)]
		[string]$File
	)

	$FullPath = ""
	if ($Path.Length -gt 0) {
		if ($Path[$Path.Length - 1] -ne "\") {
			$FullPath = $Path + "\" + $File
		}
		else {
			$FullPath = $Path + $File
		}
	}

	return $FullPath
}
#endregion

#region Helper functions

function PreprocessSpecialValueSetting {
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[hashtable] $InputObject
	)

	process {
		if ($InputObject.Keys -contains "SpecialValue") {
			$Type = $InputObject.SpecialValue.Type
			$PreValue = $InputObject.SpecialValue.Value

			$InputObject.Remove("SpecialValue")
			if ($Type -eq "Range") {
				$preValue = $preValue.ToLower()
	
				$predicates = @()
				if ($preValue -match "([0-9]+)[a-z ]* or less") {
					$y = [int]$Matches[1]
					$predicates += { param($x) $x -le $y }.GetNewClosure()
				}
				if ($preValue -match "([0-9]+)[ a-z]* or greater") {
					$y = [int]$Matches[1]
					$predicates += { param($x) $x -ge $y }.GetNewClosure()
				}
				if ($preValue -match "not ([0-9]+)") {
					$y = [int]$Matches[1]
					$predicates += { param($x) $x -ne $y }.GetNewClosure()
				}
				
				$InputObject.ExpectedValue = $preValue
				$InputObject.Predicate     = {
					param($x)
					return ($predicates | ForEach-Object { &$_ $x }) -notcontains $false
				}.GetNewClosure()
				return $InputObject
			}
			elseif ($Type -eq "Placeholder") {
				$value = $Settings[$preValue]
				$InputObject.Value = $value
	
				if ([string]::IsNullOrEmpty($value)) {
					$InputObject.ExpectedValue = "Non-empty string."
					$InputObject.Predicate     = { param($x) -not [string]::IsNullOrEmpty($x) }.GetNewClosure()
					return $InputObject
				}

				$InputObject.ExpectedValue = $value
				$InputObject.Predicate     = { param($x) $x -eq $value }.GetNewClosure()
				return $InputObject
			}
		}

		$value = $InputObject.Value

		$InputObject.ExpectedValue = $value -join ", "
		$InputObject.Predicate     = {
			param([string[]]$xs)
			
			if ($xs.Count -ne $value.Count) {
				return $false
			}
			
			$comparisonFunction = [Func[string, string, Boolean]]{ param($a, $b) $a -eq $b }
			$comparison = [System.Linq.Enumerable]::Zip([string[]]$value, $xs, $comparisonFunction)
			return $comparison -notcontains $false
		}.GetNewClosure()
		return $InputObject
	}
}

function ConvertTo-NTAccountUser {
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[string] $Name
	)

	process {
		if ($_ -match "^(S-[0-9-]{3,})") {
			$sidAccount = [System.Security.Principal.SecurityIdentifier]$Name
		}
		else {
			$sidAccount = ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier])
		}
		return $sidAccount.Translate([System.Security.Principal.NTAccount])
	}
}

function Get-SecurityPolicy {
	# get a temporary file to save and process the secedit settings
	Write-Verbose -Message "Get temporary file"
	$securityPolicyPath = Join-Path -Path $env:TEMP -ChildPath 'SecurityPolicy.inf'
	Write-Verbose -Message "Tempory file: $tmp"

	# export the secedit settings to this temporary file
	Write-Verbose "Export current Local Security Policy"
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

	$privilegeRights = @{}
	foreach ($key in $config["Privilege Rights"].Keys) {
		# Make all accounts SIDs
		$accounts = $($config["Privilege Rights"][$key] -split ",").Trim() | ConvertTo-NTAccountUser
		$privilegeRights[$key] = $accounts
	}
	$config["Privilege Rights"] = $privilegeRights

	return $config
}

# Get domain role
# 0 {"Standalone Workstation"}
# 1 {"Member Workstation"}
# 2 {"Standalone Server"}
# 3 {"Member Server"}
# 4 {"Backup Domain Controller"}
# 5 {"Primary Domain Controller"}
function Get-DomainRole {
	[DomainRole](Get-CimInstance -Class Win32_ComputerSystem).DomainRole
}

function Get-PrimaryDomainSID {
	<#
	.SYNOPSIS
		Obtains SID of the primary AD domain for the local computer
	#>

	[CmdletBinding()]
	Param()
	# Note: this script obtains SID of the primary AD domain for the local computer. It works both
	#       if the local computer is a domain member (DomainRole = 1 or DomainRole = 3)
	#       or if the local computer is a domain controller (DomainRole = 4 or DomainRole = 4).
	#       The code works even under local user account and does not require calling user
	#       to be domain account.

	[string]$domainSID = $null

	[int]$domainRole = Get-DomainRole

	if (($domainRole -ne [DomainRole]::StandaloneWorkstation) -and ($domainRole -ne [DomainRole]::StandaloneServer)) {

		[string] $domain = Get-CimInstance Win32_ComputerSystem | Select-Object -Expand Domain
		[string] $krbtgtSID = (New-Object Security.Principal.NTAccount $domain\krbtgt).Translate([Security.Principal.SecurityIdentifier]).Value
		$domainSID = $krbtgtSID.SubString(0, $krbtgtSID.LastIndexOf('-'))
	}

	return $domainSID
}

function Get-LocalAdminNames {
	# The Administrators Group has the SID S-1-5-32-544
	return (Get-LocalGroupMember -SID "S-1-5-32-544").Name `
		| Where-Object { $_.StartsWith($env:COMPUTERNAME) } `
		| ForEach-Object { $_.Substring($env:COMPUTERNAME.Length + 1) }
}

function Get-AuditPolicySubcategoryGUID {
	Param(
		[Parameter(Mandatory = $true)]
		[string] $Subcategory
	)
	switch ($Subcategory) {
		# Information availabe with: auditpol /list /subcategory:* /v
		# System
		'Security State Change'                  { "{0CCE9210-69AE-11D9-BED3-505054503030}" }
		'Security System Extension'              { "{0CCE9211-69AE-11D9-BED3-505054503030}" }
		'System Integrity'                       { "{0CCE9212-69AE-11D9-BED3-505054503030}" }
		'IPsec Driver'                           { "{0CCE9213-69AE-11D9-BED3-505054503030}" }
		'Other System Events'                    { "{0CCE9214-69AE-11D9-BED3-505054503030}" }
		# Logon/Logoff
		'Logon'                                  { "{0CCE9215-69AE-11D9-BED3-505054503030}" }
		'Logoff'                                 { "{0CCE9216-69AE-11D9-BED3-505054503030}" }
		'Account Lockout'                        { "{0CCE9217-69AE-11D9-BED3-505054503030}" }
		'IPsec Main Mode'                        { "{0CCE9218-69AE-11D9-BED3-505054503030}" }
		'IPsec Quick Mode'                       { "{0CCE9219-69AE-11D9-BED3-505054503030}" }
		'IPsec Extended Mode'                    { "{0CCE921A-69AE-11D9-BED3-505054503030}" }
		'Special Logon'                          { "{0CCE921B-69AE-11D9-BED3-505054503030}" }
		'Other Logon/Logoff Events'              { "{0CCE921C-69AE-11D9-BED3-505054503030}" }
		'Network Policy Server'                  { "{0CCE9243-69AE-11D9-BED3-505054503030}" }
		'User / Device Claims'                   { "{0CCE9247-69AE-11D9-BED3-505054503030}" }
		'Group Membership'                       { "{0CCE9249-69AE-11D9-BED3-505054503030}" }
		# Object Access
		'File System'                            { "{0CCE921D-69AE-11D9-BED3-505054503030}" }
		'Registry'                               { "{0CCE921E-69AE-11D9-BED3-505054503030}" }
		'Kernel Object'                          { "{0CCE921F-69AE-11D9-BED3-505054503030}" }
		'SAM'                                    { "{0CCE9220-69AE-11D9-BED3-505054503030}" }
		'Certification Services'                 { "{0CCE9221-69AE-11D9-BED3-505054503030}" }
		'Application Generated'                  { "{0CCE9222-69AE-11D9-BED3-505054503030}" }
		'Handle Manipulation'                    { "{0CCE9223-69AE-11D9-BED3-505054503030}" }
		'File Share'                             { "{0CCE9224-69AE-11D9-BED3-505054503030}" }
		'Filtering Platform Packet Drop'         { "{0CCE9225-69AE-11D9-BED3-505054503030}" }
		'Filtering Platform Connection'          { "{0CCE9226-69AE-11D9-BED3-505054503030}" }
		'Other Object Access Events'             { "{0CCE9227-69AE-11D9-BED3-505054503030}" }
		'Detailed File Share'                    { "{0CCE9244-69AE-11D9-BED3-505054503030}" }
		'Removable Storage'                      { "{0CCE9245-69AE-11D9-BED3-505054503030}" }
		'Central Policy Staging'                 { "{0CCE9246-69AE-11D9-BED3-505054503030}" }
		# Privelege Use
		'Sensitive Privilege Use'                { "{0CCE9228-69AE-11D9-BED3-505054503030}" }
		'Non Sensitive Privilege Use'            { "{0CCE9229-69AE-11D9-BED3-505054503030}" }
		'Other Privilege Use Events'             { "{0CCE922A-69AE-11D9-BED3-505054503030}" }
		# Detailed Tracking
		'Process Creation'                       { "{0CCE922B-69AE-11D9-BED3-505054503030}" }
		'Process Termination'                    { "{0CCE922C-69AE-11D9-BED3-505054503030}" }
		'DPAPI Activity'                         { "{0CCE922D-69AE-11D9-BED3-505054503030}" }
		'RPC Events'                             { "{0CCE922E-69AE-11D9-BED3-505054503030}" }
		'Plug and Play Events'                   { "{0CCE9248-69AE-11D9-BED3-505054503030}" }
		'Token Right Adjusted Events'            { "{0CCE924A-69AE-11D9-BED3-505054503030}" }
		# Policy Change
		'Audit Policy Change'                    { "{0CCE922F-69AE-11D9-BED3-505054503030}" }
		'Authentication Policy Change'           { "{0CCE9230-69AE-11D9-BED3-505054503030}" }
		'Authorization Policy Change'            { "{0CCE9231-69AE-11D9-BED3-505054503030}" }
		'MPSSVC Rule-Level Policy Change'        { "{0CCE9232-69AE-11D9-BED3-505054503030}" }
		'Filtering Platform Policy Change'       { "{0CCE9233-69AE-11D9-BED3-505054503030}" }
		'Other Policy Change Events'             { "{0CCE9234-69AE-11D9-BED3-505054503030}" }
		# Account Management
		'User Account Management'                { "{0CCE9235-69AE-11D9-BED3-505054503030}" }
		'Computer Account Management'            { "{0CCE9236-69AE-11D9-BED3-505054503030}" }
		'Security Group Management'              { "{0CCE9237-69AE-11D9-BED3-505054503030}" }
		'Distribution Group Management'          { "{0CCE9238-69AE-11D9-BED3-505054503030}" }
		'Application Group Management'           { "{0CCE9239-69AE-11D9-BED3-505054503030}" }
		'Other Account Management Events'        { "{0CCE923A-69AE-11D9-BED3-505054503030}" }
		# DS Access
		'Directory Service Access'               { "{0CCE923B-69AE-11D9-BED3-505054503030}" }
		'Directory Service Changes'              { "{0CCE923C-69AE-11D9-BED3-505054503030}" }
		'Directory Service Replication'          { "{0CCE923D-69AE-11D9-BED3-505054503030}" }
		'Detailed Directory Service Replication' { "{0CCE923E-69AE-11D9-BED3-505054503030}" }
		# Account Logon
		'Credential Validation'                  { "{0CCE923F-69AE-11D9-BED3-505054503030}" }
		'Kerberos Service Ticket Operations'     { "{0CCE9240-69AE-11D9-BED3-505054503030}" }
		'Other Account Logon Events'             { "{0CCE9241-69AE-11D9-BED3-505054503030}" }
		'Kerberos Authentication Service'        { "{0CCE9242-69AE-11D9-BED3-505054503030}" }

		Default                                  { "" }
	}
}

function Convert-ToAuditInfo {
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Psobject] $auditObject
	)

	process {
		return [AuditInfo]@{
			Id      = $auditObject.Name
			Task    = $auditObject.Task
			Message = $auditObject.Status
			Audit   = $auditObject.Passed
		}
	}
}
#endregion

#region Audit functions
function Get-RoleAudit {
	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string[]] $Role = @("MemberServer","StandaloneServer")
	)

	process {
		$domainRoles = $Role | ForEach-Object { [DomainRole]$_ }
		if ((Get-DomainRole) -notin $domainRoles) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Not applicable. This audit applies to " + ($Role -join " and ") + "."
				Audit = [AuditStatus]::None
			}
		}
		return $null
	}
}

function Get-RegistryAudit {
	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Path,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Name,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[AllowEmptyString()]
		[AllowEmptyCollection()]
		[string[]] $Value,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ScriptBlock] $Predicate,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[String] $ExpectedValue,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[bool] $DoesNotExist = $false
	)

	process {
		try {
			$regValues = Get-ItemProperty -ErrorAction Stop -Path $Path -Name $Name `
				| Select-Object -ExpandProperty $Name

			if ($DoesNotExist) {
				return [AuditInfo]@{
					Id = $Id
					Task = $Task
					Message = "Registry value found."
					Audit = [AuditStatus]::False
				}
			}

			if (-not (& $Predicate $regValues)) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
					-Message "$($Id): Registry value $Name in registry key $Path is not correct."

				$regValue = $regValues -join ", "

				return [AuditInfo]@{
					Id = $Id
					Task = $Task
					Message = "Registry value: $regValue. Differs from expected value: $ExpectedValue."
					Audit = [AuditStatus]::False
				}
			}
		}
		catch [System.Management.Automation.PSArgumentException] {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
				-Message "$($Id): Could not get value $Name in registry key $path."
			
			if ($DoesNotExist) {
				return [AuditInfo]@{
					Id = $Id
					Task = $Task
					Message = "Compliant. Registry value not found."
					Audit = [AuditStatus]::True
				}
			}

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Registry value not found."
				Audit = [AuditStatus]::False
			}
		}
		catch [System.Management.Automation.ItemNotFoundException] {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
				-Message "$($Id): Could not get key $Name in registry key $path."

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Registry key not found."
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

function Get-UserRightPolicyAudit {
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet(
			'SeNetworkLogonRight',
			'SeTcbPrivilege',
			'SeBackupPrivilege',
			'SeChangeNotifyPrivilege',
			'SeSystemtimePrivilege',
			'SeCreatePagefilePrivilege',
			'SeDebugPrivilege',
			'SeRemoteShutdownPrivilege',
			'SeAuditPrivilege',
			'SeIncreaseQuotaPrivilege',
			'SeLoadDriverPrivilege',
			'SeBatchLogonRight',
			'SeServiceLogonRight',
			'SeInteractiveLogonRight',
			'SeSecurityPrivilege',
			'SeSystemEnvironmentPrivilege',
			'SeProfileSingleProcessPrivilege',
			'SeSystemProfilePrivilege',
			'SeAssignPrimaryTokenPrivilege',
			'SeTakeOwnershipPrivilege',
			'SeDenyNetworkLogonRight',
			'SeDenyBatchLogonRight',
			'SeDenyServiceLogonRight',
			'SeDenyInteractiveLogonRight',
			'SeUndockPrivilege',
			'SeManageVolumePrivilege',
			'SeRemoteInteractiveLogonRight',
			'SeDenyRemoteInteractiveLogonRight',
			'SeImpersonatePrivilege',
			'SeCreateGlobalPrivilege',
			'SeIncreaseWorkingSetPrivilege',
			'SeTimeZonePrivilege',
			'SeCreateSymbolicLinkPrivilege',
			'SeDelegateSessionUserImpersonatePrivilege',
			'SeCreateTokenPrivilege',
			'SeCreatePermanentPrivilege',
			'SeIncreaseBasePriorityPrivilege',
			'SeLockMemoryPrivilege',
			'SeRestorePrivilege',
			'SeTrustedCredManAccessPrivilege',
			'SeEnableDelegationPrivilege',
			'SeRelabelPrivilege',
			'SeShutdownPrivilege'
		)]
		[string] $Policy,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[AllowEmptyCollection()]
		[string[]] $Identity
	)

	process {
		$securityPolicy = Get-SecurityPolicy -Verbose:$VerbosePreference
		$currentUserRights = $securityPolicy["Privilege Rights"][$Policy]

		$identityAccounts = $Identity | ConvertTo-NTAccountUser

		$usersWithTooManyRights = $currentUserRights | Where-Object { $_ -notin $identityAccounts }
		$usersWithoutRights = $identityAccounts | Where-Object { $_ -notin $currentUserRights }

		if ($usersWithTooManyRights.Count -gt 0) {
			$message = "The following users have too many rights: " + ($usersWithTooManyRights -join ", ")
			Write-Verbose -Message $message

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = $message
				Audit = [AuditStatus]::False
			}
		}

		if ($usersWithoutRights.Count -gt 0) {
			$message = "The following users have don't have the rights: " + ($usersWithoutRights -join ", ")
			Write-Verbose -Message $message

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = $message
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

function Get-AccountPolicyAudit {
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet(
			'MinimumPasswordAge',
			'MaximumPasswordAge',
			'MinimumPasswordLength',
			'PasswordComplexity',
			'PasswordHistorySize',
			'LockoutBadCount',
			'ResetLockoutCount',
			'LockoutDuration',
			'RequireLogonToChangePassword',
			'ForceLogoffWhenHourExpire',
			'NewAdministratorName',
			'NewGuestName',
			'ClearTextPassword',
			'LSAAnonymousNameLookup',
			'EnableAdminAccount',
			'EnableGuestAccount'
		)]
		[string] $Policy,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[object] $Value,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ScriptBlock] $Predicate
	)

	process {
		$securityPolicy = Get-SecurityPolicy -Verbose:$VerbosePreference
		$currentAccountPolicy = $securityPolicy["System Access"][$Policy]

		if ($null -eq $currentAccountPolicy) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Currently not set."
				Audit = [AuditStatus]::False
			}
		}

		# Sanitize input
		$currentAccountPolicy = $currentAccountPolicy.Trim()

		if (-not (& $Predicate $currentAccountPolicy)) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Currently set to: $currentAccountPolicy. Differs from expected value: $ExpectedValue"
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

function Get-AuditPolicyAudit {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet(
			'Security System Extension',
			'System Integrity',
			'IPsec Driver',
			'Other System Events',
			'Security State Change',
			'Logon',
			'Logoff',
			'Account Lockout',
			'IPsec Main Mode',
			'IPsec Quick Mode',
			'IPsec Extended Mode',
			'Special Logon',
			'Other Logon/Logoff Events',
			'Network Policy Server',
			'User / Device Claims',
			'Group Membership',
			'File System',
			'Registry',
			'Kernel Object',
			'SAM',
			'Certification Services',
			'Application Generated',
			'Handle Manipulation',
			'File Share',
			'Filtering Platform Packet Drop',
			'Filtering Platform Connection',
			'Other Object Access Events',
			'Detailed File Share',
			'Removable Storage',
			'Central Policy Staging',
			'Non Sensitive Privilege Use',
			'Other Privilege Use Events',
			'Sensitive Privilege Use',
			'Process Creation',
			'Process Termination',
			'DPAPI Activity',
			'RPC Events',
			'Plug and Play Events',
			'Token Right Adjusted Events',
			'Audit Policy Change',
			'Authentication Policy Change',
			'Authorization Policy Change',
			'MPSSVC Rule-Level Policy Change',
			'Filtering Platform Policy Change',
			'Other Policy Change Events',
			'Computer Account Management',
			'Security Group Management',
			'Distribution Group Management',
			'Application Group Management',
			'Other Account Management Events',
			'User Account Management',
			'Directory Service Access',
			'Directory Service Changes',
			'Directory Service Replication',
			'Detailed Directory Service Replication',
			'Kerberos Service Ticket Operations',
			'Other Account Logon Events',
			'Kerberos Authentication Service',
			'Credential Validation')]
		[string] $Subcategory,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet(
			'Success',
			'Failure',
			'Success and Failure',
			'No Auditing')]
		[string] $AuditFlag
	)

	process {
		# Get the audit policy for the subcategory $subcategory
		$subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory $Subcategory
		$auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"

		# auditpol does not throw exceptions, so test the results and throw if needed
		if ($LASTEXITCODE -ne 0) {
			$errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
			throw [System.ArgumentException] $errorString
			Write-Error -Message $errorString
		}

		if ($null -eq $auditPolicyString) {
			return [AuditInfo]@{
				Id      = $Id
				Task    = $Task
				Message = "Couldn't get setting. Auditpol returned nothing."
				Audit   = [AuditStatus]::False
			}
		}

		# Remove empty lines and headers
		$line = $auditPolicyString `
			| Where-Object { $_ } `
			| Select-Object -Skip 3

		if ($line -notmatch "(No Auditing|Success and Failure|Success|Failure)$") {
			return [AuditInfo]@{
				Id      = $Id
				Task    = $Task
				Message = "Couldn't get setting."
				Audit   = [AuditStatus]::False
			}
		}
		
		$setting = $Matches[0]
		
		if ($setting -ne $AuditFlag -and -not (($line -eq "Success and Failure" -and ($AuditFlag -in "Success", "Failure")))) {
			return [AuditInfo]@{
				Id      = $Id
				Task    = $Task
				Message = "Set to: $setting"
				Audit   = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id      = $Id
			Task    = $Task
			Message = "Compliant"
			Audit   = [AuditStatus]::True
		}
	}
}

function Get-WindowsFeatureAudit {
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Feature
	)

	process {
		$installState = (Get-WindowsFeature | Where-Object Name -eq $Feature).InstallState

		if ($installState -eq "Installed") {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "The feature is installed."
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

enum GARights {
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000
}

# See https://docs.microsoft.com/en-us/windows/desktop/FileIO/file-security-and-access-rights for more information
$GAToFSRMapping = @{
	[GARights]::GENERIC_READ = `
		[FileSystemRights]::ReadAttributes -bor `
		[FileSystemRights]::ReadData -bor `
		[FileSystemRights]::ReadExtendedAttributes -bor `
		[FileSystemRights]::ReadPermissions -bor `
		[FileSystemRights]::Synchronize
	[GARights]::GENERIC_WRITE = `
		[FileSystemRights]::AppendData -bor `
		[FileSystemRights]::WriteAttributes -bor `
		[FileSystemRights]::WriteData -bor `
		[FileSystemRights]::WriteExtendedAttributes -bor `
		[FileSystemRights]::ReadPermissions -bor `
		[FileSystemRights]::Synchronize
	[GARights]::GENERIC_EXECUTE = `
		[FileSystemRights]::ExecuteFile -bor `
		[FileSystemRights]::ReadPermissions -bor `
		[FileSystemRights]::ReadAttributes -bor `
		[FileSystemRights]::Synchronize
	[GARights]::GENERIC_ALL = `
		[FileSystemRights]::FullControl
}

function Convert-FileSystemRights {
	param(
		[Parameter(Mandatory = $true)]
		[FileSystemRights] $OriginalRights
	)
	
	[FileSystemRights]$MappedRights = [FileSystemRights]::new()
	
	# map generic access right
	foreach ($GAR in $GAToFSRMapping.Keys) {
		if (($OriginalRights.value__ -band $GAR.value__) -eq $GAR.value__) {
			$MappedRights = $MappedRights -bor $GAToFSRMapping[$GAR]
		}
	}

	# mask standard access rights and object-specific access rights
	$MappedRights = $MappedRights -bor ($OriginalRights -band 0x00FFFFFF)

	return $MappedRights
}

# Non official mappings
$GAToRRMaping = @{
	[GARights]::GENERIC_READ = `
		[RegistryRights]::ReadKey
	[GARights]::GENERIC_WRITE = `
		[RegistryRights]::WriteKey
	[GARights]::GENERIC_ALL = `
		[RegistryRights]::FullControl
}

function Get-FileSystemPermissionsAudit {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Target,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[hashtable] $PrincipalRights
	)

	process {
		if ($Target -match "(%(.+)%)") {
			$varName = $Matches[2]
			$replaceValue = (Get-Item -Path "Env:$varName").Value
			$Target = $Target.Replace($Matches[1], $replaceValue)
		}

		$acls = (Get-Acl $Target).Access

		Write-Verbose "File system permissions for target: $Target)"

		$prinicpalsWithTooManyRights = $acls | Where-Object {
			$_.IdentityReference.Value -NotIn $PrincipalRights.Keys
		}
		$principalsWithWrongRights = $acls `
			| Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
			| Where-Object {
				# convert string to rights enum
				$referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
				$mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
				$mappedRights -notin $referenceRights
			}

		if (($prinicpalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
			$logOptions = @{
				Path = $Settings.LogFilePath
				Name = $Settings.LogFileName
				Level = "Error"
			}

			$messages = @()
			$messages += $prinicpalsWithTooManyRights | ForEach-Object {
				$mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
				"Unexpected '$($_.IdentityReference)' with access '$($mappedRights)'"
			}
			$messages += $principalsWithWrongRights | ForEach-Object {
				$idKey = $_.IdentityReference.Value
				$mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
				"Found '$($idKey)' with access '$($mappedRights)' instead of '$($PrincipalRights[$idKey])'"
			}.GetNewClosure()
			$messages | ForEach-Object { Write-LogFile @logOptions -Message "$($Id): $_" }

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = $messages -join "; "
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

function Convert-RegistryRights {
	param(
		[Parameter(Mandatory = $true)]
		[RegistryRights] $OriginalRights
	)
	
	[RegistryRights]$MappedRights = [RegistryRights]::new()
	
	# map generic access right
	foreach ($GAR in $GAToRRMaping.Keys) {
		if (($OriginalRights.value__ -band $GAR.value__) -eq $GAR.value__) {
			$MappedRights = $MappedRights -bor $GAToRRMaping[$GAR]
		}
	}

	# mask standard access rights and object-specific access rights
	$MappedRights = $MappedRights -bor ($OriginalRights -band 0x00FFFFFF)

	return $MappedRights
}

function Get-RegistryPermissionsAudit {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Target,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[hashtable] $PrincipalRights
	)

	process {
		if ($Target -match "(%(.+)%)") {
			$varName = $Matches[2]
			$replaceValue = (Get-Item -Path "Env:$varName").Value
			$Target = $Target.Replace($Matches[1], $replaceValue)
		}

		$acls = (Get-Acl $Target).Access

		Write-Verbose "Registry permissions for target: $Target)"

		$prinicpalsWithTooManyRights = $acls | Where-Object {
			$_.IdentityReference.Value -NotIn $PrincipalRights.Keys
		}
		$principalsWithWrongRights = $acls `
			| Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
			| Where-Object {
				# convert string to rights enum
				$referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [RegistryRights]$_ }
				$mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
				$mappedRights -notin $referenceRights
			}

		if (($prinicpalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
			$logOptions = @{
				Path = $Settings.LogFilePath
				Name = $Settings.LogFileName
				Level = "Error"
			}

			$messages = @()
			$messages += $prinicpalsWithTooManyRights | ForEach-Object {
				$mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
				"Unexpected '$($_.IdentityReference)' with access '$($mappedRights)'"
			}
			$messages += $principalsWithWrongRights | ForEach-Object {
				$idKey = $_.IdentityReference.Value
				$mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
				"Found '$($idKey)' with access '$($mappedRights)' instead of '$($PrincipalRights[$idKey])'"
			}.GetNewClosure()
			$messages | ForEach-Object { Write-LogFile @logOptions -Message "$($Id): $_" }

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = $messages -join "; "
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

function Get-FirewallProfileAudit {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Profile,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Setting,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Value
	)

	process {
		Write-Verbose -Message "Profile: $Profile, Setting: $Setting, Value: $Value"

		$firewallProfileArgs = @{ Name = $Profile }
		if ($Setting -like "AllowLocal*Rules") {
			$firewallProfileArgs.PolicyStore = "localhost"
		}

		$profileSettings = Get-NetFirewallProfile @firewallProfileArgs
		$currentValue = $profileSettings | Select-Object -ExpandProperty $Setting

		if ($currentValue -ne $Value) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Profile setting '$Setting' is currently set to '$currentValue'. Expected value is '$Value'."
				Audit = [AuditStatus]::False
			}
		}

		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Audit = [AuditStatus]::True
		}
	}
}

#endregion

#region Audit tests
<#
	This section contains all audit tests. Each test will return a PSCustomObject with the following properties

	Name      The name or ID  of the test,something to uniquely identify it
	Task      Short description of the test or the
	Status    Compliant / Not comliant / error
	Passed    Is the test successful (true / false / warning

	If an error occured, the error message and/or additional informations are logged in the logfile defined through $Settings.LogFilePath and $Settings.LogFileName
#>

#region DISA STIG Audit functions

# Passwords for the built-in Administrator account must be changed at least every 60 days.
# - - - - - - - - - - - - -
# StigID: WN16-00-000030
# Group ID (Vulid): V-73223
# CCI: CCI-000199
#
# The longer a password is in use, the greater the opportunity for someone to gain unauthorized
# knowledge of the password. The built-in Administrator account is not generally used and
# its password not may be changed as frequently as necessary. Changing the password for the
# built-in Administrator account on a regular basis will limit its exposure.Organizations
# that use an automated tool, such Microsofts Local Administrator Password Solution (LAPS),
# on domain-joined systems can configure this to occur more frequently. LAPS will change the
# password every 30 days by default.
function Test-SV-87875r2_rule {
	Param(
		[System.Int32] $days = 60
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87875r2_rule")
	$obj | Add-Member NoteProperty Task("Passwords for the built-in Administrator account must be changed at least every $days days.")

	$builtInAdmin = Get-localUser | Where-Object -Property sid -like "S-1-5-*-500"

	if ($builtInAdmin.PasswordLastSet -le (Get-Date).AddDays(-$days)) {
		$message = "Password for $($BuiltInAdmin.Name) last set on $($BuiltInAdmin.PasswordLastSet)"
		$obj | Add-Member NoteProperty Status($message)
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	else {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	Write-Output $obj
}


# Domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
#
# - - - - - - - - - - - - -
# StigID: WN16-00-000100
# Group ID (Vulid): V-73237
# CCI: CCI-000366
#
# Credential Guard uses virtualization-based security to protect data that could be used in
# credential theft attacks if compromised. A number of system requirements must be met in
# order for Credential Guard to be configured and enabled properly. Without a TPM enabled
# and ready for use, Credential Guard keys are stored in a less secure method using software.
#
function Test-SV-87889r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87889r1_rule")
	$obj | Add-Member NoteProperty Task("Domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.")

	# If machine is in a domain
	if ((Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain) {
		try {
			# Get TPM infos
			$tpm = Get-Tpm

			if ( $tpm.TpmPresent -and $tpm.TpmReady ) {
				$obj | Add-Member NoteProperty Status("Compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
			}
			else {
				$obj | Add-Member NoteProperty Status("TPM is not present or ready for use.")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			}
		}
		catch {
			# Get-Tpm threw an exception, so we probably do not have a TPM chip
			$obj | Add-Member NoteProperty Status("TPM missing")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	else {
		# If the machine is not domain joined, this is not a finding
		$obj | Add-Member NoteProperty Status("Not in domain")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}

	Write-Output $obj
}

# Systems must be maintained at a supported servicing level.
# - - - - - - - - - - - - -
# StigID: WN16-00-000110
# Group ID (Vulid): V-73239
# CCI: CCI-000366
#
# Systems at unsupported servicing levels will not receive security updates for new vulnerabilities,
# which leave them subject to exploitation. Systems must be maintained at a servicing level
# supported by the vendor with new security updates.
function Test-SV-87891r1_rule {
	Param(
		[System.Int32]$version = 14393
	)
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87891r1_rule")
	$obj | Add-Member NoteProperty Task("Systems must be maintained at a supported servicing level.")

	$acutalVersion = ([System.Environment]::OSVersion.Version).Build

	if ( $acutalVersion -ge $version ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Version is $acutalVersion")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}



# Local volumes must use a format that supports NTFS attributes.
# - - - - - - - - - - - - -
# StigID: WN16-00-000150
# Group ID (Vulid): V-73247
# CCI: CCI-000213
#
# The ability to set access permissions and auditing is critical to maintaining the security
# and proper access controls of a system. To support this, volumes must be formatted using
# a file system that supports NTFS attributes.
function Test-SV-87899r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87899r1_rule")
	$obj | Add-Member NoteProperty Task("Local volumes must use a format that supports NTFS attributes.")

	$volumes = Get-Volume `
		| Where-Object DriveType -eq Fixed `
		| Where-Object FileSystem -ne "NTFS"

	if ($volumes.Count -eq 0) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Found volume without NTFS formatting. " + ($volumes.UniqueId -join ', '))
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Non-administrative accounts or groups must only have print permissions on printer shares.
#
# - - - - - - - - - - - - -
# StigID: WN16-00-000200
# Group ID (Vulid): V-73257
# CCI: CCI-000213
#
# Windows shares are a means by which files, folders, printers, and other resources can be
# published for network users to access. Improper configuration can permit access to devices
# and data beyond a users need.
function Test-SV-87909r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87909r1_rule")
	$obj | Add-Member NoteProperty Task("Non-administrative accounts or groups must only have print permissions on printer shares.")

	$printers = Get-Printer
	$sharedPrinter = @()

	foreach ( $printer in $printers ) {
		if ( $printer.shared ) {
			$sharedPrinter += $printer.name
		}
	}

	if ( $sharedPrinter ) {
		$obj | Add-Member NoteProperty Status("Found shared printer(s)")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000200: Found shared printer(s) $sharedPrinter, please check printer security settings" -Level Error
	}
	else {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}

	Write-Output $obj
}

# Outdated or unused accounts must be removed from the system or disabled.
# - - - - - - - - - - - - -
# StigID: WN16-00-000210
# Group ID (Vulid): V-73259
# CCI: CCI-000764 CCI-000795
#
# Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts
# must be deleted if no longer necessary or, if still required, disabled until needed.Satisfies:
# SRG-OS-000104-GPOS-00051, SRG-OS-000118-GPOS-00060
function Test-SV-87911r2_rule {
	[CmdletBinding()]
	Param(
		[System.Int32]$days = 35
	)
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87911r2_rule")
	$obj | Add-Member NoteProperty Task("Outdated or unused accounts must be removed from the system or disabled.")

	$accounts = ([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where-Object { $_.SchemaClassName -eq 'user' }

	$compliant = $true

	foreach ($account in $accounts) {

		# if account is enabled
		if ( ($account.Properties.UserFlags.Value -band 0x2) -ne 0x2 ) {
			if ( $account.Properties.LastLogin.Value -lt (Get-Date).AddDays(-$days) ) {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000210: Outdated or unused account $($account.Name) - no login within $days days" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Found outdated or unused accounts.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Accounts must require passwords.
# - - - - - - - - - - - - -
# StigID: WN16-00-000220
# Group ID (Vulid): V-73261
# CCI: CCI-000764
#
# The lack of password protection enables anyone to gain access to the information system,
# which opens a backdoor opportunity for intruders to compromise the system as well as other
# resources. Accounts on a system must require passwords.
function Test-SV-87913r2_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87913r2_rule")
	$obj | Add-Member NoteProperty Task("Accounts must require passwords.")

	$accounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | Select-Object Name, PasswordRequired, Disabled
	$passwordNotRequired = @()

	foreach ($account in $accounts) {
		if (-not $account.Disabled) {
			if ( -not $account.PasswordRequired) {
				$passwordNotRequired += $account.name
			}
		}
	}

	if ( $passwordNotRequired ) {
		$obj | Add-Member NoteProperty Status("Found account without password.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		foreach ($entry in $passwordNotRequired) {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000220: Found enabled account not requiring a password: $entry" -Level Error
		}
	}
	else {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}

	Write-Output $obj
}

# Passwords must be configured to expire.
# - - - - - - - - - - - - -
# StigID: WN16-00-000230
# Group ID (Vulid): V-73263
# CCI: CCI-000199
#
# Passwords that do not expire or are reused increase the exposure of a password with greater
# probability of being discovered or cracked.
function Test-SV-87915r2_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87915r2_rule")
	$obj | Add-Member NoteProperty Task("Passwords must be configured to expire.")

	$accounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | Select-Object Name, PasswordExpires, Disabled
	$passwordNeverExpires = @()

	foreach ($account in $accounts) {
		if (-not $account.Disabled) {
			if ( -not $account.PasswordExpires) {
				$passwordNeverExpires += $account.name
			}
		}
	}

	if ( $passwordNeverExpires ) {
		$obj | Add-Member NoteProperty Status("Found account with never expiring passwords.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		foreach ($entry in $passwordNeverExpires) {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000220: Found enabled account not requiring a password: $entry" -Level Error
		}
	}
	else {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}

	Write-Output $obj
}


# Non-system-created file shares on a system must limit access to groups that require it.
# - - - - - - - - - - - - -
# StigID: WN16-00-000250
# Group ID (Vulid): V-73267
# CCI: CCI-001090
#
# Shares on a system provide network access. To prevent exposing sensitive information, where
# shares are necessary, permissions must be reconfigured to give the minimum access to accounts
# that require it.
function Test-SV-87919r1_rule {
	[CmdletBinding()]
	Param(
		[String[]]$reference = @("ADMIN$", "C$", "IPC$")
	)
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87919r1_rule")
	$obj | Add-Member NoteProperty Task("Non-system-created file shares on a system must limit access to groups that require it.")

	try {
		$shares = Get-CimInstance -Class Win32_Share | Select-Object -ErrorAction Stop -ExpandProperty Name

		$compare = Compare-Object -ReferenceObject $reference -DifferenceObject $shares

		if ( $compare.Count -eq 0 ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Shares not as expected")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::Warning)
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000250: Found shares $shares" -Level Error
		}
	}
	catch {
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000250: $($error[0])" -Level Error
	}

	Write-Output $obj
}

# Software certificate installation files must be removed from Windows Server 2016.
# - - - - - - - - - - - - -
# StigID: WN16-00-000270
# Group ID (Vulid): V-73271
# CCI: CCI-000366
#
# Use of software certificates and their accompanying installation files for end users to access
# resources is less secure than the use of hardware-based certificates.
function Test-SV-87923r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87923r1_rule")
	$obj | Add-Member NoteProperty Task("Software certificate installation files must be removed from Windows Server 2016.")

	$items = Get-Childitem –Path C:\ -Include *.pfx, *.p12 -File -Recurse -ErrorAction SilentlyContinue

	if ( $items.Count -eq 0 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Found certificates.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000270: Found the following certificates: `n $items"
	}

	Write-Output $obj
}

# Systems requiring data at rest protections must employ cryptographic mechanisms to prevent
# unauthorized disclosure and modification of the information at rest.
# - - - - - - - - - - - - -
# StigID: WN16-00-000280
# Group ID (Vulid): V-73273
# CCI: CCI-001199 CCI-002475 CCI-002476
#
# This requirement addresses protection of user-generated data as well as operating system-specific
# configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality
# and integrity protections, as appropriate, in accordance with the security category and/or
# classification of the information.Select-Objection of a cryptographic mechanism is based on the
# need to protect the integrity of organizational information. The strength of the mechanism
# is commensurate with the security category and/or classification of the information. Organizations
# have the flexibility to either encrypt all information on storage devices (i.e., full disk
# encryption) or encrypt specific data structures (e.g., files, records, or fields).Satisfies:
# SRG-OS-000185-GPOS-00079, SRG-OS-000404-GPOS-00183, SRG-OS-000405-GPOS-00184
function Test-SV-87925r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87925r1_rule")
	$obj | Add-Member NoteProperty Task("Systems requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.")

	try {
		$volumes = Get-BitLockerVolume -ErrorAction Stop
		$notProtected = $false

		foreach ( $volume in $volumes ) {
			if ( -not (($volume.VolumeStatus -eq "FullyEncrypted") -and ($volume.ProtectionStatus -eq "On")) ) {
				$notProtected = $true
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000280: Drive $($volume.MountPoint) not BitLocker protected" -Level Error
			}
		}

		if ( $notProtected ) {
			$obj | Add-Member NoteProperty Status("Bitlocker not enabled")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		$obj | Add-Member NoteProperty Status("Bitlocker not enabled")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000280: BitLocker not found on system" -Level Error
	}

	Write-Output $obj
}

function Test-SV-88165r1_rule_3 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88165r1_rule_3")
	$obj | Add-Member NoteProperty Task("Virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection (VirtualizationBasedSecurityStatus Running).")

	$vBSS = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard `
		| Select-Object -ExpandProperty VirtualizationBasedSecurityStatus

	# 2 indicates running
	if ($vBSS -eq 2) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Device Guard not running")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-CC-000110: Device Guard not running" -Level Error
	}

	Write-Output $obj
}


# Credential Guard running
function Test-SV-88167r1_rule_2 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88167r1_rule_2")
	$obj | Add-Member NoteProperty Task("Credential Guard must be running on domain-joined systems (SecurityServicesRunning).")

	try {
		$securityServices = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ErrorAction Stop -ExpandProperty SecurityServicesRunning

		if ($securityServices -contains 1) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Security services aren't running.")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch {
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-CC-000120: $($error[0])" -Level Error
	}

	Write-Output $obj
}

function Test-SV-88169r1_rule_2 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88169r1_rule_2")
	$obj | Add-Member NoteProperty Task("Virtualization-based protection of code integrity must be enabled on domain-joined systems (SecurityServicesRunning).")

	try {
		$securityServices = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ErrorAction Stop -ExpandProperty SecurityServicesRunning

		if ($securityServices -contains 2) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Not compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch {
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-CC-000130: $($error[0])" -Level Error
	}

	Write-Output $obj
}


# The built-in administrator account must be renamed.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000030
# Group ID (Vulid): V-73623
# CCI: CCI-000366
#
# The built-in administrator account is a well-known account subject to attack. Renaming this
# account to an unidentified name improves the protection of this account and the system.
function Test-SV-88287r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88287r1_rule")
	$obj | Add-Member NoteProperty Task("The built-in administrator account must be renamed.")

	try {
		# local admin account SID ends with 500
		$builtInAdmin = Get-localUser | Where-Object -Property sid -like "S-1-5-*-500"
		$otherAdmins = Get-LocalAdminNames | Where-Object { $_ -eq "Administrator" }

		if (($null -ne $builtInAdmin.Name) -and ($builtInAdmin.Name -ne "Administrator")) {
			if ($otherAdmins.Count -eq 0) {
				$obj | Add-Member NoteProperty Status("Compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
			}
			else {
				$obj | Add-Member NoteProperty Status("Built-in Administrator is renamed, but other account in the Administrators local group is named Administrator.")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::Warning)
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Built-in Administrator account is not renamed.")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-SO-000030: Cannot get local admin account info - $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The built-in guest account must be renamed.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000040
# Group ID (Vulid): V-73625
# CCI: CCI-000366
#
# The built-in guest account is a well-known user account on all Windows systems and, as initially
# installed, does not require a password. This can allow access to system resources by unauthorized
# users. Renaming this account to an unidentified name improves the protection of this account
# and the system.
function Test-SV-88289r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88289r1_rule")
	$obj | Add-Member NoteProperty Task("The built-in guest account must be renamed.")

	try {
		# local guest account SID ends with 501
		$account = Get-localUser | Where-Object -Property SID -like "S-1-5-*-501"

		if ( ($account.name -ne "Guest") -and ($null -ne $account.name) ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Built-in guest account not renamed.")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-SO-000040: Cannot get local guest account info - $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}


# The built-in guest account must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000010
# Group ID (Vulid): V-73809
# CCI: CCI-000804
#
# A system faces an increased vulnerability threat if the built-in guest account is not disabled.
# This is a known account that exists on all Windows systems and cannot be deleted. This account
# is initialized during the installation of the operating system with no password assigned.
#
function Test-SV-88475r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88475r1_rule")
	$obj | Add-Member NoteProperty Task("The built-in guest account must be disabled.")

	try {
		# local guest account SID ends with 501
		$account = Get-localUser | Where-Object -Property sid -like "S-1-5-*-501"

		if ( $account.Enabled -eq $false ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Built-in guest account is not disabled.")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-SO-000010: Cannot get local guest account info - $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

#endregion

#endregion

function New-AuditPipeline {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[scriptblock[]] $AuditFunctions
	)

	return {
		param(
			[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
			[hashtable] $AuditSetting
		)

		process {
			$auditSettingObj = New-Object -TypeName psobject -Property $AuditSetting

			foreach ($auditFunction in $AuditFunctions) {
				$audit = $auditSettingObj | & $auditFunction -Verbose:$VerbosePreference
				if ($audit -is [AuditInfo]) {
					return $audit
				}
			}
			return $null
		}
	}.GetNewClosure()
}

function Get-DisaAudit {
	[CmdletBinding()]
	Param(
		[switch] $PerformanceOptimized,

		# [string[]] $Exclude

		[switch] $RegistrySettings,

		[switch] $UserRights,

		[switch] $AccountPolicies,

		[switch] $WindowsFeatures,

		[switch] $FileSystemPermissions,

		[switch] $RegistryPermissions,

		[switch] $OtherAudits
	)

	# if ($PerformanceOptimized) {
	# 	$Exclude += "Test-SV-87923r1_rule","Test-SV-88423r1_rule","Test-SV-88427r1_rule",
	# }

	# disa registry settings
	if ($RegistrySettings) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-RegistryAudit}
		$DisaRequirements.RegistrySettings | PreprocessSpecialValueSetting |  &$pipline -Verbose:$VerbosePreference
	}
	# disa user rights
	if ($UserRights) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-UserRightPolicyAudit}
		$DisaRequirements.UserRights | &$pipline -Verbose:$VerbosePreference
	}
	# disa account policy
	if ($AccountPolicies) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-AccountPolicyAudit}
		$DisaRequirements.AccountPolicies | PreprocessSpecialValueSetting |  &$pipline -Verbose:$VerbosePreference
	}
	# disa windows features
	if ($WindowsFeatures) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-WindowsFeatureAudit}
		$DisaRequirements.WindowsFeatures | &$pipline -Verbose:$VerbosePreference
	}
	# disa file system permissions
	if ($FileSystemPermissions) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-FileSystemPermissionsAudit}
		$DisaRequirements.FileSystemPermissions | &$pipline -Verbose:$VerbosePreference
	}
	# disa registry permissions
	if ($RegistryPermissions) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-RegistryPermissionsAudit}
		$DisaRequirements.RegistryPermissions | &$pipline -Verbose:$VerbosePreference
	}
	
	if ($OtherAudits) {
		Test-SV-87875r2_rule   | Convert-ToAuditInfo
		Test-SV-87889r1_rule   | Convert-ToAuditInfo
		Test-SV-87891r1_rule   | Convert-ToAuditInfo
		Test-SV-87899r1_rule   | Convert-ToAuditInfo
		Test-SV-87909r1_rule   | Convert-ToAuditInfo
		Test-SV-87911r2_rule   | Convert-ToAuditInfo
		Test-SV-87913r2_rule   | Convert-ToAuditInfo
		Test-SV-87915r2_rule   | Convert-ToAuditInfo
		Test-SV-87919r1_rule   | Convert-ToAuditInfo
		if (-not ($PerformanceOptimized)) {
			Test-SV-87923r1_rule | Convert-ToAuditInfo
		}
		Test-SV-87925r1_rule   | Convert-ToAuditInfo
		Test-SV-88165r1_rule_3 | Convert-ToAuditInfo
		Test-SV-88167r1_rule_2 | Convert-ToAuditInfo
		if (-not ($PerformanceOptimized)) {
			Test-SV-88169r1_rule_2 | Convert-ToAuditInfo
		}
		Test-SV-88287r1_rule   | Convert-ToAuditInfo
		Test-SV-88289r1_rule   | Convert-ToAuditInfo
		Test-SV-88475r1_rule   | Convert-ToAuditInfo
	}
}

function Get-CisAudit {
	[CmdletBinding()]
	Param(
		[switch] $PerformanceOptimized,

		# [string[]] $Exclude

		[switch] $RegistrySettings,

		[switch] $UserRights,

		[switch] $AccountPolicies,

		[switch] $FirewallProfiles,

		[switch] $AuditPolicies
	)
	# cis registry settings
	if ($RegistrySettings) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-RegistryAudit}
		$CisBenchmarks.RegistrySettings | PreprocessSpecialValueSetting | &$pipline -Verbose:$VerbosePreference
	}
	# cis user rights
	if ($UserRights) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-UserRightPolicyAudit}
		$CisBenchmarks.UserRights | &$pipline -Verbose:$VerbosePreference
	}
	# cis account policies
	if ($AccountPolicies) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-AccountPolicyAudit}
		$CisBenchmarks.AccountPolicies | PreprocessSpecialValueSetting | &$pipline -Verbose:$VerbosePreference
	}
	# cis firewall profiles
	if ($FirewallProfiles) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-FirewallProfileAudit}
		$CisBenchmarks.FirewallProfileSettings | &$pipline -Verbose:$VerbosePreference
	}
	# cis audit policies
	if ($AuditPolicies) {
		$pipline = New-AuditPipeline ${Function:Get-RoleAudit}, ${Function:Get-AuditPolicyAudit}
		$CisBenchmarks.AuditPolicies | &$pipline -Verbose:$VerbosePreference
	}
}

#region Report-Generation
<#
	In this section the HTML report gets build and saved to the desired destination set by parameter saveTo
#>

function Get-HtmlReport {
	param (
		[string] $Path = "$($env:HOMEPATH)\Documents\$(Get-Date -UFormat %Y%m%d_%H%M)_auditreport.html",

		[switch] $DarkMode,

		[switch] $PerformanceOptimized
	)

	$parent = Split-Path $Path
	if (Test-Path $parent) {
		[hashtable[]]$sections = @(
			@{
				Title = "DISA Recommendations"
				Description = "This section contains all recommendations from the Windows Server 2016 Security Technical Implementation Guide V1R5 2018-07-27"
				SubSections = @(
					@{
						Title = "Registry Settings/Group Policies"
						AuditInfos = Get-DisaAudit -RegistrySettings | Sort-Object -Property Id
					},
					@{
						Title = "User Rights Assignment"
						AuditInfos = Get-DisaAudit -UserRights | Sort-Object -Property Id
					},
					@{
						Title = "Account Policies"
						AuditInfos = Get-DisaAudit -AccountPolicies | Sort-Object -Property Id
					},
					@{
						Title = "Windows Features"
						AuditInfos = Get-DisaAudit -WindowsFeatures | Sort-Object -Property Id
					},
					@{
						Title = "File System Permissions"
						AuditInfos = Get-DisaAudit -FileSystemPermissions | Sort-Object -Property Id
					},
					
					@{
						Title = "Registry Permissions"
						AuditInfos = Get-DisaAudit -RegistryPermissions | Sort-Object -Property Id
					},
					@{
						Title = "Other"
						AuditInfos = Get-DisaAudit -OtherAudits -PerformanceOptimized:$PerformanceOptimized | Sort-Object -Property Id
					}
				)
			},
			@{
				Title = "CIS Benchmarks"
				Description = "This section contains all benchmarks from CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0 - 03-31-2017. WARNING: Tests in this version haven't been fully tested yet."
				SubSections = @(
					@{
						Title = "Registry Settings/Group Policies"
						AuditInfos = Get-CisAudit -RegistrySettings # | Sort-Object -Property Id
					}
					@{
						Title = "User Rights Assignment"
						AuditInfos = Get-CisAudit -UserRights | Sort-Object -Property Id
					}
					@{
						Title = "Account Policies"
						AuditInfos = Get-CisAudit -AccountPolicies | Sort-Object -Property Id
					}
					@{
						Title = "Windows Firewall with Advanced Security"
						AuditInfos = Get-CisAudit -FirewallProfiles | Sort-Object -Property Id
					}
					@{
						Title = " Advanced Audit Policy Configuration"
						AuditInfos = Get-CisAudit -AuditPolicies | Sort-Object -Property Id
					}
				)
			}
		)

		Get-ATAPHtmlReport `
			-Path $Path `
			-Title "Windows Server 2016 Audit Report" `
			-ModuleName "WindowsServer2016Audit" `
			-BasedOn "Windows Server 2016 Security Technical Implementation Guide V1R5 2018-07-27", "CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0 - 03-31-2017" `
			-Sections $sections `
			-DarkMode:$DarkMode
	}
	else {
		Write-Error "The path doesn't not exist!"
	}
}

Set-Alias -Name Get-WindowsServer2016HtmlReport -Value Get-HtmlReport
#endregion