<#
BSD 3-Clause License

Copyright (c) 2018, FB Pro GmbH
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

<#

Author(s):   Dennis Esly, Benedikt Böhme
Date:        2018-05-31
Last Change: 2018-08-20

#>

using module ATAPHtmlReport

# Import setting from file
$Settings = Import-LocalizedData -FileName "Settings.psd1"

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
function Get-SecPolSetting {
	<#
.Synopsis
	Wrapper for the cmdline tool secedit.exe.
.DESCRIPTION
	Converts one or many PSCustomObject Testresult to a html table with one result per row.
	Newlines are converted into <br> (only in status column!)
#>
	[CmdletBinding()]
	Param(
		[Parameter(ParameterSetName = 'SystemAccess')]
		[switch]$SystemAccess,

		[Parameter(ParameterSetName = 'SystemAccess', Mandatory = $true)]
		[ValidateSet('MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount',
			'LockoutDuration', 'RequireLogonToChangePassword', 'ForceLogoffWhenHourExpire', 'NewAdministratorName', 'NewGuestName', 'ClearTextPassword',
			'LSAAnonymousNameLookup', 'EnableAdminAccount', 'EnableGuestAccount')]
		[String]$SystemAccessSetting,

		[Parameter(ParameterSetName = 'PriviligeRights')]
		[switch]$PrivilegeRights,

		[Parameter(ParameterSetName = 'PriviligeRights', Mandatory = $true)]
		[validateSet('SeNetworkLogonRight', 'SeTcbPrivilege', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeSystemtimePrivilege', 'SeCreatePagefilePrivilege', 'SeDebugPrivilege',
			'SeRemoteShutdownPrivilege', 'SeAuditPrivilege', 'SeIncreaseQuotaPrivilege', 'SeLoadDriverPrivilege', 'SeBatchLogonRight', 'SeServiceLogonRight',
			'SeInteractiveLogonRight', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeProfileSingleProcessPrivilege', 'SeSystemProfilePrivilege',
			'SeAssignPrimaryTokenPrivilege', 'SeTakeOwnershipPrivilege', 'SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight',
			'SeDenyInteractiveLogonRight', 'SeUndockPrivilege', 'SeManageVolumePrivilege', 'SeRemoteInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
			'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege',
			'SeDelegateSessionUserImpersonatePrivilege', 'SeCreateTokenPrivilege', 'SeCreatePermanentPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeLockMemoryPrivilege',
			'SeRestorePrivilege', 'SeTrustedCredManAccessPrivilege', 'SeEnableDelegationPrivilege')]
		[String]$PrivilegeRightsSetting

	)

	# get a temporary file to save and process the secedit settings
	Write-Verbose -Message "Get temporary file"
	$tmp = [System.IO.Path]::GetTempFileName()
	Write-Verbose -Message "Tempory file: $tmp"

	# export the secedit settings to this temporary file
	Write-Verbose "Export current Local Security Policy"
	secedit.exe /export /cfg "$($tmp)" | Out-Null

	# load the settings from the temporary file
	$securitySettings = Get-Content -Path $tmp

	$currentSetting = ""

	# go through the file content line by line and check the setting we are dealing with
	foreach ($line in $securitySettings) {

		# Account Policy settings
		if ($SystemAccess) {
			if ( $line -like "$SystemAccessSetting*" ) {
				$x = $line.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)
				$currentSetting = $x[1].Trim()
				Write-Verbose "Found System Access setting: $SystemAccessSetting::$currentSetting"
				break
			}
		}

		# User Rights Assignment settings
		if ($PrivilegeRights) {
			if ( $line -like "$PrivilegeRightsSetting*" ) {
				$x = $line.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)
				$currentSetting = $x[1].Trim()
				Write-Verbose "Found Privilige Rights setting: $PrivilegeRightsSetting::$currentSetting"
				break
			}
		}
	}

	Write-Output $currentSetting
}

function Test-DomainMember {
	return (Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
}

function Test-DomainController {
	$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole

	return $domainRole -eq 4 -or $domainRole -eq 5
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

	# Get domain role
	# 0 {"Standalone Workstation"}
	# 1 {"Member Workstation"}
	# 2 {"Standalone Server"}
	# 3 {"Member Server"}
	# 4 {"Backup Domain Controller"}
	# 5 {"Primary Domain Controller"}
	[int]$domainRole = Get-CimInstance Win32_ComputerSystem | Select-Object -Expand DomainRole
	[bool]$isDomainMember = ($domainRole -ne 0) -and ($domainRole -ne 2)

	if ($isDomainMember) {

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

function Convert-ToAuditInfo {
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Psobject] $auditObject
	)

	process {
		Write-Output (New-Object -TypeName AuditInfo -Property @{
			Id      = $auditObject.Name
			Task    = $auditObject.Task
			Message = $auditObject.Status
			Audit   = $auditObject.Passed
		})
	}
}

function Test-RegistrySetting {
	param(
		[Parameter(Mandatory = $true)]
		[PSObject] $obj,
		[Parameter(Mandatory = $true)]
		[string] $StigId,
		[Parameter(Mandatory = $true)]
		[string] $Path,
		[Parameter(Mandatory = $true)]
		[string] $Name,
		[Parameter(Mandatory = $true)]
		$ExpectedValue,

		[Parameter(ParameterSetName = "WithPredicate")]
		[Scriptblock] $Predicate
	)

	if ($PSCmdlet.ParameterSetName -ne "WithPredicate") {
		$Predicate = { param($value) $value -eq $ExpectedValue }
	}

	try {
		$regValue = Get-ItemProperty -ErrorAction Stop -Path $Path -Name $Name `
			| Select-Object -ExpandProperty $Name

		if (& $Predicate $regValue) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Registry value: $regValue. Differs from expected value: $ExpectedValue.")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
				-Message "${$StigId}: Registry value $Name in registry key $Path is not correct."
		}
	}
	catch [System.Management.Automation.PSArgumentException] {
		$obj | Add-Member NoteProperty Status("Registry value not found.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
			-Message "${$StigId}: Could not get value $Name in registry key $path."
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		$obj | Add-Member NoteProperty Status("Registry key not found.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
			-Message "${$StigId}: Could not get key $Name in registry key $path."
	}

	return $obj
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

#region Registry test

# Administrator accounts must not be enumerated during elevation.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000280
# Group ID (Vulid): V-73487
# CCI: CCI-001084
#
# Enumeration of administrator accounts when elevating can provide part of the logon information
# to an unauthorized user. This setting configures the system to always require users to type
# in a username and password to elevate a running application.
function Test-SV-88139r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88139r1_rule")
	$obj | Add-Member NoteProperty Task("Administrator accounts must not be enumerated during elevation.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000280" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" `
		-Name "EnumerateAdministrators" `
		-ExpectedValue 0 `
	| Write-Output
}

# Local administrator accounts must have their privileged token filtered to prevent elevated
# privileges from being used over the network on domain systems.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000020
# Group ID (Vulid): V-73495
# CCI: CCI-001084
#
# A compromised local administrator account can provide means for an attacker to move laterally
# between domain systems.With User Account Control enabled, filtering the privileged token
# for local administrator accounts will prevent the elevated privileges of these accounts
# from being used over the network.
function Test-SV-88147r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88147r1_rule")
	$obj | Add-Member NoteProperty Task("Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-MS-000020" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
		-Name "LocalAccountTokenFilterPolicy" `
		-ExpectedValue 0 `
	| Write-Output
}

# WDigest Authentication must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000030
# Group ID (Vulid): V-73497
# CCI: CCI-000381
#
# When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the
# Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled
# by default in Windows 10. This setting ensures this is enforced.
function Test-SV-88149r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88149r1_rule")
	$obj | Add-Member NoteProperty Task("WDigest Authentication must be disabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000030" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" `
		-Name "UseLogonCredential" `
		-ExpectedValue 0 `
	| Write-Output
}

# Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection
# level to prevent IP source routing.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000040
# Group ID (Vulid): V-73499
# CCI: CCI-000366
#
# Configuring the system to disable IPv6 source routing protects against spoofing.
function Test-SV-88151r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88151r1_rule")
	$obj | Add-Member NoteProperty Task("Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000040" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" `
		-Name "DisableIPSourceRouting" `
		-ExpectedValue 2 `
	| Write-Output
}

# Source routing must be configured to the highest protection level to prevent Internet Protocol
# (IP) source routing.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000050
# Group ID (Vulid): V-73501
# CCI: CCI-000366
#
# Configuring the system to disable IP source routing protects against spoofing.
function Test-SV-88153r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88153r1_rule")
	$obj | Add-Member NoteProperty Task("Source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000050" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" `
		-Name "DisableIPSourceRouting" `
		-ExpectedValue 2 `
	| Write-Output
}

# Windows Server 2016 must be configured to prevent Internet Control Message Protocol (ICMP)
# redirects from overriding Open Shortest Path First (OSPF)-generated routes.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000060
# Group ID (Vulid): V-73503
# CCI: CCI-000366
#
# Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled,
# this forces ICMP to be routed via the shortest path first.
function Test-SV-88155r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88155r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000060" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" `
		-Name "EnableICMPRedirect" `
		-ExpectedValue 0 `
	| Write-Output
}

# Windows Server 2016 must be configured to ignore NetBIOS name release requests except from
# WINS servers.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000070
# Group ID (Vulid): V-73505
# CCI: CCI-002385
#
# Configuring the system to ignore name release requests, except from WINS servers, prevents
# a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request
# to the server for each entry in the servers cache, causing a response delay in the normal
# operation of the servers WINS resolution capability.
function Test-SV-88157r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88157r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to ignore NetBIOS name release requests except from WINS servers.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000070" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" `
		-Name "NoNameReleaseOnDemand" `
		-ExpectedValue 1 `
	| Write-Output
}

# Insecure logons to an SMB server must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000080
# Group ID (Vulid): V-73507
# CCI: CCI-000366
#
# Insecure guest logons allow unauthenticated access to shared folders. Shared resources on
# a system must require authentication to establish proper access.
function Test-SV-88159r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88159r1_rule")
	$obj | Add-Member NoteProperty Task("Insecure logons to an SMB server must be disabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000080" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" `
		-Name "AllowInsecureGuestAuth" `
		-ExpectedValue 0 `
	| Write-Output
}

# Command line data must be included in process creation events.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000100
# Group ID (Vulid): V-73511
# CCI: CCI-000135
#
# Maintaining an audit trail of system activity logs can help identify configuration errors,
# troubleshoot service disruptions, and analyze compromises that have occurred, as well as
# detect attacks. Audit logs are necessary to provide a trail of evidence in case the system
# or network is compromised. Collecting this data is essential for analyzing the security
# of information assets and detecting signs of suspicious and unexpected behavior.Enabling
# Include command line data for process creation events will record the command line information
# with the process creation events in the log. This can provide additional detail when malware
# has run on a system.
function Test-SV-88163r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88163r1_rule")
	$obj | Add-Member NoteProperty Task("Command line data must be included in process creation events.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000100" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" `
		-Name "ProcessCreationIncludeCmdLine_Enabled" `
		-ExpectedValue 1 `
	| Write-Output
}

# Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers
# identified as bad.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000140
# Group ID (Vulid): V-73521
# CCI: CCI-000366
#
# Compromised boot drivers can introduce malware prior to protection mechanisms that load after
# initialization. The Early Launch Antimalware driver can limit allowed drivers based on classifications
# determined by the malware protection application. At a minimum, drivers determined to be
# bad must not be allowed.
function Test-SV-88173r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88173r1_rule")
	$obj | Add-Member NoteProperty Task("Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000140" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" `
		-Name "DriverLoadPolicy" `
		-ExpectedValue 8 `
	| Write-Output
}

# Group Policy objects must be reprocessed even if they have not changed.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000150
# Group ID (Vulid): V-73525
# CCI: CCI-000366
#
# Registry entries for group policy settings can potentially be changed from the required configuration.
# This could occur as part of troubleshooting or by a malicious process on a compromised system.
# Enabling this setting and then Select-Objecting the Process even if the Group Policy objects have
# not changed option ensures the policies will be reprocessed even if none have been changed.
# This way, any unauthorized changes are forced to match the domain-based group policy settings
# again.
function Test-SV-88177r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88177r1_rule")
	$obj | Add-Member NoteProperty Task("Group Policy objects must be reprocessed even if they have not changed.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000150" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" `
		-Name "NoGPOListChanges" `
		-ExpectedValue 0 `
	| Write-Output
}

# Downloading print driver packages over HTTP must be prevented.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000160
# Group ID (Vulid): V-73527
# CCI: CCI-000381
#
# Some features may communicate with the vendor, sending system information or downloading
# data or components for the feature. Turning off this capability will prevent potentially
# sensitive information from being sent outside the enterprise and will prevent uncontrolled
# updates to the system. This setting prevents the computer from downloading print driver
# packages over HTTP.
function Test-SV-88179r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88179r1_rule")
	$obj | Add-Member NoteProperty Task("Downloading print driver packages over HTTP must be prevented.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000160" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" `
		-Name "DisableWebPnPDownload" `
		-ExpectedValue 1 `
	| Write-Output
}

# Printing over HTTP must be prevented.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000170
# Group ID (Vulid): V-73529
# CCI: CCI-000381
#
# Some features may communicate with the vendor, sending system information or downloading
# data or components for the feature. Turning off this capability will prevent potentially
# sensitive information from being sent outside the enterprise and will prevent uncontrolled
# updates to the system.This setting prevents the client computer from printing over HTTP,
# which allows the computer to print to printers on the intranet as well as the Internet.
function Test-SV-88181r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88181r1_rule")
	$obj | Add-Member NoteProperty Task("Printing over HTTP must be prevented.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000170" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" `
		-Name "DisableHTTPPrinting" `
		-ExpectedValue 1 `
	| Write-Output
}

# The network Select-Objection user interface (UI) must not be displayed on the logon screen.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000180
# Group ID (Vulid): V-73531
# CCI: CCI-000381
#
# Enabling interaction with the network Select-Objection UI allows users to change connections to
# available networks without signing in to Windows.
function Test-SV-88185r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88185r1_rule")
	$obj | Add-Member NoteProperty Task("The network selection user interface (UI) must not be displayed on the logon screen.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000180" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" `
		-Name "DontDisplayNetworkSelectionUI" `
		-ExpectedValue 1 `
	| Write-Output
}

# Local users on domain-joined computers must not be enumerated.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000030
# Group ID (Vulid): V-73533
# CCI: CCI-000381
#
# The username is one part of logon credentials that could be used to gain access to a system.
# Preventing the enumeration of users limits this information to authorized personnel.
function Test-SV-88187r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88187r1_rule")
	$obj | Add-Member NoteProperty Task("Local users on domain-joined computers must not be enumerated.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-MS-000030" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" `
		-Name "EnumerateLocalUsers" `
		-ExpectedValue 0 `
	| Write-Output
}

# Windows Server 2016 must be configured to block untrusted fonts from loading.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000200
# Group ID (Vulid): V-73535
# CCI: CCI-000366
#
# Attackers may use fonts that include malicious code to compromise a system. This setting
# will prevent untrusted fonts, processed by the Graphics Device Interface (GDI), from loading
# if installed outside of the %windir%/Fonts directory.
function Test-SV-88189r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88189r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to block untrusted fonts from loading.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000200" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" `
		-Name "MitigationOptions_FontBocking" `
		-ExpectedValue "1000000000000" `
	| Write-Output
}

# Users must be prompted to authenticate when the system wakes from sleep (on battery).
# - - - - - - - - - - - - -
# StigID: WN16-CC-000210
# Group ID (Vulid): V-73537
# CCI: CCI-000366
#
# A system that does not require authentication when resuming from sleep may provide access
# to unauthorized users. Authentication must always be required when accessing a system. This
# setting ensures users are prompted for a password when the system wakes from sleep (on battery).
#
function Test-SV-88197r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88197r1_rule")
	$obj | Add-Member NoteProperty Task("Users must be prompted to authenticate when the system wakes from sleep (on battery).")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000210" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" `
		-Name "DCSettingIndex" `
		-ExpectedValue 1 `
	| Write-Output
}

# Users must be prompted to authenticate when the system wakes from sleep (plugged in).
# - - - - - - - - - - - - -
# StigID: WN16-CC-000220
# Group ID (Vulid): V-73539
# CCI: CCI-000366
#
# A system that does not require authentication when resuming from sleep may provide access
# to unauthorized users. Authentication must always be required when accessing a system. This
# setting ensures users are prompted for a password when the system wakes from sleep (plugged
# in).
function Test-SV-88201r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88201r1_rule")
	$obj | Add-Member NoteProperty Task("Users must be prompted to authenticate when the system wakes from sleep (plugged in).")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000220" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" `
		-Name "ACSettingIndex" `
		-ExpectedValue 1 `
	| Write-Output
}

# Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to
# the RPC server.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000040
# Group ID (Vulid): V-73541
# CCI: CCI-001967
#
# Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring
# RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent
# anonymous connections.
function Test-SV-88203r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88203r1_rule")
	$obj | Add-Member NoteProperty Task("Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-MS-000040" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" `
		-Name "RestrictRemoteClients" `
		-ExpectedValue 1 `
	| Write-Output
}

# The Application Compatibility Program Inventory must be prevented from collecting data and
# sending the information to Microsoft.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000240
# Group ID (Vulid): V-73543
# CCI: CCI-000381
#
# Some features may communicate with the vendor, sending system information or downloading
# data or components for the feature. Turning off this capability will prevent potentially
# sensitive information from being sent outside the enterprise and will prevent uncontrolled
# updates to the system.This setting will prevent the Program Inventory from collecting data
# about a system and sending the information to Microsoft.
function Test-SV-88207r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88207r1_rule")
	$obj | Add-Member NoteProperty Task("The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000240" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" `
		-Name "DisableInventory" `
		-ExpectedValue 1 `
	| Write-Output
}

# AutoPlay must be turned off for non-volume devices.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000250
# Group ID (Vulid): V-73545
# CCI: CCI-001764
#
# Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading
# from a drive as soon as media is inserted into the drive. As a result, the setup file of
# programs or music on audio media may start. This setting will disable AutoPlay for non-volume
# devices, such as Media Transfer Protocol (MTP) devices.
function Test-SV-88209r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88209r1_rule")
	$obj | Add-Member NoteProperty Task("AutoPlay must be turned off for non-volume devices.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000250" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" `
		-Name "NoAutoplayfornonVolume" `
		-ExpectedValue 1 `
	| Write-Output
}

# The default AutoRun behavior must be configured to prevent AutoRun commands.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000260
# Group ID (Vulid): V-73547
# CCI: CCI-001764
#
# Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring
# this setting prevents AutoRun commands from executing.
function Test-SV-88211r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88211r1_rule")
	$obj | Add-Member NoteProperty Task("The default AutoRun behavior must be configured to prevent AutoRun commands.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000260" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" `
		-Name "NoAutorun" `
		-ExpectedValue 1 `
	| Write-Output
}

# AutoPlay must be disabled for all drives.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000270
# Group ID (Vulid): V-73549
# CCI: CCI-001764
#
# Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading
# from a drive as soon media is inserted into the drive. As a result, the setup file of programs
# or music on audio media may start. By default, AutoPlay is disabled on removable drives,
# such as the floppy disk drive (but not the CD-ROM drive) and on network drives. Enabling
# this policy disables AutoPlay on all drives.
function Test-SV-88213r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88213r1_rule")
	$obj | Add-Member NoteProperty Task("AutoPlay must be disabled for all drives.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000270" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" `
		-Name "NoDriveTypeAutoRun" `
		-ExpectedValue 255 `
	| Write-Output
}

# Windows Telemetry must be configured to Security or Basic.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000290
# Group ID (Vulid): V-73551
# CCI: CCI-000366
#
# Some features may communicate with the vendor, sending system information or downloading
# data or components for the feature. Limiting this capability will prevent potentially sensitive
# information from being sent outside the enterprise. The Security option for Telemetry configures
# the lowest amount of data, effectively none outside of the Malicious Software Removal Tool
# (MSRT), Defender, and telemetry client settings. Basic sends basic diagnostic and usage
# data and may be required to support some Microsoft services.
function Test-SV-88215r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88215r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Telemetry must be configured to Security or Basic.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000290" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" `
		-Name "AllowTelemetry" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Application event log size must be configured to 32768 KB or greater.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000300
# Group ID (Vulid): V-73553
# CCI: CCI-001849
#
# Inadequate log size will cause the log to fill up quickly. This may prevent audit events
# from being recorded properly and require frequent attention by administrative personnel.
#
function Test-SV-88217r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88217r1_rule")
	$obj | Add-Member NoteProperty Task("The Application event log size must be configured to 32768 KB or greater.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000300" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" `
		-Name "MaxSize" `
		-ExpectedValue 32768 `
	| Write-Output
}

# The Security event log size must be configured to 196608 KB or greater.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000310
# Group ID (Vulid): V-73555
# CCI: CCI-001849
#
# Inadequate log size will cause the log to fill up quickly. This may prevent audit events
# from being recorded properly and require frequent attention by administrative personnel.
#
function Test-SV-88219r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88219r1_rule")
	$obj | Add-Member NoteProperty Task("The Security event log size must be configured to 196608 KB or greater.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000310" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" `
		-Name "MaxSize" `
		-ExpectedValue 196608 `
	| Write-Output
}

# The System event log size must be configured to 32768 KB or greater.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000320
# Group ID (Vulid): V-73557
# CCI: CCI-001849
#
# Inadequate log size will cause the log to fill up quickly. This may prevent audit events
# from being recorded properly and require frequent attention by administrative personnel.
#
function Test-SV-88221r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88221r1_rule")
	$obj | Add-Member NoteProperty Task("The System event log size must be configured to 32768 KB or greater.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000320" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" `
		-Name "MaxSize" `
		-ExpectedValue 32768 `
	| Write-Output
}

# Windows SmartScreen must be enabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000330
# Group ID (Vulid): V-73559
# CCI: CCI-000381
#
# Windows SmartScreen helps protect systems from programs downloaded from the internet that
# may be malicious. Enabling SmartScreen will warn users of potentially malicious programs.
#
function Test-SV-88223r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88223r1_rule")
	$obj | Add-Member NoteProperty Task("Windows SmartScreen must be enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000330" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" `
		-Name "EnableSmartScreen" `
		-ExpectedValue 1 `
	| Write-Output
}

# Explorer Data Execution Prevention must be enabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000340
# Group ID (Vulid): V-73561
# CCI: CCI-002824
#
# Data Execution Prevention provides additional protection by performing checks on memory to
# help prevent malicious code from running. This setting will prevent Data Execution Prevention
# from being turned off for File Explorer.
function Test-SV-88225r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88225r1_rule")
	$obj | Add-Member NoteProperty Task("Explorer Data Execution Prevention must be enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000340" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" `
		-Name "NoDataExecutionPrevention" `
		-ExpectedValue 0 `
	| Write-Output
}

# Turning off File Explorer heap termination on corruption must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000350
# Group ID (Vulid): V-73563
# CCI: CCI-000366
#
# Legacy plug-in applications may continue to function when a File Explorer session has become
# corrupt. Disabling this feature will prevent this.
function Test-SV-88227r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88227r1_rule")
	$obj | Add-Member NoteProperty Task("Turning off File Explorer heap termination on corruption must be disabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000350" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" `
		-Name "NoHeapTerminationOnCorruption" `
		-ExpectedValue 0 `
	| Write-Output
}

# File Explorer shell protocol must run in protected mode.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000360
# Group ID (Vulid): V-73565
# CCI: CCI-000366
#
# The shell protocol will limit the set of folders that applications can open when run in protected
# mode. Restricting files an application can open to a limited set of folders increases the
# security of Windows.
function Test-SV-88229r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88229r1_rule")
	$obj | Add-Member NoteProperty Task("File Explorer shell protocol must run in protected mode.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000360" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" `
		-Name "PreXPSP2ShellProtocolBehavior" `
		-ExpectedValue 0 `
	| Write-Output
}

# Passwords must not be saved in the Remote Desktop Client.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000370
# Group ID (Vulid): V-73567
# CCI: CCI-002038
#
# Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish
# a remote desktop session to another system. The system must be configured to prevent users
# from saving passwords in the Remote Desktop Client.Satisfies: SRG-OS-000373-GPOS-00157,
# SRG-OS-000373-GPOS-00156
function Test-SV-88231r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88231r1_rule")
	$obj | Add-Member NoteProperty Task("Passwords must not be saved in the Remote Desktop Client.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000370" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" `
		-Name "DisablePasswordSaving" `
		-ExpectedValue 1 `
	| Write-Output
}

# Local drives must be prevented from sharing with Remote Desktop Session Hosts.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000380
# Group ID (Vulid): V-73569
# CCI: CCI-001090
#
# Preventing users from sharing the local drives on their client computers with Remote Session
# Hosts that they access helps reduce possible exposure of sensitive data.
function Test-SV-88233r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88233r1_rule")
	$obj | Add-Member NoteProperty Task("Local drives must be prevented from sharing with Remote Desktop Session Hosts.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000380" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" `
		-Name "fDisableCdm" `
		-ExpectedValue 1 `
	| Write-Output
}

# Remote Desktop Services must always prompt a client for passwords upon connection.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000390
# Group ID (Vulid): V-73571
# CCI: CCI-002038
#
# This setting controls the ability of users to supply passwords automatically as part of their
# remote desktop connection. Disabling this setting would allow anyone to use the stored credentials
# in a connection item to connect to the terminal server.Satisfies: SRG-OS-000373-GPOS-00157,
# SRG-OS-000373-GPOS-00156
function Test-SV-88235r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88235r1_rule")
	$obj | Add-Member NoteProperty Task("Remote Desktop Services must always prompt a client for passwords upon connection.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000390" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" `
		-Name "fPromptForPassword" `
		-ExpectedValue 1 `
	| Write-Output
}

# The Remote Desktop Session Host must require secure Remote Procedure Call (RPC) communications.
#
# - - - - - - - - - - - - -
# StigID: WN16-CC-000400
# Group ID (Vulid): V-73573
# CCI: CCI-001453
#
# Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data
# disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets
# between a client and server and modifies them before allowing the packets to be exchanged.
# Usually the attacker will modify the information in the packets in an attempt to cause either
# the client or server to reveal sensitive information.
function Test-SV-88237r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88237r1_rule")
	$obj | Add-Member NoteProperty Task("The Remote Desktop Session Host must require secure Remote Procedure Call (RPC) communications.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000400" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" `
		-Name "fEncryptRPCTraffic" `
		-ExpectedValue 1 `
	| Write-Output
}

# Remote Desktop Services must be configured with the client connection encryption set to High
# Level.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000410
# Group ID (Vulid): V-73575
# CCI: CCI-001453
#
# Remote connections must be encrypted to prevent interception of data or sensitive information.
# Select-Objecting High Level will ensure encryption of Remote Desktop Services sessions in both
# directions.
function Test-SV-88239r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88239r1_rule")
	$obj | Add-Member NoteProperty Task("Remote Desktop Services must be configured with the client connection encryption set to High Level.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000410" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" `
		-Name "MinEncryptionLevel" `
		-ExpectedValue 3 `
	| Write-Output
}

# Attachments must be prevented from being downloaded from RSS feeds.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000420
# Group ID (Vulid): V-73577
# CCI: CCI-000366
#
# Attachments from RSS feeds may not be secure. This setting will prevent attachments from
# being downloaded from RSS feeds.
function Test-SV-88241r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88241r1_rule")
	$obj | Add-Member NoteProperty Task("Attachments must be prevented from being downloaded from RSS feeds.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000420" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" `
		-Name "DisableEnclosureDownload" `
		-ExpectedValue 1 `
	| Write-Output
}

# Basic authentication for RSS feeds over HTTP must not be used.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000430
# Group ID (Vulid): V-73579
# CCI: CCI-000381
#
# Basic authentication uses plain-text passwords that could be used to compromise a system.
# Disabling Basic authentication will reduce this potential.
function Test-SV-88243r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88243r1_rule")
	$obj | Add-Member NoteProperty Task("Basic authentication for RSS feeds over HTTP must not be used.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000430" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" `
		-Name "AllowBasicAuthInClear" `
		-ExpectedValue 0 `
	| Write-Output
}

# Indexing of encrypted files must be turned off.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000440
# Group ID (Vulid): V-73581
# CCI: CCI-000381
#
# Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files
# from being indexed.
function Test-SV-88245r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88245r1_rule")
	$obj | Add-Member NoteProperty Task("Indexing of encrypted files must be turned off.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000440" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" `
		-Name "AllowIndexingEncryptedStoresOrItems" `
		-ExpectedValue 0 `
	| Write-Output
}

# Users must be prevented from changing installation options.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000450
# Group ID (Vulid): V-73583
# CCI: CCI-001812
#
# Installation options for applications are typically controlled by administrators. This setting
# prevents users from changing installation options that may bypass security features.
function Test-SV-88247r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88247r1_rule")
	$obj | Add-Member NoteProperty Task("Users must be prevented from changing installation options.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000450" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" `
		-Name "EnableUserControl" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Windows Installer Always install with elevated privileges option must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000460
# Group ID (Vulid): V-73585
# CCI: CCI-001812
#
# Standard user accounts must not be granted elevated privileges. Enabling Windows Installer
# to elevate privileges when installing applications can allow malicious persons and applications
# to gain full control of a system.
function Test-SV-88249r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88249r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Installer Always install with elevated privileges option must be disabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000460" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" `
		-Name "AlwaysInstallElevated" `
		-ExpectedValue 0 `
	| Write-Output
}

# Users must be notified if a web-based program attempts to install software.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000470
# Group ID (Vulid): V-73587
# CCI: CCI-000366
#
# Web-based programs may attempt to install malicious software on a system. Ensuring users
# are notified if a web-based program attempts to install software allows them to refuse the
# installation.
function Test-SV-88251r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88251r1_rule")
	$obj | Add-Member NoteProperty Task("Users must be notified if a web-based program attempts to install software.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000470" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" `
		-Name "SafeForScripting" `
		-ExpectedValue 0 `
	| Write-Output
}

# Automatically signing in the last interactive user after a system-initiated restart must
# be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000480
# Group ID (Vulid): V-73589
# CCI: CCI-000366
#
# Windows can be configured to automatically sign the user back in after a Windows Update restart.
# Some protections are in place to help ensure this is done in a secure fashion; however,
# disabling this will prevent the caching of credentials for this purpose and also ensure
# the user is aware of the restart.
function Test-SV-88253r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88253r1_rule")
	$obj | Add-Member NoteProperty Task("Automatically signing in the last interactive user after a system-initiated restart must be disabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000480" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "DisableAutomaticRestartSignOn" `
		-ExpectedValue 1 `
	| Write-Output
}

# PowerShell script block logging must be enabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000490
# Group ID (Vulid): V-73591
# CCI: CCI-000135
#
# Maintaining an audit trail of system activity logs can help identify configuration errors,
# troubleshoot service disruptions, and analyze compromises that have occurred, as well as
# detect attacks. Audit logs are necessary to provide a trail of evidence in case the system
# or network is compromised. Collecting this data is essential for analyzing the security
# of information assets and detecting signs of suspicious and unexpected behavior.Enabling
# PowerShell script block logging will record detailed information from the processing of
# PowerShell commands and scripts. This can provide additional detail when malware has run
# on a system.
function Test-SV-88255r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88255r1_rule")
	$obj | Add-Member NoteProperty Task("PowerShell script block logging must be enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000490" `
		-Path "HKLM:\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" `
		-Name "EnableScriptBlockLogging" `
		-ExpectedValue 1 `
	| Write-Output
}

# The Windows Remote Management (WinRM) client must not use Basic authentication.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000500
# Group ID (Vulid): V-73593
# CCI: CCI-000877
#
# Basic authentication uses plain-text passwords that could be used to compromise a system.
# Disabling Basic authentication will reduce this potential.
function Test-SV-88257r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88257r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Remote Management (WinRM) client must not use Basic authentication.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000500" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" `
		-Name "AllowBasic" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000510
# Group ID (Vulid): V-73595
# CCI: CCI-002890 CCI-003123
#
# Unencrypted remote access to a system can allow sensitive information to be compromised.
# Windows remote management connections must be encrypted to prevent this.Satisfies: SRG-OS-000393-GPOS-00173,
# SRG-OS-000394-GPOS-00174
function Test-SV-88259r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88259r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Remote Management (WinRM) client must not allow unencrypted traffic.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000510" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" `
		-Name "AllowUnencryptedTraffic" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Windows Remote Management (WinRM) client must not use Digest authentication.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000520
# Group ID (Vulid): V-73597
# CCI: CCI-000877
#
# Digest authentication is not as strong as other options and may be subject to man-in-the-middle
# attacks. Disallowing Digest authentication will reduce this potential.
function Test-SV-88261r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88261r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Remote Management (WinRM) client must not use Digest authentication.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000520" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" `
		-Name "AllowDigest" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Windows Remote Management (WinRM) service must not use Basic authentication.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000530
# Group ID (Vulid): V-73599
# CCI: CCI-000877
#
# Basic authentication uses plain-text passwords that could be used to compromise a system.
# Disabling Basic authentication will reduce this potential.
function Test-SV-88263r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88263r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Remote Management (WinRM) service must not use Basic authentication.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000530" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" `
		-Name "AllowBasic" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000540
# Group ID (Vulid): V-73601
# CCI: CCI-002890 CCI-003123
#
# Unencrypted remote access to a system can allow sensitive information to be compromised.
# Windows remote management connections must be encrypted to prevent this.Satisfies: SRG-OS-000393-GPOS-00173,
# SRG-OS-000394-GPOS-00174
function Test-SV-88265r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88265r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Remote Management (WinRM) service must not allow unencrypted traffic.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000540" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" `
		-Name "AllowUnencryptedTraffic" `
		-ExpectedValue 0 `
	| Write-Output
}

# The Windows Remote Management (WinRM) service must not store RunAs credentials.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000550
# Group ID (Vulid): V-73603
# CCI: CCI-002038
#
# Storage of administrative credentials could allow unauthorized access. Disallowing the storage
# of RunAs credentials for Windows Remote Management will prevent them from being used with
# plug-ins.Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
function Test-SV-88267r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88267r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows Remote Management (WinRM) service must not store RunAs credentials.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000550" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" `
		-Name "DisableRunAs" `
		-ExpectedValue 1 `
	| Write-Output
}

# Local accounts with blank passwords must be restricted to prevent access from the network.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000020
# Group ID (Vulid): V-73621
# CCI: CCI-000366
#
# An account without a password can allow unauthorized access to a system as only the username
# would be required. Password policies should prevent accounts with blank passwords from existing
# on a system. However, if a local account with a blank password does exist, enabling this
# setting will prevent network access, limiting the account to local console logon only.
function Test-SV-88285r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88285r1_rule")
	$obj | Add-Member NoteProperty Task("Local accounts with blank passwords must be restricted to prevent access from the network.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000020" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "LimitBlankPasswordUse" `
		-ExpectedValue 1 `
	| Write-Output
}

# Audit policy using subcategories must be enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000050
# Group ID (Vulid): V-73627
# CCI: CCI-000169
#
# Maintaining an audit trail of system activity logs can help identify configuration errors,
# troubleshoot service disruptions, and analyze compromises that have occurred, as well as
# detect attacks. Audit logs are necessary to provide a trail of evidence in case the system
# or network is compromised. Collecting this data is essential for analyzing the security
# of information assets and detecting signs of suspicious and unexpected behavior. This setting
# allows administrators to enable more precise auditing capabilities.
function Test-SV-88291r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88291r1_rule")
	$obj | Add-Member NoteProperty Task("Audit policy using subcategories must be enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000050" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "SCENoApplyLegacyAuditPolicy" `
		-ExpectedValue 1 `
	| Write-Output
}

# Domain controllers must require LDAP access signing.
# - - - - - - - - - - - - -
# StigID: WN16-DC-000320
# Group ID (Vulid): V-73629
# CCI: CCI-002418 CCI-002421
#
# Unsigned network traffic is susceptible to man-in-the-middle attacks, where an intruder captures
# packets between the server and the client and modifies them before forwarding them to the
# client. In the case of an LDAP server, this means that an attacker could cause a client
# to make decisions based on false records from the LDAP directory. The risk of an attacker
# pulling this off can be decreased by implementing strong physical security measures to protect
# the network infrastructure. Furthermore, implementing Internet Protocol security (IPsec)
# authentication header mode (AH), which performs mutual authentication and packet integrity
# for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely
# difficult.Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
function Test-SV-88293r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88293r1_rule")
	$obj | Add-Member NoteProperty Task("Domain controllers must require LDAP access signing.")

	#TODO: Test function on domain connected server

	if (Test-DomainController) {
		Test-RegistrySetting `
			-obj $obj `
			-StigId "WN16-DC-000320" `
			-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\" `
			-Name "LDAPServerIntegrity" `
			-ExpectedValue 2
	}
	else {
		$obj | Add-Member NoteProperty Status("Not domain integrated. Test irrelevant.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::None)
	}

	Write-Output $obj
}

# Domain controllers must be configured to allow reset of machine account passwords.
# - - - - - - - - - - - - -
# StigID: WN16-DC-000330
# Group ID (Vulid): V-73631
# CCI: CCI-000366
#
# Enabling this setting on all domain controllers in a domain prevents domain members from
# changing their computer account passwords. If these passwords are weak or compromised, the
# inability to change them may leave these computers vulnerable.
function Test-SV-88295r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88295r1_rule")
	$obj | Add-Member NoteProperty Task("Domain controllers must be configured to allow reset of machine account passwords.")

	if (Test-DomainController) {
		Test-RegistrySetting `
			-obj $obj `
			-StigId "WN16-DC-000330" `
			-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
			-Name "RefusePasswordChange" `
			-ExpectedValue 0
	}
	else {
		$obj | Add-Member NoteProperty Status("Not domain integrated. Test irrelevant.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::None)
	}

	Write-Output $obj
}

# The setting Domain member: Digitally encrypt or sign secure channel data (always) must be
# configured to Enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000080
# Group ID (Vulid): V-73633
# CCI: CCI-002418 CCI-002421
#
# Requests sent on the secure channel are authenticated, and sensitive information (such as
# passwords) is encrypted, but not all information is encrypted. If this policy is enabled,
# outgoing secure channel traffic will be encrypted and signed.Satisfies: SRG-OS-000423-GPOS-00187,
# SRG-OS-000424-GPOS-00188
function Test-SV-88297r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88297r1_rule")
	$obj | Add-Member NoteProperty Task("Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.")

	if (Test-DomainMember) {
		Test-RegistrySetting `
			-obj $obj `
			-StigId "WN16-SO-000080" `
			-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
			-Name "RequireSignOrSeal" `
			-ExpectedValue 1
	}
	else {
		$obj | Add-Member NoteProperty Status("Not domain integrated. Test irrelevant.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::None)
	}

	Write-Output $obj
}

# The setting Domain member: Digitally encrypt secure channel data (when possible) must be
# configured to enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000090
# Group ID (Vulid): V-73635
# CCI: CCI-002418 CCI-002421
#
# Requests sent on the secure channel are authenticated, and sensitive information (such as
# passwords) is encrypted, but not all information is encrypted. If this policy is enabled,
# outgoing secure channel traffic will be encrypted.Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
#
function Test-SV-88299r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88299r1_rule")
	$obj | Add-Member NoteProperty Task("Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled.")

	if (Test-DomainMember) {
		Test-RegistrySetting `
			-obj $obj `
			-StigId "WN16-SO-000090" `
			-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
			-Name "SealSecureChannel" `
			-ExpectedValue 1
	}
	else {
		$obj | Add-Member NoteProperty Status("Not domain integrated. Test irrelevant.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::None)
	}

	Write-Output $obj
}

# The setting Domain member: Digitally sign secure channel data (when possible) must be configured
# to Enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000100
# Group ID (Vulid): V-73637
# CCI: CCI-002418 CCI-002421
#
# Requests sent on the secure channel are authenticated, and sensitive information (such as
# passwords) is encrypted, but the channel is not integrity checked. If this policy is enabled,
# outgoing secure channel traffic will be signed.Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
#
function Test-SV-88301r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88301r1_rule")
	$obj | Add-Member NoteProperty Task("Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.")

	if (Test-DomainMember) {
		Test-RegistrySetting `
			-obj $obj `
			-StigId "WN16-SO-000100" `
			-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
			-Name "SignSecureChannel" `
			-ExpectedValue 1
	}
	else {
		$obj | Add-Member NoteProperty Status("Not domain integrated. Test irrelevant.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::None)
	}


	Write-Output $obj
}

# The computer account password must not be prevented from being reset.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000110
# Group ID (Vulid): V-73639
# CCI: CCI-001967
#
# Computer account passwords are changed automatically on a regular basis. Disabling automatic
# password changes can make the system more vulnerable to malicious access. Frequent password
# changes can be a significant safeguard for the system. A new password for the computer account
# will be generated every 30 days.
function Test-SV-88303r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88303r1_rule")
	$obj | Add-Member NoteProperty Task("The computer account password must not be prevented from being reset.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000110" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
		-Name "DisablePasswordChange" `
		-ExpectedValue 0 `
	| Write-Output
}

# The maximum age for machine account passwords must be configured to 30 days or less.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000120
# Group ID (Vulid): V-73641
# CCI: CCI-000366
#
# Computer account passwords are changed automatically on a regular basis. This setting controls
# the maximum password age that a machine account may have. This must be set to no more than
# 30 days, ensuring the machine changes its password monthly.
function Test-SV-88305r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88305r1_rule")
	$obj | Add-Member NoteProperty Task("The maximum age for machine account passwords must be configured to 30 days or less.")

	#TODO: Change

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000120" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
		-Name "MaximumPasswordAge" `
		-ExpectedValue "Less than 30 days, but not 0." `
		-Predicate { param($regValue) $regValue -le 30 -and $regValue -ne 0 } `
	| Write-Output
}

# Windows Server 2016 must be configured to require a strong session key.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000130
# Group ID (Vulid): V-73643
# CCI: CCI-002418 CCI-002421
#
# A computer connecting to a domain controller will establish a secure channel. The secure
# channel connection may be subject to compromise, such as hijacking or eavesdropping, if
# strong session keys are not used to establish the connection. Requiring strong session keys
# enforces 128-bit encryption between systems.Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
#
function Test-SV-88307r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88307r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to require a strong session key.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000130" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" `
		-Name "RequireStrongKey" `
		-ExpectedValue 1 `
	| Write-Output
}

# The machine inactivity limit must be set to 15 minutes, locking the system with the screen
# saver.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000140
# Group ID (Vulid): V-73645
# CCI: CCI-000057
#
# Unattended systems are susceptible to unauthorized use and should be locked when unattended.
# The screen saver should be set at a maximum of 15 minutes and be password protected. This
# protects critical and sensitive data from exposure to unauthorized personnel with physical
# access to the computer.
function Test-SV-88309r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88309r1_rule")
	$obj | Add-Member NoteProperty Task("The machine inactivity limit must be set to 15 minutes, locking the system with the screen saver.")

	#TODO: Change

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000140" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "InactivityTimeoutSecs" `
		-ExpectedValue "Less than 900 seconds." `
		-Predicate { param($regValue) $regValue -le 900 } `
	| Write-Output
}

# The required legal notice must be configured to display before console logon.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000150
# Group ID (Vulid): V-73647
# CCI: CCI-000048 CCI-000050 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388
#
# Failure to display the logon banner prior to a logon attempt will negate legal proceedings
# resulting from unauthorized access to system resources.Satisfies: SRG-OS-000023-GPOS-00006,
# SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088
function Test-SV-88311r1_rule {
	[CmdletBinding()]
	Param(
		[string] $msg
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88311r1_rule")
	$obj | Add-Member NoteProperty Task("The required legal notice must be configured to display before console logon.")

	$ExpectedValue = ""
	$Predicate = $null

	if ($PSBoundParameters.ContainsKey("msg")) {
		$ExpectedValue = "$msg"
		$Predicate = { param($regValue) $regValue -eq $msg }
	}
	else {
		$ExpectedValue = "Non-empty string."
		$Predicate = { param($regValue) $null -ne $regValue -and $regValue -ne "" }
	}

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000150" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "LegalNoticeText" `
		-ExpectedValue $ExpectedValue `
		-Predicate $Predicate `
	| Write-Output
}

# The Windows dialog box title for the legal banner must be configured with the appropriate
# text.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000160
# Group ID (Vulid): V-73649
# CCI: CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388
#
# Failure to display the logon banner prior to a logon attempt will negate legal proceedings
# resulting from unauthorized access to system resources.Satisfies: SRG-OS-000023-GPOS-00006,
# SRG-OS-000228-GPOS-00088
function Test-SV-88313r1_rule {
	Param(
		[string] $msg
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88313r1_rule")
	$obj | Add-Member NoteProperty Task("The Windows dialog box title for the legal banner must be configured with the appropriate text.")

	if ($PSBoundParameters.ContainsKey("msg")) {
		$ExpectedValue = "$msg"
		$Predicate = { param($regValue) $regValue -eq $msg }
	}
	else {
		$ExpectedValue = "Non-empty string."
		$Predicate = { param($regValue) $null -ne $regValue -and $regValue -ne "" }
	}

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000160" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "LegalNoticeCaption" `
		-ExpectedValue $ExpectedValue `
		-Predicate $Predicate `
	| Write-Output
}

# Caching of logon credentials must be limited.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000050
# Group ID (Vulid): V-73651
# CCI: CCI-000366
#
# The default Windows configuration caches the last logon credentials for users who log on
# interactively to a system. This feature is provided for system availability reasons, such
# as the users machine being disconnected from the network or domain controllers being unavailable.
# Even though the credential cache is well protected, if a system is attacked, an unauthorized
# individual may isolate the password to a domain user account using a password-cracking program
# and gain access to the domain.
function Test-SV-88315r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88315r1_rule")
	$obj | Add-Member NoteProperty Task("Caching of logon credentials must be limited.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-MS-000050" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" `
		-Name "CachedLogonsCount" `
		-ExpectedValue "Less than 4" `
		-Predicate { param($regValue) $regValue -le "4" } `
	| Write-Output
}

# The setting Microsoft network client: Digitally sign communications (always) must be configured
# to Enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000190
# Group ID (Vulid): V-73653
# CCI: CCI-002418 CCI-002421
#
# The server message block (SMB) protocol provides the basis for many network operations. Digitally
# signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled,
# the SMB client will only communicate with an SMB server that performs SMB packet signing.Satisfies:
# SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
function Test-SV-88317r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88317r1_rule")
	$obj | Add-Member NoteProperty Task("The setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000190" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" `
		-Name "RequireSecuritySignature" `
		-ExpectedValue 1 `
	| Write-Output
}

# The setting Microsoft network client: Digitally sign communications (if server agrees) must
# be configured to Enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000200
# Group ID (Vulid): V-73655
# CCI: CCI-002418 CCI-002421
#
# The server message block (SMB) protocol provides the basis for many network operations. If
# this policy is enabled, the SMB client will request packet signing when communicating with
# an SMB server that is enabled or required to perform SMB packet signing.Satisfies: SRG-OS-000423-GPOS-00187,
# SRG-OS-000424-GPOS-00188
function Test-SV-88319r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88319r1_rule")
	$obj | Add-Member NoteProperty Task("The setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000200" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" `
		-Name "EnableSecuritySignature" `
		-ExpectedValue 1 `
	| Write-Output
}

# Unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000210
# Group ID (Vulid): V-73657
# CCI: CCI-000197
#
# Some non-Microsoft SMB servers only support unencrypted (plain-text) password authentication.
# Sending plain-text passwords across the network when authenticating to an SMB server reduces
# the overall security of the environment. Check with the vendor of the SMB server to determine
# if there is a way to support encrypted password authentication.
function Test-SV-88321r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88321r1_rule")
	$obj | Add-Member NoteProperty Task("Unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000210" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" `
		-Name "EnablePlainTextPassword" `
		-ExpectedValue 0 `
	| Write-Output
}

# The amount of idle time required before suspending a session must be configured to 15 minutes
# or less.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000220
# Group ID (Vulid): V-73659
# CCI: CCI-001133 CCI-002361
#
# Open sessions can increase the avenues of attack on a system. This setting is used to control
# when a computer disconnects an inactive SMB session. If client activity resumes, the session
# is automatically reestablished. This protects critical and sensitive network data from exposure
# to unauthorized personnel with physical access to the computer.Satisfies: SRG-OS-000163-GPOS-00072,
# SRG-OS-000279-GPOS-00109
function Test-SV-88323r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88323r1_rule")
	$obj | Add-Member NoteProperty Task("The amount of idle time required before suspending a session must be configured to 15 minutes or less.")

	#TODO: Change

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000220" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" `
		-Name "autodisconnect" `
		-ExpectedValue "Less than 15 minutes." `
		-Predicate { param($regValue) $regValue -le 15 } `
	| Write-Output
}

# The setting Microsoft network server: Digitally sign communications (always) must be configured
# to Enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000230
# Group ID (Vulid): V-73661
# CCI: CCI-002418 CCI-002421
#
# The server message block (SMB) protocol provides the basis for many network operations. Digitally
# signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled,
# the SMB server will only communicate with an SMB client that performs SMB packet signing.Satisfies:
# SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
function Test-SV-88325r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88325r1_rule")
	$obj | Add-Member NoteProperty Task("The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000230" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" `
		-Name "RequireSecuritySignature" `
		-ExpectedValue 1 `
	| Write-Output
}

# The setting Microsoft network server: Digitally sign communications (if client agrees) must
# be configured to Enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000240
# Group ID (Vulid): V-73663
# CCI: CCI-002418 CCI-002421
#
# The server message block (SMB) protocol provides the basis for many network operations. Digitally
# signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled,
# the SMB server will negotiate SMB packet signing as requested by the client.Satisfies: SRG-OS-000423-GPOS-00187,
# SRG-OS-000424-GPOS-00188
function Test-SV-88327r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88327r1_rule")
	$obj | Add-Member NoteProperty Task("The setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000240" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" `
		-Name "EnableSecuritySignature" `
		-ExpectedValue 1 `
	| Write-Output
}

# Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000260
# Group ID (Vulid): V-73667
# CCI: CCI-000366
#
# Anonymous enumeration of SAM accounts allows anonymous logon users (null session connections)
# to list all accounts names, thus providing a list of potential points to attack the system.
#
function Test-SV-88331r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88331r1_rule")
	$obj | Add-Member NoteProperty Task("Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000260" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "RestrictAnonymousSAM" `
		-ExpectedValue 1 `
	| Write-Output
}

# Anonymous enumeration of shares must not be allowed.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000270
# Group ID (Vulid): V-73669
# CCI: CCI-001090
#
# Allowing anonymous logon users (null session connections) to list all account names and enumerate
# all shared resources can provide a map of potential points to attack the system.
function Test-SV-88333r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88333r1_rule")
	$obj | Add-Member NoteProperty Task("Anonymous enumeration of shares must not be allowed.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000270" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "RestrictAnonymous" `
		-ExpectedValue 1 `
	| Write-Output
}

# Windows Server 2016 must be configured to prevent the storage of passwords and credentials.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000280
# Group ID (Vulid): V-73671
# CCI: CCI-002038
#
# This setting controls the storage of passwords and credentials for network authentication
# on the local system. Such credentials must not be stored on the local machine, as that may
# lead to account compromise.Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
#
function Test-SV-88335r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88335r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to prevent the storage of passwords and credentials.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000280" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "DisableDomainCreds" `
		-ExpectedValue 1 `
	| Write-Output
}

# Windows Server 2016 must be configured to prevent anonymous users from having the same permissions
# as the Everyone group.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000290
# Group ID (Vulid): V-73673
# CCI: CCI-000366
#
# Access by anonymous users must be restricted. If this setting is enabled, anonymous users
# have the same rights and permissions as the built-in Everyone group. Anonymous users must
# not have these permissions or rights.
function Test-SV-88337r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88337r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to prevent anonymous users from having the same permissions as the Everyone group.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000290" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "EveryoneIncludesAnonymous" `
		-ExpectedValue 0 `
	| Write-Output
}

# Anonymous access to Named Pipes and Shares must be restricted.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000300
# Group ID (Vulid): V-73675
# CCI: CCI-001090
#
# Allowing anonymous access to named pipes or shares provides the potential for unauthorized
# system access. This setting restricts access to those defined in Network access: Named Pipes
# that can be accessed anonymously and Network access: Shares that can be accessed anonymously,
# both of which must be blank under other requirements.
function Test-SV-88339r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88339r1_rule")
	$obj | Add-Member NoteProperty Task("Anonymous access to Named Pipes and Shares must be restricted.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000300" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" `
		-Name "RestrictNullSessAccess" `
		-ExpectedValue 1 `
	| Write-Output
}

# Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000310
# Group ID (Vulid): V-73677
# CCI: CCI-002235
#
# The Windows Security Account Manager (SAM) stores users passwords. Restricting Remote Procedure
# Call (RPC) connections to the SAM to Administrators helps protect those credentials.
function Test-SV-88341r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88341r1_rule")
	$obj | Add-Member NoteProperty Task("Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-MS-000310" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "RestrictRemoteSAM" `
		-ExpectedValue "O:BAG:BAD:(A;;RC;;;BA)" `
	| Write-Output
}

# Services using Local System that use Negotiate when reverting to NTLM authentication must
# use the computer identity instead of authenticating anonymously.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000320
# Group ID (Vulid): V-73679
# CCI: CCI-000366
#
# Services using Local System that use Negotiate when reverting to NTLM authentication may
# gain unauthorized access if allowed to authenticate anonymously versus using the computer
# identity.
function Test-SV-88343r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88343r1_rule")
	$obj | Add-Member NoteProperty Task("Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000320" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\" `
		-Name "UseMachineId" `
		-ExpectedValue 1 `
	| Write-Output
}

# NTLM must be prevented from falling back to a Null session.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000330
# Group ID (Vulid): V-73681
# CCI: CCI-000366
#
# NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized
# access.
function Test-SV-88345r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88345r1_rule")
	$obj | Add-Member NoteProperty Task("NTLM must be prevented from falling back to a Null session.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000330" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\" `
		-Name "allownullsessionfallback" `
		-ExpectedValue 0 `
	| Write-Output
}

# PKU2U authentication using online identities must be prevented.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000340
# Group ID (Vulid): V-73683
# CCI: CCI-000366
#
# PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities
# from authenticating to domain-joined systems. Authentication will be centrally managed with
# Windows user accounts.
function Test-SV-88347r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88347r1_rule")
	$obj | Add-Member NoteProperty Task("PKU2U authentication using online identities must be prevented.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000340" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" `
		-Name "AllowOnlineID" `
		-ExpectedValue 0 `
	| Write-Output
}

# Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption
# suites.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000350
# Group ID (Vulid): V-73685
# CCI: CCI-000803
#
# Certain encryption types are no longer considered secure. The DES and RC4 encryption suites
# must not be used for Kerberos encryption.
function Test-SV-88349r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88349r1_rule")
	$obj | Add-Member NoteProperty Task("Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000350" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" `
		-Name "SupportedEncryptionTypes" `
		-ExpectedValue 2147483640 `
	| Write-Output
}

# Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of
# passwords.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000360
# Group ID (Vulid): V-73687
# CCI: CCI-000196
#
# The LAN Manager hash uses a weak encryption algorithm and there are several tools available
# that use this hash to retrieve account passwords. This setting controls whether a LAN Manager
# hash of the password is stored in the SAM the next time the password is changed.
function Test-SV-88351r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88351r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of passwords.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000360" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "NoLMHash" `
		-ExpectedValue 1 `
	| Write-Output
}

# The LAN Manager authentication level must be set to send NTLMv2 response only and to refuse
# LM and NTLM.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000380
# Group ID (Vulid): V-73691
# CCI: CCI-000366
#
# The Kerberos v5 authentication protocol is the default for authentication of users who are
# logging on to domain accounts. NTLM, which is less secure, is retained in later Windows
# versions for compatibility with clients and servers that are running earlier versions of
# Windows or applications that still use it. It is also used to authenticate logons to standalone
# computers that are running later versions.
function Test-SV-88355r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88355r1_rule")
	$obj | Add-Member NoteProperty Task("The LAN Manager authentication level must be set to send NTLMv2 response only and to refuse LM and NTLM.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000380" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" `
		-Name "LmCompatibilityLevel" `
		-ExpectedValue 5 `
	| Write-Output
}

# Windows Server 2016 must be configured to at least negotiate signing for LDAP client signing.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000390
# Group ID (Vulid): V-73693
# CCI: CCI-000366
#
# This setting controls the signing requirements for LDAP clients. This must be set to Negotiate
# signing or Require signing, depending on the environment and type of LDAP server in use.
#
function Test-SV-88357r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88357r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to at least negotiate signing for LDAP client signing.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000390" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\" `
		-Name "LDAPClientIntegrity" `
		-ExpectedValue 1 `
	| Write-Output
}

# Session security for NTLM SSP-based clients must be configured to require NTLMv2 session
# security and 128-bit encryption.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000400
# Group ID (Vulid): V-73695
# CCI: CCI-000366
#
# Microsoft has implemented a variety of security support providers for use with Remote Procedure
# Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.
#
function Test-SV-88359r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88359r1_rule")
	$obj | Add-Member NoteProperty Task("Session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000400" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" `
		-Name "NTLMMinClientSec" `
		-ExpectedValue 53739520 `
	| Write-Output
}

# Session security for NTLM SSP-based servers must be configured to require NTLMv2 session
# security and 128-bit encryption.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000410
# Group ID (Vulid): V-73697
# CCI: CCI-000366
#
# Microsoft has implemented a variety of security support providers for use with Remote Procedure
# Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.
#
function Test-SV-88361r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88361r1_rule")
	$obj | Add-Member NoteProperty Task("Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000410" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" `
		-Name "NTLMMinServerSec" `
		-ExpectedValue 53739520 `
	| Write-Output
}

# Users must be required to enter a password to access private keys stored on the computer.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000420
# Group ID (Vulid): V-73699
# CCI: CCI-000186
#
# If the private key is discovered, an attacker can use the key to authenticate as an authorized
# user and gain access to the network infrastructure.The cornerstone of the PKI is the private
# key used to encrypt or digitally sign information.If the private key is stolen, this will
# lead to the compromise of the authentication and non-repudiation gained through PKI because
# the attacker can use the private key to digitally sign documents and pretend to be the authorized
# user.Both the holders of a digital certificate and the issuing authority must protect the
# computers, storage devices, or whatever they use to keep the private keys.
function Test-SV-88363r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88363r1_rule")
	$obj | Add-Member NoteProperty Task("Users must be required to enter a password to access private keys stored on the computer.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000420" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\" `
		-Name "ForceKeyProtection" `
		-ExpectedValue 2 `
	| Write-Output
}

# Windows Server 2016 must be configured to use FIPS-compliant algorithms for encryption, hashing,
# and signing.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000430
# Group ID (Vulid): V-73701
# CCI: CCI-000068 CCI-002450
#
# This setting ensures the system uses algorithms that are FIPS-compliant for encryption, hashing,
# and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government
# and must be the algorithms used for all OS encryption functions.Satisfies: SRG-OS-000033-GPOS-00014,
# SRG-OS-000478-GPOS-00223
function Test-SV-88365r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88365r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000430" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" `
		-Name "Enabled" `
		-ExpectedValue 1 `
	| Write-Output
}

# Windows Server 2016 must be configured to require case insensitivity for non-Windows subsystems.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000440
# Group ID (Vulid): V-73703
# CCI: CCI-000366
#
# This setting controls the behavior of non-Windows subsystems when dealing with the case of
# arguments or commands. Case sensitivity could lead to the access of files or commands that
# must be restricted. To prevent this from happening, case insensitivity restrictions must
# be required.
function Test-SV-88367r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88367r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to require case insensitivity for non-Windows subsystems.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000440" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" `
		-Name "ObCaseInsensitive" `
		-ExpectedValue 1 `
	| Write-Output
}

# The default permissions of global system objects must be strengthened.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000450
# Group ID (Vulid): V-73705
# CCI: CCI-000366
#
# Windows systems maintain a global list of shared system resources such as DOS device names,
# mutexes, and semaphores. Each type of object is created with a default Discretionary Access
# Control List (DACL) that specifies who can access the objects with what permissions. When
# this policy is enabled, the default DACL is stronger, allowing non-administrative users
# to read shared objects but not to modify shared objects they did not create.
function Test-SV-88369r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88369r1_rule")
	$obj | Add-Member NoteProperty Task("The default permissions of global system objects must be strengthened.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000450" `
		-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" `
		-Name "ProtectionMode" `
		-ExpectedValue 1 `
	| Write-Output
}

# User Account Control approval mode for the built-in Administrator must be enabled.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000460
# Group ID (Vulid): V-73707
# CCI: CCI-002038
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting configures the built-in
# Administrator account so that it runs in Admin Approval Mode.Satisfies: SRG-OS-000373-GPOS-00157,
# SRG-OS-000373-GPOS-00156
function Test-SV-88371r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88371r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control approval mode for the built-in Administrator must be enabled.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000460" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "FilterAdministratorToken" `
		-ExpectedValue 1 `
	| Write-Output
}

# UIAccess applications must not be allowed to prompt for elevation without using the secure
# desktop.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000470
# Group ID (Vulid): V-73709
# CCI: CCI-001084
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting prevents User Interface
# Accessibility programs from disabling the secure desktop for elevation prompts.
function Test-SV-88373r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88373r1_rule")
	$obj | Add-Member NoteProperty Task("UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000470" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "EnableUIADesktopToggle" `
		-ExpectedValue 0 `
	| Write-Output
}

# User Account Control must, at a minimum, prompt administrators for consent on the secure
# desktop.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000480
# Group ID (Vulid): V-73711
# CCI: CCI-001084
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting configures the elevation
# requirements for logged-on administrators to complete a task that requires raised privileges.
#
function Test-SV-88375r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88375r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control must, at a minimum, prompt administrators for consent on the secure desktop.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000480" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "ConsentPromptBehaviorAdmin" `
		-ExpectedValue 2 `
	| Write-Output
}

# User Account Control must automatically deny standard user requests for elevation.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000490
# Group ID (Vulid): V-73713
# CCI: CCI-002038
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting controls the behavior
# of elevation when requested by a standard user account.Satisfies: SRG-OS-000373-GPOS-00157,
# SRG-OS-000373-GPOS-00156
function Test-SV-88377r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88377r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control must automatically deny standard user requests for elevation.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000490" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "ConsentPromptBehaviorUser" `
		-ExpectedValue 0 `
	| Write-Output
}

# User Account Control must be configured to detect application installations and prompt for
# elevation.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000500
# Group ID (Vulid): V-73715
# CCI: CCI-001084
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting requires Windows to respond
# to application installation requests by prompting for credentials.
function Test-SV-88379r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88379r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control must be configured to detect application installations and prompt for elevation.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000500" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "EnableInstallerDetection" `
		-ExpectedValue 1 `
	| Write-Output
}

# User Account Control must only elevate UIAccess applications that are installed in secure
# locations.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000510
# Group ID (Vulid): V-73717
# CCI: CCI-001084
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting configures Windows to
# only allow applications installed in a secure location on the file system, such as the Program
# Files or the Windows\System32 folders, to run with elevated privileges.
function Test-SV-88381r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88381r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control must only elevate UIAccess applications that are installed in secure locations.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000510" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "EnableSecureUIAPaths" `
		-ExpectedValue 1 `
	| Write-Output
}

# User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000520
# Group ID (Vulid): V-73719
# CCI: CCI-002038
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting enables UAC.Satisfies:
# SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
function Test-SV-88383r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88383r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control must run all administrators in Admin Approval Mode, enabling UAC.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000520" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "EnableLUA" `
		-ExpectedValue 1 `
	| Write-Output
}

# User Account Control must virtualize file and registry write failures to per-user locations.
#
# - - - - - - - - - - - - -
# StigID: WN16-SO-000530
# Group ID (Vulid): V-73721
# CCI: CCI-001084
#
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges,
# including administrative accounts, unless authorized. This setting configures non-UAC-compliant
# applications to run in virtualized file and registry entries in per-user locations, allowing
# them to run.
function Test-SV-88385r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88385r1_rule")
	$obj | Add-Member NoteProperty Task("User Account Control must virtualize file and registry write failures to per-user locations.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000530" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
		-Name "EnableVirtualization" `
		-ExpectedValue 1 `
	| Write-Output
}

# A screen saver must be enabled on the system.
# - - - - - - - - - - - - -
# StigID: WN16-UC-000010
# Group ID (Vulid): V-73723
# CCI: CCI-000060
#
# Unattended systems are susceptible to unauthorized use and must be locked when unattended.
# Enabling a password-protected screen saver to engage after a specified period of time helps
# protects critical and sensitive data from exposure to unauthorized personnel with physical
# access to the computer.
function Test-SV-88387r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88387r1_rule")
	$obj | Add-Member NoteProperty Task("A screen saver must be enabled on the system.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "ScreenSaveActive" `
		-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" `
		-Name "ScreenSaveActive" `
		-ExpectedValue "1" `
	| Write-Output
}

# The screen saver must be password protected.
# - - - - - - - - - - - - -
# StigID: WN16-UC-000020
# Group ID (Vulid): V-73725
# CCI: CCI-000056
#
# Unattended systems are susceptible to unauthorized use and must be locked when unattended.
# Enabling a password-protected screen saver to engage after a specified period of time helps
# protects critical and sensitive data from exposure to unauthorized personnel with physical
# access to the computer.
function Test-SV-88389r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88389r1_rule")
	$obj | Add-Member NoteProperty Task("The screen saver must be password protected.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-UC-000020" `
		-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" `
		-Name "ScreenSaverIsSecure" `
		-ExpectedValue "1" `
	| Write-Output
}

# Zone information must be preserved when saving attachments.
# - - - - - - - - - - - - -
# StigID: WN16-UC-000030
# Group ID (Vulid): V-73727
# CCI: CCI-000366
#
# Attachments from outside sources may contain malicious code. Preserving zone of origin (Internet,
# intranet, local, restricted) information on file attachments allows Windows to determine
# risk.
function Test-SV-88391r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88391r1_rule")
	$obj | Add-Member NoteProperty Task("Zone information must be preserved when saving attachments.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-UC-000030" `
		-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" `
		-Name "SaveZoneInformation" `
		-ExpectedValue 2 `
	| Write-Output
}

# The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000180
# Group ID (Vulid): V-73807
# CCI: CCI-000366
#
# Unattended systems are susceptible to unauthorized use and must be locked. Configuring a
# system to lock when a smart card is removed will ensure the system is inaccessible when
# unattended.
function Test-SV-88473r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88473r1_rule")
	$obj | Add-Member NoteProperty Task("The Smart Card removal option must be configured to Force Logoff or Lock Workstation.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-SO-000180" `
		-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" `
		-Name "scremoveoption" `
		-ExpectedValue "1" `
	| Write-Output
}

#endregion


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

# Permissions for the system drive root directory (usually C:\) must conform to minimum requirements.
#
# - - - - - - - - - - - - -
# StigID: WN16-00-000160
# Group ID (Vulid): V-73249
# CCI: CCI-002165
#
# Changing the systems file and directory permissions allows the possibility of unauthorized
# and anonymous modification to the operating system and installed applications.The default
# permissions are adequate when the Security Option Network access: Let everyone permissions
# apply to anonymous users is set to Disabled (WN16-SO-000290).Satisfies: SRG-OS-000312-GPOS-00122,
# SRG-OS-000312-GPOS-00123, SRG-OS-000312-GPOS-00124
function Test-SV-87901r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87901r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for the system drive root directory (usually C:\) must conform to minimum requirements.")

	$acls = Get-Acl ($env:SystemDrive + "\") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"CREATOR OWNER" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000160: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT Authority\System" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000160: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000160: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Users" {
				if (( $acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ( $acl.FileSystemRights -ne "CreateFiles, Synchronize" ) -xor ( $acl.FileSystemRights -ne "AppendData, Synchronize") ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000160: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000160: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Permissions for program file directories must conform to minimum requirements.
# - - - - - - - - - - - - -
# StigID: WN16-00-000170
# Group ID (Vulid): V-73251
# CCI: CCI-002165
#
# Changing the systems file and directory permissions allows the possibility of unauthorized
# and anonymous modification to the operating system and installed applications.The default
# permissions are adequate when the Security Option Network access: Let everyone permissions
# apply to anonymous users is set to Disabled (WN16-SO-000290).Satisfies: SRG-OS-000312-GPOS-00122,
# SRG-OS-000312-GPOS-00123, SRG-OS-000312-GPOS-00124

# Test for folder C:\Program Files
function Test-SV-87903r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87903r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for program file directorie $env:ProgramFiles must conform to minimum requirements.")

	$acls = Get-Acl ($env:ProgramFiles + "\") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\TrustedInstaller" {
				if ( ($acl.FileSystemRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"CREATOR OWNER" {
				if ( ($acl.FileSystemRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT Authority\System" {
				if ( -not(($acl.FileSystemRights -eq "FullControl") -or ($acl.FileSystemRights -eq "Modify, Synchronize") -xor ($acl.FileSystemRights -eq 268435456) -xor ($acl.FileSystemRights -eq -536805376)) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( -not(($acl.FileSystemRights -eq "FullControl") -or ($acl.FileSystemRights -eq "Modify, Synchronize") -xor ($acl.FileSystemRights -eq 268435456) -xor ($acl.FileSystemRights -eq -536805376)) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			"BUILTIN\Users" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000170: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Test for folder C:\Program Files(x86)
function Test-SV-87903r1_rule_2 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87903r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for program file directorie ${env:ProgramFiles(x86)} must conform to minimum requirements.")

	$acls = Get-Acl (${env:ProgramFiles(x86)} + "\") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\TrustedInstaller" {
				if ( ($acl.FileSystemRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"CREATOR OWNER" {
				if ( ($acl.FileSystemRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT Authority\System" {
				if ( -not(($acl.FileSystemRights -eq "FullControl") -xor ($acl.FileSystemRights -eq "Modify, Synchronize") -xor ($acl.FileSystemRights -eq 268435456) -xor ($acl.FileSystemRights -eq -536805376)) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( -not(($acl.FileSystemRights -eq "FullControl") -xor ($acl.FileSystemRights -eq "Modify, Synchronize") -xor ($acl.FileSystemRights -eq 268435456) -xor ($acl.FileSystemRights -eq -536805376)) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			"BUILTIN\Users" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000170: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000170: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Permissions for the Windows installation directory must conform to minimum requirements.
# - - - - - - - - - - - - -
# StigID: WN16-00-000180
# Group ID (Vulid): V-73253
# CCI: CCI-002165
#
# Changing the systems file and directory permissions allows the possibility of unauthorized
# and anonymous modification to the operating system and installed applications.The default
# permissions are adequate when the Security Option Network access: Let everyone permissions
# apply to anonymous users is set to Disabled (WN16-SO-000290).Satisfies: SRG-OS-000312-GPOS-00122,
# SRG-OS-000312-GPOS-00123, SRG-OS-000312-GPOS-00124
function Test-SV-87905r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87905r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for the Windows installation directory $env:windir must conform to minimum requirements.")

	$acls = Get-Acl ($env:windir + "\") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\TrustedInstaller" {
				if ( ($acl.FileSystemRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"CREATOR OWNER" {
				if ( ($acl.FileSystemRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT Authority\System" {
				if ( -not(($acl.FileSystemRights -eq "FullControl") -or ($acl.FileSystemRights -eq "Modify, Synchronize") -xor ($acl.FileSystemRights -eq 268435456) -xor ($acl.FileSystemRights -eq -536805376)) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( -not(($acl.FileSystemRights -eq "FullControl") -xor ($acl.FileSystemRights -eq "Modify, Synchronize") -xor ($acl.FileSystemRights -eq 268435456) -xor ($acl.FileSystemRights -eq -536805376)) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights)" -Level Error
				}
			}

			"BUILTIN\Users" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" {
				if ( ($acl.FileSystemRights -ne "ReadAndExecute, Synchronize") -xor ($acl.FileSystemRights -eq -1610612736) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000180: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000180: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.
# - - - - - - - - - - - - -
# StigID: WN16-00-000190
# Group ID (Vulid): V-73255
# CCI: CCI-002235
#
# The registry is integral to the function, security, and stability of the Windows system.
# Changing the systems registry permissions allows the possibility of unauthorized and anonymous
# modification to the operating system.
function Test-SV-87907r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87907r1_rule")
	$obj | Add-Member NoteProperty Task("Default permissions for the HKEY_LOCAL_MACHINE\Security registry hive must be maintained.")

	$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('Security', 'Default', 'ReadPermissions')
	$acls = $key.GetAccessControl() | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT Authority\System" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.RegistryRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000190: Found $($acl.IdentityReference):$($acl.RegistryRights) -expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( ($acl.RegistryRights -ne "ReadPermissions, ChangePermissions")  ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):ReadPermissions, ChangePermissions" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Found unexpected permission $($acl.IdentityReference) with access $($acl.RegistryRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

function Test-SV-87907r1_rule_2 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87907r1_rule_2")
	$obj | Add-Member NoteProperty Task("Default permissions for the HKEY_LOCAL_MACHINE\Software registry hive must be maintained.")

	$acls = Get-Acl ("HKLM:\Software") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT Authority\System" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.RegistryRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000190: Found $($acl.IdentityReference):$($acl.RegistryRights) -expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.RegistryRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Users" {
				if ( ($acl.RegistryRights -ne "ReadKey") -xor ($acl.RegistryRights -eq -2147483648) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):ReadKey" -Level Error
				}
			}

			"CREATOR OWNER" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.RegistryRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" {
				if ( ($acl.RegistryRights -ne "ReadKey") -xor ($acl.RegistryRights -eq -2147483648) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):ReadKey" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Found unexpected permission $($acl.IdentityReference) with access $($acl.RegistryRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

function Test-SV-87907r1_rule_3 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87907r1_rule_3")
	$obj | Add-Member NoteProperty Task("Default permissions for the HKEY_LOCAL_MACHINE\System registry hive must be maintained.")

	$acls = Get-Acl ("HKLM:\System") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT Authority\System" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.RegistryRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-00-000190: Found $($acl.IdentityReference):$($acl.RegistryRights) -expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.RegistryRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Users" {
				if ( ($acl.RegistryRights -ne "ReadKey") -xor ($acl.RegistryRights -eq -2147483648) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):ReadKey" -Level Error
				}
			}

			"CREATOR OWNER" {
				if ( ($acl.RegistryRights -ne "FullControl") -xor ($acl.FileSystemRights -eq 268435456) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" {
				if ( ($acl.RegistryRights -ne "ReadKey") -xor ($acl.RegistryRights -eq -2147483648) ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.RegistryRights) - expected $($acl.IdentityReference):ReadKey" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Found unexpected permission $($acl.IdentityReference) with access $($acl.RegistryRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
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
function Test-SV-87911r1_rule {
	[CmdletBinding()]
	Param(
		[System.Int32]$days = 35
	)
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87911r1_rule")
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

# A host-based firewall must be installed and enabled on the system.
# - - - - - - - - - - - - -
# StigID: WN16-00-000310
# Group ID (Vulid): V-73279
# CCI: CCI-000366 CCI-002080
#
# A firewall provides a line of defense against attack, allowing or blocking inbound and outbound
# connections based on a set of rules.
function Test-SV-87931r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87931r1_rule")
	$obj | Add-Member NoteProperty Task("A host-based firewall must be installed and enabled on the system.")

	$profiles = Get-NetFirewallProfile
	$firewallDisabled = $false

	foreach ($profile in $profiles) {
		if (-not $profile.enabled ) {
			$firewallDisabled = $true
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-00-000310: Firewallprofile $($profile.Name) is disabled" -Level Error
		}
	}

	if ( $firewallDisabled ) {
		$obj | Add-Member NoteProperty Status("Found disabled firewall profile.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	else {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}

	Write-Output $obj
}

# The Fax Server role must not be installed.
# - - - - - - - - - - - - -
# StigID: WN16-00-000350
# Group ID (Vulid): V-73287
# CCI: CCI-000381
#
# Unnecessary services increase the attack surface of a system. Some of these services may
# not support required levels of authentication or encryption or may provide unauthorized
# access to the system.
function Test-SV-87939r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87939r1_rule")
	$obj | Add-Member NoteProperty Task("The Fax Server role must not be installed.")

	if ((Get-WindowsFeature | Where-Object Name -eq Fax | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Fax server role is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Microsoft FTP service must not be installed unless required.
# - - - - - - - - - - - - -
# StigID: WN16-00-000360
# Group ID (Vulid): V-73289
# CCI: CCI-000382
#
# Unnecessary services increase the attack surface of a system. Some of these services may
# not support required levels of authentication or encryption.
function Test-SV-87941r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87941r1_rule")
	$obj | Add-Member NoteProperty Task("The Microsoft FTP service must not be installed unless required.")

	if ((Get-WindowsFeature | Where-Object Name -eq Web-Ftp-Service | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("FTP service is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Peer Name Resolution Protocol must not be installed.
# - - - - - - - - - - - - -
# StigID: WN16-00-000370
# Group ID (Vulid): V-73291
# CCI: CCI-000381
#
# Unnecessary services increase the attack surface of a system. Some of these services may
# not support required levels of authentication or encryption or may provide unauthorized
# access to the system.
function Test-SV-87943r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87943r1_rule")
	$obj | Add-Member NoteProperty Task("The Peer Name Resolution Protocol must not be installed.")

	if ((Get-WindowsFeature | Where-Object Name -eq PNRP | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Peer name resolution protocol is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Simple TCP/IP Services must not be installed.
# - - - - - - - - - - - - -
# StigID: WN16-00-000380
# Group ID (Vulid): V-73293
# CCI: CCI-000381
#
# Unnecessary services increase the attack surface of a system. Some of these services may
# not support required levels of authentication or encryption or may provide unauthorized
# access to the system.
function Test-SV-87945r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87945r1_rule")
	$obj | Add-Member NoteProperty Task("Simple TCP/IP Services must not be installed.")

	if ((Get-WindowsFeature | Where-Object Name -eq Simple-TCPIP | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Simple TCP/IP Services is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Telnet Client must not be installed.
# - - - - - - - - - - - - -
# StigID: WN16-00-000390
# Group ID (Vulid): V-73295
# CCI: CCI-000382
#
# Unnecessary services increase the attack surface of a system. Some of these services may
# not support required levels of authentication or encryption or may provide unauthorized
# access to the system.
function Test-SV-87947r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87947r1_rule")
	$obj | Add-Member NoteProperty Task("The Telnet Client must not be installed.")

	if ((Get-WindowsFeature | Where-Object Name -eq Telnet-Client | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The Telnet Client is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The TFTP Client must not be installed.
# - - - - - - - - - - - - -
# StigID: WN16-00-000400
# Group ID (Vulid): V-73297
# CCI: CCI-000381
#
# Unnecessary services increase the attack surface of a system. Some of these services may
# not support required levels of authentication or encryption or may provide unauthorized
# access to the system.
function Test-SV-87949r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87949r1_rule")
	$obj | Add-Member NoteProperty Task("The TFTP Client must not be installed.")

	if ((Get-WindowsFeature | Where-Object Name -eq TFTP-Client | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The TFTP Client is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Server Message Block (SMB) v1 protocol must be uninstalled.
# - - - - - - - - - - - - -
# StigID: WN16-00-000410
# Group ID (Vulid): V-73299
# CCI: CCI-000381
#
# SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be
# vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS
# compliant.
function Test-SV-87951r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87951r1_rule")
	$obj | Add-Member NoteProperty Task("The Server Message Block (SMB) v1 protocol must be uninstalled.")

	if ((Get-WindowsFeature | Where-Object Name -eq FS-SMB1 | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The server Message Block (SMB) v1 protocol is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Windows PowerShell 2.0 must not be installed.
# - - - - - - - - - - - - -
# StigID: WN16-00-000420
# Group ID (Vulid): V-73301
# CCI: CCI-000381
#
# Windows PowerShell 5.0 added advanced logging features that can provide additional detail
# when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against
# a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.
function Test-SV-87953r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87953r1_rule")
	$obj | Add-Member NoteProperty Task("Windows PowerShell 2.0 must not be installed.")

	if ((Get-WindowsFeature | Where-Object Name -eq PowerShell-v2 | Select-Object -ExpandProperty InstallState) -ne "Installed") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Windows PowerShell 2.0 is installed.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}


# Windows 2016 account lockout duration must be configured to 15 minutes or greater.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000010
# Group ID (Vulid): V-73309
# CCI: CCI-002238
#
# The account lockout feature, when enabled, prevents brute-force password attacks on the system.
# This parameter specifies the period of time that an account will remain locked after the
# specified number of failed logon attempts.
function Test-SV-87961r2_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87961r2_rule")
	$obj | Add-Member NoteProperty Task("Windows 2016 account lockout duration must be configured to 15 minutes or greater.")

	$lockoutDuration = Get-SecPolSetting -SystemAccess -SystemAccessSetting LockoutDuration

	if ( $lockoutDuration -ge 15 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Windows 2016 account lockout duration is not configured to 15 minutes or greater, found $lockoutDuration.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Windows 2016 account lockout duration is not configured to 15 minutes or greater, found $lockoutDuration." -Level Error
	}

	Write-Output $obj
}

# The number of allowed bad logon attempts must be configured to three or less.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000020
# Group ID (Vulid): V-73311
# CCI: CCI-000044
#
# The account lockout feature, when enabled, prevents brute-force password attacks on the system.
# The higher this value is, the less effective the account lockout feature will be in protecting
# the local system. The number of bad logon attempts must be reasonably small to minimize
# the possibility of a successful password attack while allowing for honest errors made during
# normal user logon.
function Test-SV-87963r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87963r1_rule")
	$obj | Add-Member NoteProperty Task("The number of allowed bad logon attempts must be configured to three or less.")

	$badLogons = Get-SecPolSetting -SystemAccess -SystemAccessSetting LockoutBadCount

	if ( $badLogons -le 3 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The number of allowed bad logon attempts is not configured to three or less, found $badLogons.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "The number of allowed bad logon attempts is not configured to three or less, found $badLogons." -Level Error
	}

	Write-Output $obj
}

# The period of time before the bad logon counter is reset must be configured to 15 minutes
# or greater.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000030
# Group ID (Vulid): V-73313
# CCI: CCI-000044 CCI-002238
#
# The account lockout feature, when enabled, prevents brute-force password attacks on the system.
# This parameter specifies the period of time that must pass after failed logon attempts before
# the counter is reset to 0. The smaller this value is, the less effective the account lockout
# feature will be in protecting the local system.Satisfies: SRG-OS-000021-GPOS-00005, SRG-OS-000329-GPOS-00128
#
function Test-SV-87965r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87965r1_rule")
	$obj | Add-Member NoteProperty Task("The period of time before the bad logon counter is reset must be configured to 15 minutes or greater.")

	$logonCounterReset = Get-SecPolSetting -SystemAccess -SystemAccessSetting ResetLockoutCount

	if ( $logonCounterReset -ge 15 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The period of time before the bad logon counter is reset is not configured to 15 minutes or greater, found $passwordAge.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "The period of time before the bad logon counter is reset is not configured to 15 minutes or greater, found $passwordAge." -Level Error
	}

	Write-Output $obj
}

# The password history must be configured to 24 passwords remembered.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000040
# Group ID (Vulid): V-73315
# CCI: CCI-000200
#
# A system is more vulnerable to unauthorized access when system users recycle the same password
# several times without being required to change to a unique password on a regularly scheduled
# basis. This enables users to effectively negate the purpose of mandating periodic password
# changes. The default value is 24 for Windows domain systems. DoD has decided this is the
# appropriate value for all Windows systems.
function Test-SV-87967r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87967r1_rule")
	$obj | Add-Member NoteProperty Task("The password history must be configured to 24 passwords remembered.")

	$passwordHistory = Get-SecPolSetting -SystemAccess -SystemAccessSetting PasswordHistorySize

	if ( $passwordHistory -eq 24 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The password history is not configured to 24 passwords remembered, found $passwordHistory.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "The password history is not configured to 24 passwords remembered, found $passwordHistory." -Level Error
	}

	Write-Output $obj
}

# The maximum password age must be configured to 60 days or less.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000050
# Group ID (Vulid): V-73317
# CCI: CCI-000199
#
# The longer a password is in use, the greater the opportunity for someone to gain unauthorized
# knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized
# system users to crack passwords and gain access to a system.
function Test-SV-87969r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87969r1_rule")
	$obj | Add-Member NoteProperty Task("The maximum password age must be configured to 60 days or less.")

	$passwordAge = Get-SecPolSetting -SystemAccess -SystemAccessSetting MaximumPasswordAge

	if ( $passwordAge -le 60 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Maximum password age not configured to 60 days or less, found $passwordAge.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Maximum password age not configured to 60 days or less, found $passwordAge." -Level Error
	}

	Write-Output $obj
}

# The minimum password age must be configured to at least one day.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000060
# Group ID (Vulid): V-73319
# CCI: CCI-000198
#
# Permitting passwords to be changed in immediate succession within the same day allows users
# to cycle passwords through their history database. This enables users to effectively negate
# the purpose of mandating periodic password changes.
function Test-SV-87971r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87971r1_rule")
	$obj | Add-Member NoteProperty Task("The minimum password age must be configured to at least one day.")

	$passwordAge = Get-SecPolSetting -SystemAccess -SystemAccessSetting MinimumPasswordAge

	if ( $passwordAge -ge 1 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The minimum password age is not configured to at least one day, found $passwordAge.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "The minimum password age is not configured to at least one day, found $passwordAge." -Level Error
	}

	Write-Output $obj
}

# The minimum password length must be configured to 14 characters.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000070
# Group ID (Vulid): V-73321
# CCI: CCI-000205
#
# Information systems not protected with strong password schemes (including passwords of minimum
# length) provide the opportunity for anyone to crack the password, thus gaining access to
# the system and compromising the device, information, or the local network.
function Test-SV-87973r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87973r1_rule")
	$obj | Add-Member NoteProperty Task("The minimum password length must be configured to 14 characters.")

	$passwordLength = Get-SecPolSetting -SystemAccess -SystemAccessSetting MinimumPasswordLength

	if ( $passwordLength -ge 14 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The minimum password length is not configured to 14 character, found $passwordLength.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "The minimum password length is not configured to 14 character, found $passwordLength." -Level Error
	}

	Write-Output $obj
}

# The built-in Windows password complexity policy must be enabled.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000080
# Group ID (Vulid): V-73323
# CCI: CCI-000192 CCI-000193 CCI-000194 CCI-001619
#
# The use of complex passwords increases their strength against attack. The built-in Windows
# password complexity policy requires passwords to contain at least three of the four types
# of characters (numbers, upper- and lower-case letters, and special characters) and prevents
# the inclusion of user names or parts of user names.Satisfies: SRG-OS-000069-GPOS-00037,
# SRG-OS-000070-GPOS-00038, SRG-OS-000071-GPOS-00039, SRG-OS-000266-GPOS-00101
function Test-SV-87975r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87975r1_rule")
	$obj | Add-Member NoteProperty Task("The built-in Windows password complexity policy must be enabled.")

	$passwordComplexity = Get-SecPolSetting -SystemAccess -SystemAccessSetting PasswordComplexity

	if ( $passwordComplexity -eq 1 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("The built-in Windows password complexity policy is not enabled.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "The built-in Windows password complexity policy is not enabled." -Level Error
	}

	Write-Output $obj
}

# Reversible password encryption must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-AC-000090
# Group ID (Vulid): V-73325
# CCI: CCI-000196
#
# Storing passwords using reversible encryption is essentially the same as storing clear-text
# versions of the passwords, which are easily compromised. For this reason, this policy must
# never be enabled.
function Test-SV-87977r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-87977r1_rule")
	$obj | Add-Member NoteProperty Task("Reversible password encryption must be disabled.")

	$passwordReversibleEncryption = Get-SecPolSetting -SystemAccess -SystemAccessSetting ClearTextPassword

	if ( $passwordReversibleEncryption -eq 0 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Reversible password encryption is not disabled.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Reversible password encryption is not disabled." -Level Error
	}

	Write-Output $obj
}

# Permissions for the Application event log must prevent access by non-privileged accounts.
#
# - - - - - - - - - - - - -
# StigID: WN16-AU-000030
# Group ID (Vulid): V-73405
# CCI: CCI-000162 CCI-000163 CCI-000164
#
# Maintaining an audit trail of system activity logs can help identify configuration errors,
# troubleshoot service disruptions, and analyze compromises that have occurred, as well as
# detect attacks. Audit logs are necessary to provide a trail of evidence in case the system
# or network is compromised. The Application event log may be susceptible to tampering if
# proper permissions are not applied.Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028,
# SRG-OS-000059-GPOS-00029
function Test-SV-88057r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88057r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for the Application event log must prevent access by non-privileged accounts.")

	$acls = Get-Acl ($env:SystemRoot + "\System32\winevt\Logs\Application.evtx") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\EventLog" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000030: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT AUTHORITY\SYSTEM" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000030: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( $acl.FileSystemRights -ne "FullControl" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000030: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-AU-000030: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Permissions for the Security event log must prevent access by non-privileged accounts.
# - - - - - - - - - - - - -
# StigID: WN16-AU-000040
# Group ID (Vulid): V-73407
# CCI: CCI-000162 CCI-000163 CCI-000164
#
# Maintaining an audit trail of system activity logs can help identify configuration errors,
# troubleshoot service disruptions, and analyze compromises that have occurred, as well as
# detect attacks. Audit logs are necessary to provide a trail of evidence in case the system
# or network is compromised. The Security event log may disclose sensitive information or
# be susceptible to tampering if proper permissions are not applied.Satisfies: SRG-OS-000057-GPOS-00027,
# SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029
function Test-SV-88059r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88059r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for the Security event log must prevent access by non-privileged accounts.")

	$acls = Get-Acl ($env:SystemRoot + "\System32\winevt\Logs\Security.evtx") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\EventLog" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000040: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT AUTHORITY\SYSTEM" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000040: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( $acl.FileSystemRights -ne "FullControl" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000040: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-AU-000030: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Permissions for the System event log must prevent access by non-privileged accounts.
# - - - - - - - - - - - - -
# StigID: WN16-AU-000050
# Group ID (Vulid): V-73409
# CCI: CCI-000162 CCI-000163 CCI-000164
#
# Maintaining an audit trail of system activity logs can help identify configuration errors,
# troubleshoot service disruptions, and analyze compromises that have occurred, as well as
# detect attacks. Audit logs are necessary to provide a trail of evidence in case the system
# or network is compromised. The System event log may be susceptible to tampering if proper
# permissions are not applied.Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028,
# SRG-OS-000059-GPOS-00029
function Test-SV-88061r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88061r1_rule")
	$obj | Add-Member NoteProperty Task("Permissions for the System event log must prevent access by non-privileged accounts.")

	$acls = Get-Acl ($env:SystemRoot + "\System32\winevt\Logs\System.evtx") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\EventLog" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000050: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT AUTHORITY\SYSTEM" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000050: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( $acl.FileSystemRights -ne "FullControl" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "WN16-AU-000050: Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-AU-000050: Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# Event Viewer must be protected from unauthorized modification and deletion.
# - - - - - - - - - - - - -
# StigID: WN16-AU-000060
# Group ID (Vulid): V-73411
# CCI: CCI-001494 CCI-001495
#
# Protecting audit information also includes identifying and protecting the tools used to view
# and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized
# operation on audit information.Operating systems providing tools to interface with audit
# information will leverage user permissions and roles identifying the user accessing the
# tools and the corresponding rights the user enjoys in order to make access decisions regarding
# the modification or deletion of audit tools.Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000258-GPOS-00099
#
function Test-SV-88063r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88063r1_rule")
	$obj | Add-Member NoteProperty Task("Event Viewer must be protected from unauthorized modification and deletion.")

	$acls = Get-Acl ($env:SystemRoot + "\System32\Eventvwr.exe") | Select-Object -ExpandProperty Access
	$compliant = $true

	foreach ($acl in $acls) {
		switch ($acl.IdentityReference) {
			"NT SERVICE\TrustedInstaller" {
				if ($acl.FileSystemRights -ne "FullControl") {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):FullControl" -Level Error
				}
			}

			"NT Authority\System" {
				if ( $acl.FileSystemRights -ne "ReadAndExecute, Synchronize" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"BUILTIN\Administrators" {
				if ( $acl.FileSystemRights -ne "ReadAndExecute, Synchronize" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"BUILTIN\Users" {
				if ( $acl.FileSystemRights -ne "ReadAndExecute, Synchronize" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" {
				if ( $acl.FileSystemRights -ne "ReadAndExecute, Synchronize" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" {
				if ( $acl.FileSystemRights -ne "ReadAndExecute, Synchronize" ) {
					$compliant = $false
					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -message "Found $($acl.IdentityReference):$($acl.FileSystemRights) - expected $($acl.IdentityReference):ReadAndExecute, Synchronize" -Level Error
				}
			}

			Default {
				$compliant = $false
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Found unexpected permission $($acl.IdentityReference) with access $($acl.FileSystemRights)" -Level Error
			}
		}
	}

	if ( $compliant ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}



# The display of slide shows on the lock screen must be disabled.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000010
# Group ID (Vulid): V-73493
# CCI: CCI-000381
#
# Slide shows that are displayed on the lock screen could display sensitive information to
# unauthorized personnel. Turning off this feature will limit access to the information to
# a logged-on user.
function Test-SV-88145r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88145r1_rule")
	$obj | Add-Member NoteProperty Task("The display of slide shows on the lock screen must be disabled.")

	try {
		$regValue = Get-ItemProperty -ErrorAction Stop -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\" | Select-Object -ExpandProperty NoLockScreenSlideshow

		if ($regValue -eq 1) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Registry value for NoLockScreenSlideshow differs from expected value")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		$obj | Add-Member NoteProperty Status("Registry path to NoLockScreenSlideshow does not exist.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-CC-000010: Registry Key | Slide Shows NoLockScreenSlideshow not found" -Level Error
	}
	catch {
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-CC-000010: $($error[0])" -Level Error
	}

	Write-Output $obj
}

# Hardened UNC paths must be defined to require mutual authentication and integrity for at
# least the \\*\SYSVOL and \\*\NETLOGON shares.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000090
# Group ID (Vulid): V-73509
# CCI: CCI-000366
#
# Additional security requirements are applied to Universal Naming Convention (UNC) paths specified
# in hardened UNC paths before allowing access to them. This aids in preventing tampering
# with or spoofing of connections to these paths.
function Test-SV-88161r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88161r1_rule")
	$obj | Add-Member NoteProperty Task("Hardened UNC paths must be defined to require mutual authentication and integrity for \\*\NETLOGON shares.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000090" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" `
		-Name "\\*\NETLOGON" `
		-ExpectedValue "RequireMutualAuthentication=1, RequireIntegrity=1" `
	| Write-Output
}

# Hardend Path \\*\SYSVOL
function Test-SV-88161r1_rule_2 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88161r1_rule_2")
	$obj | Add-Member NoteProperty Task("Hardened UNC paths must be defined to require mutual authentication and integrity for \\*\SYSVOL shares.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000090" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" `
		-Name "\\*\SYSVOL" `
		-ExpectedValue "RequireMutualAuthentication=1, RequireIntegrity=1" `
	| Write-Output
}

# Virtualization-based security must be enabled with the platform security level configured
# to Secure Boot or Secure Boot with DMA Protection.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000110
# Group ID (Vulid): V-73513
# CCI: CCI-000366
#
# Virtualization Based Security (VBS) provides the platform for the additional security features
# Credential Guard and virtualization-based protection of code integrity. Secure Boot is the
# minimum security level, with DMA protection providing additional memory protection. DMA
# Protection requires a CPU that supports input/output memory management unit (IOMMU).
function Test-SV-88165r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88165r1_rule")
	$obj | Add-Member NoteProperty Task("Virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection (EnableVirtualizationBasedSecurity).")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000110" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" `
		-Name "EnableVirtualizationBasedSecurity" `
		-ExpectedValue 1 `
	| Write-Output
}

function Test-SV-88165r1_rule_2 {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88165r1_rule_2")
	$obj | Add-Member NoteProperty Task("Virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection (RequirePlatformSecurityFeatures).")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000110" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" `
		-Name "RequirePlatformSecurityFeatures" `
		-ExpectedValue 3 `
	| Write-Output
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

# Credential Guard must be running on domain-joined systems.
# - - - - - - - - - - - - -
# StigID: WN16-CC-000120
# Group ID (Vulid): V-73515
# CCI: CCI-000366
#
# Credential Guard uses virtualization-based security to protect data that could be used in
# credential theft attacks if compromised. This authentication information, which was stored
# in the Local Security Authority (LSA) in previous versions of Windows, is isolated from
# the rest of operating system and can only be accessed by privileged system software.
function Test-SV-88167r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88167r1_rule")
	$obj | Add-Member NoteProperty Task("Credential Guard must be running on domain-joined systems.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000120" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" `
		-Name "LsaCfgFlags" `
		-ExpectedValue 1 `
	| Write-Output
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

# Virtualization-based protection of code integrity must be enabled on domain-joined systems.
#
# - - - - - - - - - - - - -
# StigID: WN16-CC-000130
# Group ID (Vulid): V-73517
# CCI: CCI-000366
#
# Virtualization-based protection of code integrity enforces kernel mode memory protections
# as well as protecting Code Integrity validation paths. This isolates the processes from
# the rest of the operating system and can only be accessed by privileged system software.
#
function Test-SV-88169r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88169r1_rule")
	$obj | Add-Member NoteProperty Task("Virtualization-based protection of code integrity must be enabled on domain-joined systems.")

	Test-RegistrySetting `
		-obj $obj `
		-StigId "WN16-CC-000130" `
		-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
		-Name "HypervisorEnforcedCodeIntegrity" `
		-ExpectedValue 1 `
	| Write-Output
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

# Anonymous SID/Name translation must not be allowed.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000250
# Group ID (Vulid): V-73665
# CCI: CCI-000366
#
# Allowing anonymous SID/Name translation can provide sensitive information for accessing a
# system. Only authorized users must be able to perform such translations.
function Test-SV-88329r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88329r1_rule")
	$obj | Add-Member NoteProperty Task("Anonymous SID/Name translation must not be allowed.")

	$anonymousTranslation = Get-SecPolSetting -SystemAccess -SystemAccessSetting LSAAnonymousNameLookup

	if ( $anonymousTranslation -eq 0 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Anonymous SID/Name translation not disabled.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-SO-000250: Anonymous SID/Name translation not disabled." -Level Error
	}

	Write-Output $obj
}

# Windows Server 2016 must be configured to force users to log off when their allowed logon
# hours expire.
# - - - - - - - - - - - - -
# StigID: WN16-SO-000370
# Group ID (Vulid): V-73689
# CCI: CCI-001133
#
# Limiting logon hours can help protect data by allowing access only during specified times.
# This setting controls whether users are forced to log off when their allowed logon hours
# expire. If logon hours are set for users, this must be enforced.
function Test-SV-88353r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88353r1_rule")
	$obj | Add-Member NoteProperty Task("Windows Server 2016 must be configured to force users to log off when their allowed logon hours expire.")

	$logoffHours = Get-SecPolSetting -SystemAccess -SystemAccessSetting ForceLogoffWhenHourExpire

	if ( $logoffHours -eq 1 ) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Force users to log off when their allowed logon hours expire not enabled.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-SO-000370: Force users to log off when their allowed logon hours expire not enabled." -Level Error
	}

	Write-Output $obj
}

# The Access Credential Manager as a trusted caller user right must not be assigned to any
# groups or accounts.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000010
# Group ID (Vulid): V-73729
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities. Accounts with the Access Credential Manager as a trusted caller user right
# may be able to retrieve the credentials of other accounts from Credential Manager.
function Test-SV-88393r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88393r1_rule")
	$obj | Add-Member NoteProperty Task("The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeTrustedCredManAccessPrivilege -ErrorAction Stop

		if ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Found account(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			$members = $members.Split(",")

			foreach ($entry in $members) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000010: Found unexpected $entry" -Level Error
			}
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Access this computer from the network user right must only be assigned to the Administrators
# and Authenticated Users groups on member servers.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000340
# Group ID (Vulid): V-73733
# CCI: CCI-000213
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Access this computer from the network user right may access
# resources on the system, and this right must be limited to those requiring it.
function Test-SV-88397r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88397r1_rule")
	$obj | Add-Member NoteProperty Task("The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers.")

	# SID for authenticated users *S-1-5-11
	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeNetworkLogonRight -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( ($member -ne "*S-1-5-11") -and ($member -ne "*S-1-5-32-544") ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000340: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Act as part of the operating system user right must not be assigned to any groups or
# accounts.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000030
# Group ID (Vulid): V-73735
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Act as part of the operating system user right can assume
# the identity of any user and gain access to resources that the user is authorized to access.
# Any accounts with this right can take complete control of a system.
function Test-SV-88399r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88399r1_rule")
	$obj | Add-Member NoteProperty Task("The Act as part of the operating system user right must not be assigned to any groups or accounts.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeTcbPrivilege -ErrorAction Stop

		if ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			$members = $members.Split(",")

			foreach ($entry in $members) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000030: Found unexpected $entry" -Level Error
			}
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000030: $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Allow log on locally user right must only be assigned to the Administrators group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000050
# Group ID (Vulid): V-73739
# CCI: CCI-000213
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Allow log on locally user right can log on interactively
# to a system.
function Test-SV-88403r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88403r1_rule")
	$obj | Add-Member NoteProperty Task("The Allow log on locally user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeInteractiveLogonRight -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000050: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Back up files and directories user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000070
# Group ID (Vulid): V-73743
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Back up files and directories user right can circumvent file
# and directory permissions and could allow access to sensitive data.
function Test-SV-88407r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88407r1_rule")
	$obj | Add-Member NoteProperty Task("The Back up files and directories user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeBackupPrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000070: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Create a pagefile user right must only be assigned to the Administrators group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000080
# Group ID (Vulid): V-73745
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Create a pagefile user right can change the size of a pagefile,
# which could affect system performance.
function Test-SV-88409r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88409r1_rule")
	$obj | Add-Member NoteProperty Task("The Create a pagefile user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeCreatePagefilePrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000080: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Create a token object user right must not be assigned to any groups or accounts.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000090
# Group ID (Vulid): V-73747
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Create a token object user right allows a process to create an access token.
# This could be used to provide elevated rights and compromise a system.
function Test-SV-88411r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88411r1_rule")
	$obj | Add-Member NoteProperty Task("The Create a token object user right must not be assigned to any groups or accounts.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeCreateTokenPrivilege -ErrorAction Stop

		if ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			$members = $members.Split(",")

			foreach ($entry in $members) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000090: Found unexpected $entry" -Level Error
			}
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Create global objects user right must only be assigned to Administrators, Service, Local
# Service, and Network Service.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000100
# Group ID (Vulid): V-73749
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Create global objects user right can create objects that
# are available to all sessions, which could affect processes in other users sessions.
function Test-SV-88413r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88413r1_rule")
	$obj | Add-Member NoteProperty Task("The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.")

	# SID for administrator group S-1-5-32-544
	# SID for local service  S-1-5-19
	# SID for network service S-1-5-20
	# SID for service S-1-5-6
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeCreateGlobalPrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$reference = @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")
		$found = @()

		foreach ($member in $members) {
			if ($reference -notcontains $member) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000100: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Create permanent shared objects user right must not be assigned to any groups or accounts.
#
# - - - - - - - - - - - - -
# StigID: WN16-UR-000110
# Group ID (Vulid): V-73751
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Create permanent shared objects user right could expose sensitive
# data by creating shared objects.
function Test-SV-88415r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88415r1_rule")
	$obj | Add-Member NoteProperty Task("The Create permanent shared objects user right must not be assigned to any groups or accounts.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeCreatePermanentPrivilege -ErrorAction Stop

		if ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			$members = $members.Split(",")

			foreach ($entry in $members) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000110: Found unexpected $entry" -Level Error
			}
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Create symbolic links user right must only be assigned to the Administrators group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000120
# Group ID (Vulid): V-73753
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Create symbolic links user right can create pointers to other
# objects, which could expose the system to attack.
function Test-SV-88417r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88417r1_rule")
	$obj | Add-Member NoteProperty Task("The Create symbolic links user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeCreateSymbolicLinkPrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000120: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Debug programs user right must only be assigned to the Administrators group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000130
# Group ID (Vulid): V-73755
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Debug programs user right can attach a debugger to any process
# or to the kernel, providing complete access to sensitive and critical operating system components.
# This right is given to Administrators in the default configuration.
function Test-SV-88419r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88419r1_rule")
	$obj | Add-Member NoteProperty Task("The Debug programs user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeDebugPrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000130: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Deny access to this computer from the network user right on member servers must be configured
# to prevent access from highly privileged domain accounts and local accounts on domain systems,
# and from unauthenticated access on all systems.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000370
# Group ID (Vulid): V-73759
# CCI: CCI-000213
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Deny access to this computer from the network user right defines the accounts
# that are prevented from logging on from the network.In an Active Directory Domain, denying
# logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate
# the risk of privilege escalation from credential theft attacks, which could lead to the
# compromise of an entire domain.Local accounts on domain-joined systems must also be assigned
# this right to decrease the risk of lateral movement resulting from credential theft attacks.The
# Guests group must be assigned this right to prevent unauthenticated access.
function Test-SV-88423r1_rule {
	[CmdletBinding()]
	Param(
		[switch]$IsDomainIntegrated
	)
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88423r1_rule")
	$obj | Add-Member NoteProperty Task("The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems.")

	# guest group is denied access on all systems
	$reference = @("*S-1-5-32-546")

	if ($IsDomainIntegrated) {
		try {
			$domainSID = Get-PrimaryDomainSID
			# enterprise admins
			$reference += "*$domainSID-519"
			# domain admins
			$reference += "*$domainSID-512"
		}
		catch {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Could not get SIDs from domain accounts" -Level Error
		}
	}

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeDenyNetworkLogonRight -ErrorAction Stop
		$members = $members.Split(",")

		$compliant = Compare-Object -ReferenceObject $reference -DifferenceObject $members -ErrorAction Stop

		if ( $compliant.Count -ne 0 ) {
			foreach ($entry in $compliant) {
				if ( $entry.SideIndicator -eq "<=" ) {
					$found += $entry.InputObject + "; "
				}
			}

			$obj | Add-Member NoteProperty Status("Not compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000370: Missing SIDs $found" -Level Error
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}


# The Deny log on as a batch job user right on member servers must be configured to prevent
# access from highly privileged domain accounts on domain systems and from unauthenticated
# access on all systems.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000380
# Group ID (Vulid): V-73763
# CCI: CCI-000213
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Deny log on as a batch job user right defines accounts that are prevented
# from logging on to the system as a batch job, such as Task Scheduler.In an Active Directory
# Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks, which
# could lead to the compromise of an entire domain.The Guests group must be assigned to prevent
# unauthenticated access.
function Test-SV-88427r1_rule {
	[CmdletBinding()]
	Param(
		[switch]$IsDomainIntegrated
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88427r1_rule")
	$obj | Add-Member NoteProperty Task("The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.")

	# guest group is denied access on all systems
	$reference = @("*S-1-5-32-546")

	if ($IsDomainIntegrated) {
		try {
			$domainSID = Get-PrimaryDomainSID
			# enterprise admins
			$reference += "*$domainSID-519"
			# domain admins
			$reference += "*$domainSID-512"
		}
		catch {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Could not get SIDs from domain accounts" -Level Error
		}
	}

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeDenyBatchLogonRight -ErrorAction Stop
		$members = $members.Split(",")

		$compliant = Compare-Object -ReferenceObject $reference -DifferenceObject $members -ErrorAction Stop

		if ( $compliant.Count -ne 0 ) {
			foreach ($entry in $compliant) {
				if ( $entry.SideIndicator -eq "<=" ) {
					$found += $entry.InputObject + "; "
				}
			}

			$obj | Add-Member NoteProperty Status("Not compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000380: Missing SIDs $found" -Level Error
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Deny log on as a service user right on member servers must be configured to prevent access
# from highly privileged domain accounts on domain systems. No other groups or accounts must
# be assigned this right.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000390
# Group ID (Vulid): V-73767
# CCI: CCI-000213
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Deny log on as a service user right defines accounts that are denied logon
# as a service.In an Active Directory Domain, denying logons to the Enterprise Admins and
# Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation
# from credential theft attacks, which could lead to the compromise of an entire domain.Incorrect
# configurations could prevent services from starting and result in a DoS.
function Test-SV-88431r1_rule {
	[CmdletBinding()]
	Param(
		[switch]$IsDomainIntegrated
	)
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88431r1_rule")
	$obj | Add-Member NoteProperty Task("The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeDenyServiceLogonRight -ErrorAction Stop
		$members = $members.Split(",")

		if ($IsDomainIntegrated) {
			# if machine is in a domain, add enterprise admins and domain admins
			try {
				$reference = @()
				$domainSID = Get-PrimaryDomainSID
				# enterprise admins
				$reference += "*$domainSID-519"
				# domain admins
				$reference += "*$domainSID-512"

				$compliant = Compare-Object -ReferenceObject $reference -DifferenceObject $members -ErrorAction Stop

				if ( $compliant.Count -ne 0 ) {
					foreach ($entry in $compliant) {
						if ( $entry.SideIndicator -eq "<=" ) {
							$found += $entry.InputObject + "; "
						}
					}

					$obj | Add-Member NoteProperty Status("Not compliant")
					$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

					Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000390: Missing SIDs $found" -Level Error
				}
				else {
					$obj | Add-Member NoteProperty Status("Compliant")
					$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
				}
			}
			catch {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Could not get SIDs from domain accounts" -Level Error
			}
		}
		elseif ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("No compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000390: $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Deny log on locally user right on member servers must be configured to prevent access
# from highly privileged domain accounts on domain systems and from unauthenticated access
# on all systems.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000400
# Group ID (Vulid): V-73771
# CCI: CCI-000213
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Deny log on locally user right defines accounts that are prevented from
# logging on interactively.In an Active Directory Domain, denying logons to the Enterprise
# Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege
# escalation from credential theft attacks, which could lead to the compromise of an entire
# domain.The Guests group must be assigned this right to prevent unauthenticated access.
function Test-SV-88435r1_rule {
	[CmdletBinding()]
	Param(
		[switch]$IsDomainIntegrated
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88435r1_rule")
	$obj | Add-Member NoteProperty Task("The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems.")

	# guest group is denied access on all systems
	$reference = @("*S-1-5-32-546")

	if ($IsDomainIntegrated) {
		try {
			$domainSID = Get-PrimaryDomainSID
			# enterprise admins
			$reference += "*$domainSID-519"
			# domain admins
			$reference += "*$domainSID-512"
		}
		catch {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Could not get SIDs from domain accounts" -Level Error
		}
	}

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeDenyInteractiveLogonRight -ErrorAction Stop
		$members = $members.Split(",")

		$compliant = Compare-Object -ReferenceObject $reference -DifferenceObject $members -ErrorAction Stop

		if ( $compliant.Count -ne 0 ) {
			foreach ($entry in $compliant) {
				if ( $entry.SideIndicator -eq "<=" ) {
					$found += $entry.InputObject + "; "
				}
			}

			if ($found) {
				$obj | Add-Member NoteProperty Status("Not compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000400: Missing SIDs $found" -Level Error
			}
			else {
				$obj | Add-Member NoteProperty Status("Compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000400 $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Deny log on through Remote Desktop Services user right on member servers must be configured
# to prevent access from highly privileged domain accounts and all local accounts on domain
# systems and from unauthenticated access on all systems.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000410
# Group ID (Vulid): V-73775
# CCI: CCI-002314
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Deny log on through Remote Desktop Services user right defines the accounts
# that are prevented from logging on using Remote Desktop Services.In an Active Directory
# Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks, which
# could lead to the compromise of an entire domain.Local accounts on domain-joined systems
# must also be assigned this right to decrease the risk of lateral movement resulting from
# credential theft attacks.The Guests group must be assigned this right to prevent unauthenticated
# access.
function Test-SV-88439r1_rule {
	[CmdletBinding()]
	Param(
		[switch]$IsDomainIntegrated
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88439r1_rule")
	$obj | Add-Member NoteProperty Task("The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems.")

	# guest group is denied access on all systems
	$reference = @("*S-1-5-32-546")

	if ($IsDomainIntegrated) {
		try {
			$domainSID = Get-PrimaryDomainSID
			# enterprise admins
			$reference += "*$domainSID-519"
			# domain admins
			$reference += "*$domainSID-512"
		}
		catch {
			Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "Could not get SIDs from domain accounts" -Level Error
		}
	}

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeDenyRemoteInteractiveLogonRight -ErrorAction Stop
		$members = $members.Split(",")

		$compliant = Compare-Object -ReferenceObject $reference -DifferenceObject $members -ErrorAction Stop

		if ( $compliant.Count -ne 0 ) {
			foreach ($entry in $compliant) {
				if ( $entry.SideIndicator -eq "<=" ) {
					$found += $entry.InputObject + "; "
				}
			}

			if ($found) {
				$obj | Add-Member NoteProperty Status("Not compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000410: Missing SIDs $found" -Level Error
			}
			else {
				$obj | Add-Member NoteProperty Status("Compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000410 $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Enable computer and user accounts to be trusted for delegation user right must not be
# assigned to any groups or accounts on member servers.
# - - - - - - - - - - - - -
# StigID: WN16-MS-000420
# Group ID (Vulid): V-73779
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Enable computer and user accounts to be trusted for delegation user right
# allows the Trusted for Delegation setting to be changed. This could allow unauthorized users
# to impersonate other users.
function Test-SV-88443r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88443r1_rule")
	$obj | Add-Member NoteProperty Task("The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on member servers.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeEnableDelegationPrivilege -ErrorAction Stop

		if ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			$members = $members.Split(",")

			foreach ($entry in $members) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-MS-000420: Found unexpected $entry" -Level Error
			}
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Force shutdown from a remote system user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000200
# Group ID (Vulid): V-73781
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Force shutdown from a remote system user right can remotely
# shut down a system, which could result in a denial of service.
function Test-SV-88445r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88445r1_rule")
	$obj | Add-Member NoteProperty Task("The Force shutdown from a remote system user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeRemoteShutdownPrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000200: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Generate security audits user right must only be assigned to Local Service and Network
# Service.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000210
# Group ID (Vulid): V-73783
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Generate security audits user right specifies users and processes that
# can generate Security Log audit records, which must only be the system service accounts
# defined.
function Test-SV-88447r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88447r1_rule")
	$obj | Add-Member NoteProperty Task("The Generate security audits user right must only be assigned to Local Service and Network Service.")

	# SID for local service  S-1-5-19
	# SID for network service S-1-5-20
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeAuditPrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$reference = @("*S-1-5-19", "*S-1-5-20")
		$found = @()

		foreach ($member in $members) {
			if ($reference -notcontains $member) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000210: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Impersonate a client after authentication user right must only be assigned to Administrators,
# Service, Local Service, and Network Service.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000220
# Group ID (Vulid): V-73785
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Impersonate a client after authentication user right allows a program to
# impersonate another user or account to run on their behalf. An attacker could use this to
# elevate privileges.
function Test-SV-88449r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88449r1_rule")
	$obj | Add-Member NoteProperty Task("The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.")

	# SID for administrator group S-1-5-32-544
	# SID for local service  S-1-5-19
	# SID for network service S-1-5-20
	# SID for service S-1-5-6
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeImpersonatePrivilege -ErrorAction Stop

		$members = $members.Split(",")
		$reference = @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")
		$found = @()

		foreach ($member in $members) {
			if ($reference -notcontains $member) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000220: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Increase scheduling priority user right must only be assigned to the Administrators group.
#
# - - - - - - - - - - - - -
# StigID: WN16-UR-000230
# Group ID (Vulid): V-73787
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Increase scheduling priority user right can change a scheduling
# priority, causing performance issues or a denial of service.
function Test-SV-88451r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88451r1_rule")
	$obj | Add-Member NoteProperty Task("The Increase scheduling priority user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeIncreaseBasePriorityPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000230: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Load and unload device drivers user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000240
# Group ID (Vulid): V-73789
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Load and unload device drivers user right allows a user to load device
# drivers dynamically on a system. This could be used by an attacker to install malicious
# code.
function Test-SV-88453r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88453r1_rule")
	$obj | Add-Member NoteProperty Task("The Load and unload device drivers user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeLoadDriverPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000240: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Lock pages in memory user right must not be assigned to any groups or accounts.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000250
# Group ID (Vulid): V-73791
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.The Lock pages in memory user right allows physical memory to be assigned to
# processes, which could cause performance issues or a denial of service.
function Test-SV-88455r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88455r1_rule")
	$obj | Add-Member NoteProperty Task("The Lock pages in memory user right must not be assigned to any groups or accounts.")

	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeLockMemoryPrivilege -ErrorAction Stop

		if ( $null -eq $members ) {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
		else {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)

			$members = $members.Split(",")

			foreach ($entry in $members) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000250: Found unexpected $entry" -Level Error
			}
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Manage auditing and security log user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000260
# Group ID (Vulid): V-73793
# CCI: CCI-000162 CCI-000163 CCI-000164 CCI-000171 CCI-001914
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Manage auditing and security log user right can manage the
# security log and change auditing configurations. This could be used to clear evidence of
# tampering.Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029,
# SRG-OS-000063-GPOS-00032, SRG-OS-000337-GPOS-00129
function Test-SV-88457r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88457r1_rule")
	$obj | Add-Member NoteProperty Task("The Manage auditing and security log user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeSecurityPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000260: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Modify firmware environment values user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000270
# Group ID (Vulid): V-73795
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Modify firmware environment values user right can change
# hardware configuration environment variables. This could result in hardware failures or
# a denial of service.
function Test-SV-88459r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88459r1_rule")
	$obj | Add-Member NoteProperty Task("The Modify firmware environment values user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeSystemEnvironmentPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000270: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Perform volume maintenance tasks user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000280
# Group ID (Vulid): V-73797
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Perform volume maintenance tasks user right can manage volume
# and disk configurations. This could be used to delete volumes, resulting in data loss or
# a denial of service.
function Test-SV-88461r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88461r1_rule")
	$obj | Add-Member NoteProperty Task("The Perform volume maintenance tasks user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeSystemEnvironmentPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000280: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000280: $($error[0])" -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Profile single process user right must only be assigned to the Administrators group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000290
# Group ID (Vulid): V-73799
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Profile single process user right can monitor non-system
# processes performance. An attacker could use this to identify processes to attack.
function Test-SV-88463r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88463r1_rule")
	$obj | Add-Member NoteProperty Task("The Profile single process user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeProfileSingleProcessPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000290: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Restore files and directories user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000300
# Group ID (Vulid): V-73801
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Restore files and directories user right can circumvent file
# and directory permissions and could allow access to sensitive data. It could also be used
# to overwrite more current data.
function Test-SV-88465r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88465r1_rule")
	$obj | Add-Member NoteProperty Task("The Restore files and directories user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeRestorePrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000300: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
		$obj | Add-Member NoteProperty Status("Error")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}

# The Take ownership of files or other objects user right must only be assigned to the Administrators
# group.
# - - - - - - - - - - - - -
# StigID: WN16-UR-000310
# Group ID (Vulid): V-73803
# CCI: CCI-002235
#
# Inappropriate granting of user rights can provide system, administrative, and other high-level
# capabilities.Accounts with the Take ownership of files or other objects user right can take
# ownership of objects and make changes.
function Test-SV-88467r1_rule {
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("SV-88467r1_rule")
	$obj | Add-Member NoteProperty Task("The Take ownership of files or other objects user right must only be assigned to the Administrators group.")

	# SID for administrator group *S-1-5-32-544
	try {
		$members = Get-SecPolSetting -PrivilegeRights -PrivilegeRightsSetting SeTakeOwnershipPrivilege -ErrorAction Stop
		$members = $members.Split(",")
		$found = @()

		foreach ($member in $members) {
			if ( $member -ne "*S-1-5-32-544" ) {
				$found += $member
			}
		}

		if ($found) {
			$obj | Add-Member NoteProperty Status("Found member(s).")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			foreach ($entry in $found) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message "WN16-UR-000310: Found unexpected $entry" -Level Error
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Compliant")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
		}
	}
	catch {
		Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Message $error[0] -Level Error
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

		if ( $account.Disabled ) {
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

#region CIS Advanced Audit Policy settings Audit functions
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

function Test-AuditPolicySetting {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateSet('Security System Extension',
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
		[System.String]$Subcategory,

		[Parameter(Mandatory = $true)]
		[ValidateSet('Success', 'Failure', 'Success and Failure', 'No Auditing')]
		[System.String]$AuditFlag,

		[Parameter(Mandatory = $true)]
		[System.String]$ID
	)

	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name("$ID")
	$obj | Add-Member NoteProperty Task("$Subcategory is set to $AuditFlag")

	# Get the audit policy for the subcategory $subcategory
	$subCategoryGUID = Get-AuditPolicySubcategoryGUID -Subcategory $Subcategory
	$auditPolicyString = auditpol /get /subcategory:"$subCategoryGUID"

	# auditpol does not throw exceptions, so test the results and throw if needed
	if ($LASTEXITCODE -ne 0) {
		$errorString = "'auditpol /get /subcategory:'$subCategoryGUID' returned with exit code $LASTEXITCODE"
		throw [System.ArgumentException] $errorString
		Write-Error -Message $errorString
	}

	if ($null -ne $auditPolicyString) {
		# Remove empty lines and headers
		$line = $auditPolicyString `
			| Where-Object { $_ } `
			| Select-Object -Skip 3

		if ($line -match "(No Auditing|Success and Failure|Success|Failure)$") {
			$setting = $Matches[0]

			if ($setting -eq $AuditFlag) {
				$obj | Add-Member NoteProperty Status("Compliant")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
			}
			else {
				$obj | Add-Member NoteProperty Status("Set to: $setting")
				$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
			}
		}
		else {
			$obj | Add-Member NoteProperty Status("Couldn't get setting.")
			$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
		}
	}
	else {
		$obj | Add-Member NoteProperty Status("Couldn't get setting. Auditpol returned nothing.")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}

	Write-Output $obj
}
#endregion
#endregion

function Get-DisaAuditResult {
	Param(
		[switch] $PerformanceOptimized
	)

	Test-SV-88139r1_rule
	Test-SV-88147r1_rule
	Test-SV-88149r1_rule
	Test-SV-88151r1_rule
	Test-SV-88153r1_rule
	Test-SV-88155r1_rule
	Test-SV-88157r1_rule
	Test-SV-88159r1_rule
	Test-SV-88163r1_rule
	Test-SV-88173r1_rule
	Test-SV-88177r1_rule
	Test-SV-88179r1_rule
	Test-SV-88181r1_rule
	Test-SV-88185r1_rule
	Test-SV-88187r1_rule
	Test-SV-88189r1_rule
	Test-SV-88197r1_rule
	Test-SV-88201r1_rule
	Test-SV-88203r1_rule
	Test-SV-88207r1_rule
	Test-SV-88209r1_rule
	Test-SV-88211r1_rule
	Test-SV-88213r1_rule
	Test-SV-88215r1_rule
	Test-SV-88217r1_rule
	Test-SV-88219r1_rule
	Test-SV-88221r1_rule
	Test-SV-88223r1_rule
	Test-SV-88225r1_rule
	Test-SV-88227r1_rule
	Test-SV-88229r1_rule
	Test-SV-88231r1_rule
	Test-SV-88233r1_rule
	Test-SV-88235r1_rule
	Test-SV-88237r1_rule
	Test-SV-88239r1_rule
	Test-SV-88241r1_rule
	Test-SV-88243r1_rule
	Test-SV-88245r1_rule
	Test-SV-88247r1_rule
	Test-SV-88249r1_rule
	Test-SV-88251r1_rule
	Test-SV-88253r1_rule
	Test-SV-88255r1_rule
	Test-SV-88257r1_rule
	Test-SV-88259r1_rule
	Test-SV-88261r1_rule
	Test-SV-88263r1_rule
	Test-SV-88265r1_rule
	Test-SV-88267r1_rule
	Test-SV-88285r1_rule
	Test-SV-88291r1_rule
	Test-SV-88293r1_rule
	Test-SV-88295r1_rule
	Test-SV-88297r1_rule
	Test-SV-88299r1_rule
	Test-SV-88301r1_rule
	Test-SV-88303r1_rule
	Test-SV-88305r1_rule
	Test-SV-88307r1_rule
	Test-SV-88309r1_rule
	Test-SV-88311r1_rule
	Test-SV-88313r1_rule
	Test-SV-88315r1_rule
	Test-SV-88317r1_rule
	Test-SV-88319r1_rule
	Test-SV-88321r1_rule
	Test-SV-88323r1_rule
	Test-SV-88325r1_rule
	Test-SV-88327r1_rule
	Test-SV-88331r1_rule
	Test-SV-88333r1_rule
	Test-SV-88335r1_rule
	Test-SV-88337r1_rule
	Test-SV-88339r1_rule
	Test-SV-88341r1_rule
	Test-SV-88343r1_rule
	Test-SV-88345r1_rule
	Test-SV-88347r1_rule
	Test-SV-88349r1_rule
	Test-SV-88351r1_rule
	Test-SV-88355r1_rule
	Test-SV-88357r1_rule
	Test-SV-88359r1_rule
	Test-SV-88361r1_rule
	Test-SV-88363r1_rule
	Test-SV-88365r1_rule
	Test-SV-88367r1_rule
	Test-SV-88369r1_rule
	Test-SV-88371r1_rule
	Test-SV-88373r1_rule
	Test-SV-88375r1_rule
	Test-SV-88377r1_rule
	Test-SV-88379r1_rule
	Test-SV-88381r1_rule
	Test-SV-88383r1_rule
	Test-SV-88385r1_rule
	Test-SV-88387r1_rule
	Test-SV-88389r1_rule
	Test-SV-88391r1_rule
	Test-SV-88473r1_rule
	Test-SV-87875r2_rule
	Test-SV-87889r1_rule
	Test-SV-87891r1_rule
	Test-SV-87899r1_rule
	Test-SV-87901r1_rule
	Test-SV-87903r1_rule
	Test-SV-87903r1_rule_2
	Test-SV-87905r1_rule
	Test-SV-87907r1_rule
	Test-SV-87907r1_rule_2
	Test-SV-87907r1_rule_3
	Test-SV-87909r1_rule
	Test-SV-87911r1_rule
	Test-SV-87913r2_rule
	Test-SV-87915r2_rule
	Test-SV-87919r1_rule
	if (-not $PerformanceOptimized) {
		Test-SV-87923r1_rule
	}
	Test-SV-87925r1_rule
	Test-SV-87931r1_rule
	Test-SV-87939r1_rule
	Test-SV-87941r1_rule
	Test-SV-87943r1_rule
	Test-SV-87945r1_rule
	Test-SV-87947r1_rule
	Test-SV-87949r1_rule
	Test-SV-87951r1_rule
	Test-SV-87953r1_rule
	Test-SV-87961r2_rule
	Test-SV-87963r1_rule
	Test-SV-87965r1_rule
	Test-SV-87967r1_rule
	Test-SV-87969r1_rule
	Test-SV-87971r1_rule
	Test-SV-87973r1_rule
	Test-SV-88057r1_rule
	Test-SV-88059r1_rule
	Test-SV-88061r1_rule
	Test-SV-88145r1_rule
	Test-SV-88161r1_rule
	Test-SV-88161r1_rule_2
	Test-SV-88165r1_rule
	Test-SV-88165r1_rule_2
	Test-SV-88165r1_rule_3
	Test-SV-88167r1_rule
	Test-SV-88167r1_rule_2
	Test-SV-88169r1_rule
	Test-SV-88169r1_rule_2
	Test-SV-88287r1_rule
	Test-SV-88289r1_rule
	Test-SV-88329r1_rule
	Test-SV-88353r1_rule
	Test-SV-88393r1_rule
	Test-SV-88397r1_rule
	Test-SV-88399r1_rule
	Test-SV-88403r1_rule
	Test-SV-88407r1_rule
	Test-SV-88409r1_rule
	Test-SV-88411r1_rule
	Test-SV-88413r1_rule
	Test-SV-88415r1_rule
	Test-SV-88417r1_rule
	Test-SV-88419r1_rule
	Test-SV-88423r1_rule -IsDomainIntegrated
	Test-SV-88427r1_rule -IsDomainIntegrated
	Test-SV-88431r1_rule -IsDomainIntegrated
	Test-SV-88435r1_rule -IsDomainIntegrated
	Test-SV-88439r1_rule -IsDomainIntegrated
	Test-SV-88443r1_rule
	Test-SV-88445r1_rule
	Test-SV-88447r1_rule
	Test-SV-88449r1_rule
	Test-SV-88451r1_rule
	Test-SV-88453r1_rule
	Test-SV-88455r1_rule
	Test-SV-88457r1_rule
	Test-SV-88459r1_rule
	Test-SV-88461r1_rule
	Test-SV-88463r1_rule
	Test-SV-88465r1_rule
	Test-SV-88467r1_rule
	Test-SV-88475r1_rule
}

function Get-CisAuditPolicyResult {
	Test-AuditPolicySetting -Subcategory "Credential Validation" -AuditFlag 'Success and Failure' -id "CIS 17.1.1"
	Test-AuditPolicySetting -Subcategory "Application Group Management" -AuditFlag 'Success and Failure' -id "CIS 17.2.1"
	Test-AuditPolicySetting -Subcategory "Computer Account Management" -AuditFlag 'Success and Failure' -id "CIS 17.2.2"
	Test-AuditPolicySetting -Subcategory "Other Account Management Events" -AuditFlag 'Success and Failure' -id "CIS 17.2.4"
	Test-AuditPolicySetting -Subcategory "Security Group Management" -AuditFlag 'Success and Failure' -id "CIS 17.2.5"
	Test-AuditPolicySetting -Subcategory "User Account Management" -AuditFlag 'Success and Failure' -id "CIS 17.2.5"
	Test-AuditPolicySetting -Subcategory "Plug and Play Events" -AuditFlag 'Success' -id "CIS 17.3.1"
	Test-AuditPolicySetting -Subcategory "Process Creation" -AuditFlag 'Success' -id "CIS 17.3.2"
	Test-AuditPolicySetting -Subcategory "Account Lockout" -AuditFlag 'Success and Failure' -id "CIS 17.5.1"
	Test-AuditPolicySetting -Subcategory "Group Membership" -AuditFlag 'Success' -id "CIS 17.5.2"
	Test-AuditPolicySetting -Subcategory "Logoff" -AuditFlag 'Success' -id "CIS 17.5.3"
	Test-AuditPolicySetting -Subcategory "Logon" -AuditFlag 'Success and Failure' -id "CIS 17.5.4"
	Test-AuditPolicySetting -Subcategory "Other Logon/Logoff Events" -AuditFlag 'Success and Failure' -id "CIS 17.5.5"
	Test-AuditPolicySetting -Subcategory "Special Logon" -AuditFlag 'Success' -id "CIS 17.5.6"
	Test-AuditPolicySetting -Subcategory "Removable Storage" -AuditFlag 'Success and Failure' -id "CIS 17.6.1"
	Test-AuditPolicySetting -Subcategory "Audit Policy Change" -AuditFlag 'Success and Failure' -id "CIS 17.7.1"
	Test-AuditPolicySetting -Subcategory "Authentication Policy Change" -AuditFlag 'Success' -id "CIS 17.7.2"
	Test-AuditPolicySetting -Subcategory "Authorization Policy Change" -AuditFlag 'Success' -id "CIS 17.7.3"
	Test-AuditPolicySetting -Subcategory "Sensitive Privilege Use" -AuditFlag 'Success and Failure' -id "CIS 17.8.1"
	Test-AuditPolicySetting -Subcategory "IPsec Driver" -AuditFlag 'Success and Failure' -id "CIS 17.9.1"
	Test-AuditPolicySetting -Subcategory "Other System Events" -AuditFlag 'Success and Failure' -id "CIS 17.9.2"
	Test-AuditPolicySetting -Subcategory "Security State Change" -AuditFlag 'Success' -id "CIS 17.9.3"
	Test-AuditPolicySetting -Subcategory "Security System Extension" -AuditFlag 'Success and Failure' -id "CIS 17.9.4"
	Test-AuditPolicySetting -Subcategory "System Integrity" -AuditFlag 'Success and Failure' -id "CIS 17.9.5"
}

#region Report-Generation
<#
	In this section the HTML report gets build and saved to the desired destination set by parameter saveTo
#>

function Get-WindowsServer2016HtmlReport {
	param (
		[string] $Path = "$($env:HOMEPATH)\Documents\$(Get-Date -UFormat %Y%m%d_%H%M)_auditreport.html",

		[switch] $DarkMode,

		[switch] $PerformanceOptimized
	)

	[hashtable[]]$sections = @(
		@{
			Title = "DISA Settings"
			AuditInfos = Get-DisaAuditResult -PerfomanceOptimized:$PerformanceOptimized | Convert-ToAuditInfo | Sort-Object -Property Id
		},
		@{
			Title = "CIS advanced audit policy settings"
			AuditInfos = Get-CisAuditPolicyResult | Convert-ToAuditInfo
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
#endregion