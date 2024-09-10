using namespace Microsoft.PowerShell.Commands

#region Initialization

$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
. "$RootPath\Helpers\HashHelper.ps1"

$script:atapReportsPath = $env:ATAPReportPath
if (-not $script:atapReportsPath) {
	$script:atapReportsPath = [Environment]::GetFolderPath('MyDocuments') | Join-Path -ChildPath 'ATAPReports'
}
#endregion

#region Classes
class AuditTest {
	[string] $Id
	[string] $Task
	[hashtable[]] $Constraints
	[scriptblock] $Test
}

enum AuditInfoStatus {
	True
	False
	Warning
	None
	Error
}

class AuditInfo {
	[string] $Id
	[string] $Task
	[AuditInfoStatus] $Status
	[string] $Message
}

class ReportSection {
	[string] $Title
	[string] $Description
	[AuditInfo[]] $AuditInfos
	[ReportSection[]] $SubSections
}

class Report {
	[string] $Title
	[string] $ModuleName
	[string] $AuditorVersion
	[hashtable] $HostInformation
	[string[]] $BasedOn
	[ReportSection[]] $Sections
	[RSFullReport] $RSReport
	[FoundationReport] $FoundationReport
}


###################################################
#######    SYSTEM INFORMATION Classes    ##########
###################################################
class SystemInformation {
	[SoftwareInformation] $SoftwareInformation
	[HardwareInformation] $HardwareInformation
}

class SoftwareInformation {
	[string] $Hostname
	[string] $SystemUptime
	[string] $OperatingSystem
	[string] $BuildNumber
	[string] $OSArchitecture
	[string] $LicenseStatus
	[string] $InstallationLanguage
	[string] $DomainRole
	[string] $KernelVersion
}

class HardwareInformation {
	[string] $SystemManufacturer
	[string] $SystemSKU
	[string] $SystemModel
	[string] $SystemSerialnumber
	[string] $BiosVersion
	[string] $FreeDiskSpace
	[string] $FreePhysicalMemory
}
### Begin Foundation Classes ###
class FoundationReport {
	[ReportSection[]] $Sections
}
### End Foundation Classes

# RiskScore Classes
enum RSEndResult {
	Critical
	High
	Medium
	Low
	Unknown
}

class RSFullReport {
	[RSSeverityReport] $RSSeverityReport
	[RSQuantityReport] $RSQuantityReport
}

class RSSeverityReport {
	[AuditInfo[]] $AuditInfos
	[ResultTable[]] $ResultTable
	[RSEndResult] $Endresult
}

class RSQuantityReport {

}

class ResultTable {
	[int] $Success
	[int] $Failed
}

#endregion

#region helpers
function IsIn-FullLanguageMode {
	try {
		$languageMode = $ExecutionContext.SessionState.LanguageMode
		if ($languageMode -eq "FullLanguage"){
			return $true
		}
	} catch {
		return $false
	}
	# returns alternate language modes if not FullLanguage
	return $languageMode
}

function Start-ModuleTest {
	$moduleList = @(Get-Module -ListAvailable).Name | Select-Object -Unique
	$necessaryModules = @(
		"Microsoft.PowerShell.LocalAccounts",
		"Microsoft.PowerShell.Management",
		"Microsoft.PowerShell.Security",
		"Microsoft.PowerShell.Utility",
		"TrustedPlatformModule",
		"NetSecurity",
		"CimCmdlets",
		"SmbShare",
		"Defender",
		"DISM"
		#Modules only necessary for specific server tests
		#"IISAdministration",
		#"SQLServer",
	)
	$missingModules = @()
	foreach ($module in $necessaryModules) {
		if ($moduleList -notcontains $module) {
			$missingModules += $module
		}
	}

	if ($missingModules.Count -gt 0) {
		Write-Warning "Missing module(s) found. Missing modules can lead to errors. Following modules are missing:"
		for ($i = 0; $i -lt $missingModules.Count; $i++) {
			Write-Warning $missingModules[$i]
		}
		Write-Warning "Check out this link on how to install modules: https://learn.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershellget-3.x"
	}

}

function GetLicenseStatus {
	param(
		$SkipLicenseCheck
	)
	if ($SkipLicenseCheck -eq $false) {
		Write-Host "Checking operating system activation status. This may take a while..."
		$licenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where { $_.PartialProductKey } | select Description, LicenseStatus -ExpandProperty LicenseStatus)
		switch ($licenseStatus) {
			"0" { $lcStatus = "Unlicensed" }
			"1" { $lcStatus = "Licensed" }
			"2" { $lcStatus = "OOBGrace" }
			"3" { $lcStatus = "OOTGrace" }
			"4" { $lcStatus = "NonGenuineGrace" }
			"5" { $lcStatus = "Notification" }
			"6" { $lcStatus = "ExtendedGrace" }
		}
		return $lcStatus
	}
	else {
		return "License check has been skipped."
	}
}

function Test-ArrayEqual {
	[OutputType([bool])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[AllowNull()]
		[AllowEmptyCollection()]
		[array]
		$Array1,

		[Parameter(Mandatory = $true)]
		[AllowNull()]
		[AllowEmptyCollection()]
		[array]
		$Array2
	)

	if ($null -eq $Array1) {
		$Array1 = @()
	}

	if ($null -eq $Array2) {
		$Array2 = @()
	}

	if ($Array1.Count -ne $Array2.Count) {
		return $false
	}

	foreach ($a in $Array1) {
		if ($a -notin $Array2) {
			return $false
		}
	}
	return $true
}

function Get-LicenseStatus {
	$licenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where { $_.PartialProductKey } | select Description, LicenseStatus -ExpandProperty LicenseStatus)
	switch ($licenseStatus) {
		"0" { $lcStatus = "Unlicensed" }
		"1" { $lcStatus = "Licensed" }
		"2" { $lcStatus = "OOBGrace" }
		"3" { $lcStatus = "OOTGrace" }
		"4" { $lcStatus = "NonGenuineGrace" }
		"5" { $lcStatus = "Notification" }
		"6" { $lcStatus = "ExtendedGrace" }
	}
	return $lcStatus
}


# Get domain role
# 0 {"Standalone Workstation"}
# 1 {"Member Workstation"}
# 2 {"Standalone Server"}
# 3 {"Member Server"}
# 4 {"Backup Domain Controller"}
# 5 {"Primary Domain Controller"}
function Get-DomainRole {
	$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole
	switch ($domainRole) {
		0 { $result = "Standalone Workstation" }
		1 { $result = "Member Workstation" }
		2 { $result = "Standalone Server" }
		3 { $result = "Member Server" }
		4 { $result = "Backup Domain Controller" }
		5 { $result = "Primary Domain Controller" }
	}
	return $result
}

function checkReportNameWithOSSystem {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$ReportName
	)
	# helpers
	function handleReportNameDiscrepancy {
		param (
			[Parameter()]
			[string]
			$ReportName,
			[Parameter()]
			[string]
			$OsName,
			[Parameter()]
			[bool]
			$ShouldBeStandAlone = $False
		)
		if ($ShouldBeStandAlone -eq $True) {
			Write-Host "You chose the Reportname $ReportName but the operating system is domain-joined. Be aware that a different report type could affect the result."
		} 
		else {
			Write-Host "You chose the Reportname $ReportName but the operating system is $OsName. Be aware that a different report type could affect the result."
		}
		Write-Host ""
		Write-Host "Choose one of the following options:"
		Write-Host "[1] Continue     [2] Exit Script" -ForegroundColor Yellow
		$in = Read-Host
		switch ($in) {
			1 { 
				Write-Host "You chose to continue" 
				return $ReportName
			}
			2 { 
				Write-Host "You chose to exit the script" 
				return "Exit"
			}
			default { 
				Write-Host "Your input was invalid, call Save-ATAPHtmlReport again with your desired report" 
				return "Exit"
			}
		}
	}
	function returnSuitingReportName {
		[CmdletBinding()]
		param (
			[Parameter()]
			[string]
			$ReportName,
			[Parameter()]
			[string]
			$OsName,
			[Parameter()]
			[string]
			$OsType,
			[Parameter()]
			[bool]
			$ShouldBeStandAlone = $False
		)

		###
		# similarity check
		function isOsNameSimilarToType {
			[CmdletBinding()]
			param (
				[Parameter()]
				[string]
				$OsName,
				[Parameter()]
				[string]
				$OsType
			)
			if ($OsName -match $OsType) {
				return $true
			}
			return $false
		}
		if (-not(isOsNameSimilarToType -OsName $osName -OsType $osType)) {
			return handleReportNameDiscrepancy -ReportName $ReportName -OsName $osName
		}

		###
		# get whether domaincontroller info for later use
		function IsDomainController {	
			$domainrole = Get-DomainRole
			if ($domainrole -eq "Backup Domain Controller" -or $domainrole -eq "Primary Domain Controller") {
				return $true
			}
			return $false
		}
		$isDomainController = IsDomainController
		# should be DC
		if ($ShouldBeDomainController -eq $True) {
			if (-not($isDomainController -eq $True)) {
				return handleReportNameDiscrepancy -ReportName $ReportName -OsName $osName -ShouldBeDomainController $True
			} 
			# should not be DC
		}
		else {
			if ($isDomainController -eq $True) {
				return handleReportNameDiscrepancy -ReportName $ReportName -OsName $osName -ShouldNotBeDomainController $True
			}
		}

		###
		# should be standalone
		if ($ShouldBeStandAlone -eq $True) {
			function IsDomainedJoined {		
				if ((Get-CimInstance win32_computersystem).partofdomain) {
					return $true
				} 
				return $false
			}
			$isDomainJoined = IsDomainedJoined
			if ($isDomainJoined -eq $True) {
				return handleReportNameDiscrepancy -ReportName $ReportName -OsName $osName -ShouldBeStandAlone $True
			}
		}
		return $ReportName
	}
	#helpers end

	$osName = (Get-ComputerInfo OsName).OsName
	function Get-OsType {		
		switch ($ReportName) {
			"Microsoft Windows Server 2022" { return "Microsoft Windows Server 2022" }
			"Microsoft Windows Server 2022 DC" { return "Microsoft Windows Server 2022" }
			"Microsoft Windows Server 2019" { return "Microsoft Windows Server 2019" }
			"Microsoft Windows Server 2019 DC" { return "Microsoft Windows Server 2019" }
			"Microsoft Windows Server 2016" { return "Microsoft Windows Server 2016" }
			"Microsoft Windows Server 2016 DC" { return "Microsoft Windows Server 2016" }
			"Microsoft Windows Server 2012" { return "Microsoft Windows Server 2012" }
			"Microsoft Windows 11" { return "Microsoft Windows 11" }
			"Microsoft Windows 11 Stand-alone" { return "Microsoft Windows 11" }
			"Microsoft Windows 10" { return "Microsoft Windows 10" }
			"Microsoft Windows 10 Stand-alone" { return "Microsoft Windows 10" }
			"Microsoft Windows 10 GDPR" { return "Microsoft Windows 10" }
			"Microsoft Windows 10 BSI" { return "Microsoft Windows 10" }
			"Microsoft Windows 7" { return "Microsoft Windows 7" }
		}
	}
	$osType = Get-OsType
	switch ($ReportName) {
		"Microsoft Windows Server 2022" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType
		}
		"Microsoft Windows Server 2022 DC" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType
		}
		"Microsoft Windows Server 2019" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows Server 2019 DC" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType
		}
		"Microsoft Windows Server 2016" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows Server 2016 DC" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType
		}
		"Microsoft Windows Server 2012" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows 11" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows 11 Stand-alone" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType -ShouldBeStandAlone $True
		}
		"Microsoft Windows 10" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows 10 Stand-alone" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType -ShouldBeStandAlone $True
		}
		"Microsoft Windows 10 GDPR" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows 10 BSI" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
		"Microsoft Windows 7" { 
			return returnSuitingReportName -ReportName $ReportName -OsName $osName -OsType $osType 
		}
	}
	return $ReportName
}

### begin Foundation functions ###
function Get-FoundationReport {
	[CmdletBinding()]
	[OutputType([FoundationReport])]
	
	$Sections = @(
		[ReportSection] @{
			Title       = "Security Base Data"
			SubSections = @(
				[ReportSection] @{
					Title      = 'Platform Security'
					AuditInfos = Test-AuditGroup "SBD - Platform Security"
				}
				[ReportSection] @{
					Title      = 'Windows Base Security'
					AuditInfos = Test-AuditGroup "SBD - Windows Base Security"
				}
				[ReportSection] @{
					Title      = 'PowerShell Security'
					AuditInfos = Test-AuditGroup "SBD - PowerShell Security"
				}
				[ReportSection] @{
					Title      = 'Connectivity Security'
					AuditInfos = Test-AuditGroup "SBD - Connectivity Security"
				}
				[ReportSection] @{
					Title      = 'Application Control'
					AuditInfos = Test-AuditGroup "SBD - Application Control"
				}
			)
		}
	)

	return ([FoundationReport]@{
			Sections = $Sections
		})
}


# region for RiskScore functions
# function that calls all RiskScore-Subfunctions and generates the RSFullReport
function Get-RSFullReport {
	[CmdletBinding()]
	[OutputType([RSFullReport])]
	
	$severity = Get-RSSeverityReport

	
	return ([RSFullReport]@{
			RSSeverityReport = $severity
		})
}
# function to generate RiskSeverityReport
function Get-RSSeverityReport {
	[CmdletBinding()]
	[OutputType([RSSeverityReport])]

	# Initialization
	[AuditInfo[]]$tests = Test-AuditGroup "RSSeverityTests"

	# gather results of tests and save it in resultTable
	$resultTable = [ResultTable]::new()
	foreach ($test in $tests) {
		if ($test.AuditInfoStatus -EQ "True") {
			$resultTable.Success += 1
		}
		if ($test.AuditInfostatus -ne "True") {
			$resultTable.Failed += 1
		}
	}

	return ([RSSeverityReport]@{
			AuditInfos  = $tests
			ResultTable = $resultTable
			Endresult   = Get-RSSeverityEndResult($resultTable)
		})
}

# helper for EndResult of RiskScoreSeverity
function Get-RSSeverityEndResult {
	[CmdletBinding()]
	[OutputType([RSEndResult])]

	param (
		[Parameter(Mandatory = $true)]
		[ResultTable[]]
		$resultTable
	)

	$result = "Unknown"

	$f = $resultTable.Failed
	if ($f -eq 0) {
		$result = "Low"
	}
	if ($f -ge 1) {
		$result = "Critical"
	}
	return $result
}

#endregion

<#
.SYNOPSIS
	Tests a single AuditGroup.
.DESCRIPTION
	This cmdlet tests a single AuditGroup from folder "AuditGroups". All tests are printed on the console. Can be combined to create own report.
.EXAMPLE
	PS C:\> Test-AuditGroup "Google Chrome-CIS-2.0.0#RegistrySettings"
	This runs tests defined in the AuditGroup file called 'Google Chrome-CIS-2.0.0#RegistrySettings'.
.PARAMETER GroupName
	The name of the AuditGroup.
#>
function Test-AuditGroup {
	[CmdletBinding()]
	[OutputType([AuditInfo[]])]
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$GroupName
	)

	#Windows OS
	if ([System.Environment]::OSVersion.Platform -ne 'Unix') {
		$tests = . "$RootPath\AuditGroups\$($GroupName).ps1"
	}
	#Linux OS
	else {
		$tests = . "$RootPath/AuditGroups/$($GroupName).ps1"
	}


	$i = 1
	foreach ($test in $tests) {
		[int]$p = $i++ / $tests.Count * 100
		Write-Progress -Activity "Testing Report for '$GroupName'" -Status "Progress:" -PercentComplete $p
		Write-Verbose "Testing $($test.Id)"
		$message = "Test not implemented yet."
		$status = [AuditInfoStatus]::None
		#if audit test contains datatype "Constraints", proceed
		if ($test.Constraints) {
			$DomainRoleConstraint = $test.Constraints | Where-Object Property -EQ "DomainRole"
			#get domain role of system
			$currentRole = Get-DomainRole
			#get domain roles, which are listed in AuditTest
			$domainRoles = $DomainRoleConstraint.Values
			if ($currentRole -notin $domainRoles) {
				$roleValue = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole
				switch ($roleValue) {
					0 {	
						$message = 'Not applicable. This audit does not apply to Standalone Workstation.'
						$status = [AuditInfoStatus]::None
					}
					1 {	
						$message = 'Not applicable. This audit does not apply to Member Workstation.'
						$status = [AuditInfoStatus]::None
					}
					2 {	
						$message = 'Not applicable. This audit does not apply to Standalone Server.'
						$status = [AuditInfoStatus]::None
					}
					3 {	
						$message = 'Not applicable. This audit does not apply to Member Server.'
						$status = [AuditInfoStatus]::None
					}
					4 {	
						$message = 'Not applicable. This audit does not apply to Backup Domain Controller.'
						$status = [AuditInfoStatus]::None
					}
					5 {	
						$message = 'Not applicable. This audit does not apply to Primary Domain Controller.'
						$status = [AuditInfoStatus]::None
					}
				}
				Write-Output ([AuditInfo]@{
						Id      = $test.Id
						Task    = $test.Task
						Message = $message
						Status  = $status
					})
				continue
			}
		}

		#Windows OS
		if ([System.Environment]::OSVersion.Platform -ne 'Unix') {
			$role = Get-Wmiobject -Class 'Win32_computersystem' -ComputerName $env:computername | Select-Object domainrole
			if ($test.Task -match "(DC only)") {
				if ($role.domainRole -ne 4 -and $role.domainRole -ne 5) {
					$message = 'Not applicable. This audit does not apply to Member Server systems.'
					$status = [AuditInfoStatus]::None
					Write-Output ([AuditInfo]@{
							Id      = $test.Id
							Task    = $test.Task
							Message = $message
							Status  = $status
						})
					continue
				}
			}
		}
		try {
			$innerResult = & $test.Test

			if ($null -ne $innerResult) {
				$message = $innerResult.Message
				$status = [AuditInfoStatus]$innerResult.Status
			}
		}
		catch {
			Write-Error $_
			$message = "An error occured!"
			$status = [AuditInfoStatus]::Error
		}

		Write-Output ([AuditInfo]@{
				Id      = $test.Id
				Task    = $test.Task
				Message = $message
				Status  = $status
			})
	}
}

<#
.SYNOPSIS
	Get an audit resource.
.DESCRIPTION
	A resource provides abstration over an existing system resource. It is used by AuditTests.
.PARAMETER Name
	The name of the resource.
.EXAMPLE
	PS C:\> Get-AuditResource -Name "WindowsSecurityPolicy"
	Gets the WindowsSecurityPolicy resource.
#>
function Get-AuditResource {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Name
	)
	#Windows OS
	if ([System.Environment]::OSVersion.Platform -ne 'Unix') {
		if ($null -eq $script:loadedResources) {
			return & "$RootPath\Resources\$($Name).ps1"
		}
		if (-not $script:loadedResources.ContainsKey($Name)) {
			$script:loadedResources[$Name] = (& "$RootPath\Resources\$($Name).ps1")
		}
	}
	#Linuxs OS
	else {
		if ($null -eq $script:loadedResources) {
			return & "$RootPath/Resources/$($Name).ps1"
		}
		if (-not $script:loadedResources.ContainsKey($Name)) {
			$script:loadedResources[$Name] = (& "$RootPath/Resources/$($Name).ps1")
		}
	}
	return $script:loadedResources[$Name]
}

<#
.SYNOPSIS
	Get all reports.
.DESCRIPTION
	Find the reports installed on the system.
.PARAMETER ReportName
	The name of the report.
.EXAMPLE
	PS C:\> Get-ATAPReport
	Gets all reports.
#>
function Get-ATAPReport {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$ReportName = "*"
	)
	#Windows OS
	if ([System.Environment]::OSVersion.Platform -ne 'Unix') {
		return Get-ChildItem "$RootPath\Reports\$ReportName.ps1" | Select-Object -Property BaseName
	}
	#Linux OS
	return Get-ChildItem "$RootPath/Reports/$ReportName.ps1" | Select-Object -Property BaseName
}

<#
.SYNOPSIS
	Invokes an ATAPReport
.DESCRIPTION
	Long description
.EXAMPLE
	PS C:\> ATAPReport -ReportName "Google Chrome"
	This runs the report and outputs the logical report data.
.PARAMETER ReportName
	The name of the report.
.OUTPUTS
	Logical report data.
#>
function Invoke-ATAPReport {
	[CmdletBinding()]
	param (
		[Alias('RN')]
		[Parameter(Mandatory = $true)]
		[string]
		$ReportName
	)

	$script:loadedResources = @{}
	# Load the module manifest

	#Windows OS
	try {
		if ([System.Environment]::OSVersion.Platform -ne 'Unix') {
			$moduleInfo = Import-PowerShellDataFile -Path "$RootPath\ATAPAuditor.psd1"
			[string]$ReportName = checkReportNameWithOSSystem -ReportName $ReportName
			try {
				if ($ReportName -eq "Exit") {
					throw
				}
			}
			catch {
				Write-Host "Script halted: Exiting..."
				break
			}
			[Report]$report = (& "$RootPath\Reports\$ReportName.ps1")
			$report.RSReport = Get-RSFullReport
			$report.FoundationReport = Get-FoundationReport
		}
		#Linux OS
		else {
			$moduleInfo = Import-PowerShellDataFile -Path "$RootPath/ATAPAuditor.psd1"
			[Report]$report = (& "$RootPath/Reports/$ReportName.ps1")
		}
	}
 	catch [System.Management.Automation.CommandNotFoundException] {
		Write-Host "Either your input for -Reportname is faulty or the report does not resolve due to a bug. Please report this bug with the following errormessage: 
		1. ErrorException: $_
		2. PositionMessage: $($_.InvocationInfo.PositionMessage)
		3. ReportName: $ReportName"
		break
	}
	$report.AuditorVersion = $moduleInfo.ModuleVersion
	return $report
}

<#
.SYNOPSIS
	The Audit Test Automation Package creates transparents reports about hardening compliance status
.DESCRIPTION
	The Audit Test Automation Package gives you the ability to get an overview about the compliance status of several systems. 
	You can easily create HTML-reports and have a transparent overview over compliance and non-compliance of explicit setttings 
	and configurations in comparison to industry standards and hardening guides. 
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Microsoft Windows 10 Complete" -RiskScore -Path C:\Temp\report.html
	This runs the 'Microsoft Windows 10 Complete' report, adding RiskScore to it and stores the resulting html file under C:\Temp using the file name report.html
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Microsoft Windows 10 BSI" -RiskScore -Path C:\Temp
	This runs the 'Microsoft Windows 10 BSI' report, adding RiskScore to it and stores the resulting html file under C:\Temp using the standard naming convention for file names <ReportName_Date_Time>.html
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Microsoft Windows Server 2022" -Path C:\Temp
	This runs the 'Microsoft Windows Server 2022' report, without adding RiskScore to it and stores the resulting html file under C:\Temp using the standard naming convention for file names <ReportName_Date_Time>.html
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Google Chrome"
	This runs the 'Google Chrome' report and stores the resulting html file (by default) under ~\Documents\ATAPReports
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Ubuntu 20.04"
	This runs the 'Ubuntu 20.04' report and stores the resulting html file (by default) under ~\Documents\ATAPReports
.PARAMETER ReportName
	Determine, which OS shall be tested.
.PARAMETER Path
	The path where the result html document should be stored.
.PARAMETER RiskScore
	Add a RiskScore-Matrix to report (works only on Windows OS)
.PARAMETER MITRE
	Add a MITRE ATT&CK headmap to report (works only on Windows OS)
.PARAMETER Force
	If the parent directory doesn't exist it will be created.
.OUTPUTS
	None.
#>
function Save-ATAPHtmlReport {
	[CmdletBinding()]
	param(
		[Alias('RN')]
		[Parameter(Mandatory = $true)]
		[string]
		$ReportName,

		[Parameter(Mandatory = $false)]
		[string]
		$Path = ($script:atapReportsPath | Join-Path -ChildPath "$($ReportName)_$(Get-Date -UFormat %Y%m%d_%H%M%S).html"),

		[Parameter(Mandatory = $false)]
		[switch]
		$RiskScore,

		[Parameter(Mandatory = $false)]
		[switch]
		$SkipLicenseCheck,
		# [Parameter(Mandatory = $false)]
		# [switch]
		# $MITRE,

		[Parameter()]
		[switch]
		$Force
	)

	if ([Environment]::Is64BitProcess -eq $false) {
		Write-Host "Please use 64-bit version of PowerShell in order to use AuditTAP. Closing..." -ForegroundColor red
		return;
	}

	if (($languagemode = IsIn-FullLanguageMode) -ne $true) {
		if ($languagemode -eq $false) {
			Write-Host "The current language mode could not be determined. Ensure that AuditTAP is run in `"FullLanguage`" mode. For further information, contact your administrator. Closing..." -ForegroundColor red
		} else {
			Write-Host "The current language mode is `"$languagemode`". Ensure that AuditTAP is run in `"FullLanguage`" mode. For further information, contact your administrator. Closing..." -ForegroundColor red
		}
		return
	}

	$parent = $path
	if ($Path -match ".html") {
		$parent = Split-Path -Path $Path
	}

	#if input path is not default one
	if ($parent -ne $script:atapReportsPath) {
		$pathCheck = Test-Path -Path $parent -PathType Container
		#if path doesn't exist
		if ($pathCheck -eq $False) {
			if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path $parent)) {
				New-Item -ItemType Directory -Path $parent -Force | Out-Null
				Write-Warning "Could not find Path. Path will be created: $parent"
			}
			else {
				Write-Warning "Could not find Path. Report will be created inside default path: $($script:atapReportsPath)"
				$Path = $($script:atapReportsPath)
			}
		}
	}
	Write-Verbose "OS-Check"
	$isUnix = [System.Environment]::OSVersion.Platform -eq 'Unix'
	if ($isUnix) {
		[SystemInformation] $SystemInformation = (& "$PSScriptRoot\Helpers\ReportUnixOS.ps1")
	}
	else {
		[SystemInformation] $SystemInformation = (& "$PSScriptRoot\Helpers\ReportWindowsOS.ps1")
		Start-ModuleTest
		Write-Verbose "PS-Check"
		$psVersion = $PSVersionTable.PSVersion
		#PowerShell Major version not 5.*
		if (($psVersion.Major -ne 5)) {
			Write-Warning "ATAPAuditor is only compatible with PowerShell Version 5.1. Your version is $psVersion. Do you want to open a Powershell 5? Y/N"
			$in = Read-Host
			switch ($in) {
				Y { Start Powershell; return }
				N { Write-Warning "Stopping Script..."; return }
				default { Write-Warning "You did not choose Y nor N. Stopping Script..."; return }
			}
		}
		#PowerShell version not 5.1
		if (($psVersion.Major -eq 5) -and ($psVersion.Minor -eq 0)) {
			Write-Warning "ATAPAuditor is only compatible with PowerShell Version 5.1. Your version is $psVersion. You need to upgrade to a higher Windows version!"
			return;
		}
	}
	$report = Invoke-ATAPReport -ReportName $ReportName 
	#hashes for each recommendation
	if (!$isUnix) {
		$SystemInformation.SoftwareInformation.LicenseStatus = GetLicenseStatus $SkipLicenseCheck
	}
	$hashtable_sha256 = GenerateHashTable $report
	
	$report | Get-ATAPHtmlReport -Path $Path -RiskScore:$RiskScore -MITRE:$MITRE -hashtable_sha256:$hashtable_sha256 -LicenseStatus:$LicenseStatus -SystemInformation:$SystemInformation
}

New-Alias -Name 'shr' -Value Save-ATAPHtmlReport

$completer = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

	Get-ChildItem "$RootPath\Reports\*.ps1" `
	| Select-Object -ExpandProperty BaseName `
	| ForEach-Object { "`"$_`"" } `
	| Where-Object { $_ -like "*$wordToComplete*" }
}.GetNewClosure()

Register-ArgumentCompleter -CommandName Save-ATAPHtmlReport -ParameterName ReportName -ScriptBlock $completer
Register-ArgumentCompleter -CommandName shr -ParameterName ReportName -ScriptBlock $completer
