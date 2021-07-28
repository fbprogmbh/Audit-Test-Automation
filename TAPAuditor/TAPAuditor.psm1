using namespace Microsoft.PowerShell.Commands

#region Initialization

$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent

$script:TAPReportsPath = $env:TAPReportPath
if (-not $script:TAPReportsPath) {
	$script:TAPReportsPath = [Environment]::GetFolderPath('MyDocuments') | Join-Path -ChildPath 'TAPReports'
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
}
#endregion

#region helpers
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

	for ($i = 0; $i -lt $Array1.Count; $i++) {
		if ($Array1[$i] -ne $Array2[$i]) {
			return $false
		}
	}
	return $true
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

#endregion

<#
.SYNOPSIS
	Runs the tests of an AuditGroup.
.DESCRIPTION
	Runs the tests of an AuditGroup file.
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

	$tests = . "$RootPath\AuditGroups\$($GroupName).ps1"

	$i = 1
	foreach ($test in $tests) {
		[int]$p = $i++ / $tests.Count * 100
		Write-Progress -Activity "Testing Report for '$GroupName'" -Status "Progress:" -PercentComplete $p
		Write-Verbose "Testing $($test.Id)"
		$message = "Test not implemented yet."
		$status = [AuditInfoStatus]::None
		if ($test.Constraints) {
			$DomainRoleConstraint = $test.Constraints | Where-Object Property -EQ "DomainRole"
			$currentRole = Get-DomainRole
			$domainRoles = $DomainRoleConstraint.Values
			if ($currentRole -notin $domainRoles) {
				Write-Output ([AuditInfo]@{
					Id = $test.Id
					Task = $test.Task
					Message = 'Not applicable. This audit applies only to {0}.' -f ($DomainRoleConstraint.Values -join ' and ')
					Status = [AuditInfoStatus]::None
				})
				continue
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
			Id = $test.Id
			Task = $test.Task
			Message = $message
			Status = $status
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

	if ($null -eq $script:loadedResources) {
		return & "$RootPath\Resources\$($Name).ps1"
	}
	if (-not $script:loadedResources.ContainsKey($Name)) {
		$script:loadedResources[$Name] = (& "$RootPath\Resources\$($Name).ps1")
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
	PS C:\> Get-TAPReport
	Gets all reports.
#>
function Get-TAPReport {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$ReportName = "*"
	)

	return Get-ChildItem "$RootPath\Reports\$ReportName.ps1" | Select-Object -Property BaseName
}

<#
.SYNOPSIS
	Invokes an TAPReport
.DESCRIPTION
	Long description
.EXAMPLE
	PS C:\> TAPReport -ReportName "Google Chrome"
	This runs the report and outputs the logical report data.
.PARAMETER ReportName
	The name of the report.
.OUTPUTS
	Logical report data.
#>
function Invoke-TAPReport {
	[CmdletBinding()]
	param (
		[Alias('RN')]
		[Parameter(Mandatory = $true)]
		[string]
		$ReportName
	)

	$script:loadedResources = @{}
	# Load the module manifest
	$moduleInfo = Import-PowerShellDataFile -Path "$RootPath\TAPAuditor.psd1"

	[Report]$report = (& "$RootPath\Reports\$ReportName.ps1")
	$report.AuditorVersion = $moduleInfo.ModuleVersion
	return $report
}

<#
.SYNOPSIS
	Saves an TAPHtmlReport
.DESCRIPTION
	Runs the specified TAPReport and creates a report.
.EXAMPLE
	PS C:\> Save-TAPHtmlReport -ReportName "Google Chrome"
	This runs the 'Google Chrome' report and stores the resulting html file (by default) under ~\Documents\TAPReports
.PARAMETER ReportName
	The name of the report.
.PARAMETER Path
	The path where the result html document should be stored.
.PARAMETER DarkMode
	By default the report is displayed in light mode. If specified the report will be displayed in dark mode.
.PARAMETER Force
	If the parent directory doesn't exist it will be created.
.OUTPUTS
	None.
#>
function Save-TAPHtmlReport {
	[CmdletBinding()]
	param(
		[Alias('RN')]
		[Parameter(Mandatory = $true)]
		[string]
		$ReportName,

		[Parameter(Mandatory = $false)]
		[string]
		$Path = ($script:TAPReportsPath | Join-Path -ChildPath "$($ReportName)_$(Get-Date -UFormat %Y%m%d_%H%M).html"),

		[switch]
		$DarkMode,

		[Parameter()]
		[switch]
		$Force
	)

	$parent = Split-Path $Path
	if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path $parent)) {
		if ($Force) {
			New-Item -ItemType Directory -Path $parent -Force | Out-Null
		}
		else {
			Write-Error "Cannot save the report at $parent because the path does not exist."
			return
		}
	}
	Invoke-TAPReport -ReportName $ReportName | Get-TAPHtmlReport -Path $Path -DarkMode:$DarkMode
}

New-Alias -Name 'shr' -Value Save-TAPHtmlReport

$completer = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

	Get-ChildItem "$RootPath\Reports\*.ps1" `
		| Select-Object -ExpandProperty BaseName `
		| ForEach-Object { "`"$_`"" } `
		| Where-Object { $_ -like "*$wordToComplete*" }
}.GetNewClosure()

Register-ArgumentCompleter -CommandName Save-TAPHtmlReport -ParameterName ReportName -ScriptBlock $completer
Register-ArgumentCompleter -CommandName shr -ParameterName ReportName -ScriptBlock $completer
