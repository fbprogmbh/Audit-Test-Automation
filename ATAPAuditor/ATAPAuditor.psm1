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
	$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole
	switch ($domainRole) {
		0 { $result = "Standalone Workstation" }
		1 { $result = "Member Workstation"}
		2 { $result = "Standalone Server" }
		3 { $result = "Member Server"}
		4 { $result = "Backup Domain Controller" }
		5 { $result = "Primary Domain Controller"}
	}
	return $result
}

### begin Foundation functions ###
function Get-FoundationReport {
	[CmdletBinding()]
	[OutputType([FoundationReport])]
	
	$Sections = @(
		[ReportSection] @{
			Title = "Security Base Data"
			SubSections = @(
				[ReportSection] @{
					Title = 'Platform Security'
					AuditInfos = Test-AuditGroup "Platform Security"
				}
				[ReportSection] @{
					Title = 'Windows Base Security'
					AuditInfos = Test-AuditGroup "Windows Base Security"
				}
				[ReportSection] @{
					Title = 'PowerShell Security'
					AuditInfos = Test-AuditGroup "PowerShell Security"
				}
				[ReportSection] @{
					Title = 'Connectivity Security'
					AuditInfos = Test-AuditGroup "Connectivity Security"
				}
				[ReportSection] @{
					Title = 'Application Control'
					AuditInfos = Test-AuditGroup "Application Control"
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
	if([System.Environment]::OSVersion.Platform -ne 'Unix'){
		$tests = . "$RootPath\AuditGroups\$($GroupName).ps1"
	}
	#Linux OS
	else{
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
					if($roleValue -eq 4 -or $roleValue -eq 5){
						$message = 'Not applicable. This audit only applies to Domain controllers.'
						$status = [AuditInfoStatus]::None
					}
					if($roleValue -ne 4 -or $roleValue -ne 5){
						$message = 'Not applicable. This audit does not apply to Domain controllers.'
						$status = [AuditInfoStatus]::None
					}
					if($roleValue -eq 0 -or $roleValue -eq 2){
						$message = 'Not applicable. This audit does not apply to Standalone systems.'
						$status = [AuditInfoStatus]::None
					}
					Write-Output ([AuditInfo]@{
						Id = $test.Id
						Task = $test.Task
						Message = $message
						Status = $status
					})
					continue
				}
			}

			#Windows OS
			if([System.Environment]::OSVersion.Platform -ne 'Unix'){
				$role = Get-Wmiobject -Class 'Win32_computersystem' -ComputerName $env:computername | Select-Object domainrole
				if($test.Task -match "(DC only)"){
					if($role.domainRole -ne 4 -and $role.domainRole -ne 5){
						$message = 'Not applicable. This audit does not apply to Member Server systems.'
						$status = [AuditInfoStatus]::None
						Write-Output ([AuditInfo]@{
							Id = $test.Id
							Task = $test.Task
							Message = $message
							Status = $status
						})
						continue
					}
				}
			}
			if($test.Task -match "(MS only)"){
				if($role.domainRole -ne 2 -and $role.domainRole -ne 3){
					$message = 'Not applicable. This audit does not apply to Domain Controller systems.'
					$status = [AuditInfoStatus]::None
					Write-Output ([AuditInfo]@{
						Id = $test.Id
						Task = $test.Task
						Message = $message
						Status = $status
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
	#Windows OS
	if([System.Environment]::OSVersion.Platform -ne 'Unix'){
		if ($null -eq $script:loadedResources) {
			return & "$RootPath\Resources\$($Name).ps1"
		}
		if (-not $script:loadedResources.ContainsKey($Name)) {
			$script:loadedResources[$Name] = (& "$RootPath\Resources\$($Name).ps1")
		}
	}
	#Linuxs OS
	else{
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
	if([System.Environment]::OSVersion.Platform -ne 'Unix'){
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

	try {
		#Windows OS
		if([System.Environment]::OSVersion.Platform -ne 'Unix'){
			$moduleInfo = Import-PowerShellDataFile -Path "$RootPath\ATAPAuditor.psd1"
			[Report]$report = (& "$RootPath\Reports\$ReportName.ps1")
			$report.RSReport = Get-RSFullReport
			$report.FoundationReport = Get-FoundationReport
		}
		#Linux OS
		else{
			$moduleInfo = Import-PowerShellDataFile -Path "$RootPath/ATAPAuditor.psd1"
			[Report]$report = (& "$RootPath/Reports/$ReportName.ps1")
		}
	} catch [System.Management.Automation.CommandNotFoundException] {
		Write-Host "Input for -Reportname is faulty, please make sure to put the correct input. Stopping script."
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
	PS C:\> Save-ATAPHtmlReport -ReportName "Microsoft Windows 10 Complete" -RiskScore -Path C:\Temp\report.html -DarkMode
	This runs the 'Microsoft Windows 10 Complete' report, adding RiskScore to it, turns it into dark mode and stores the resulting html file under C:\Temp using the file name report.html
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Microsoft Windows 10 BSI" -RiskScore -Path C:\Temp -DarkMode 
	This runs the 'Microsoft Windows 10 BSI' report, adding RiskScore to it, turns it into dark mode and stores the resulting html file under C:\Temp using the standard naming convention for file names <ReportName_Date_Time>.html
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Microsoft Windows Server 2022" -Path C:\Temp -DarkMode 
	This runs the 'Microsoft Windows Server 2022' report, without adding RiskScore to it, turns it into dark mode and stores the resulting html file under C:\Temp using the standard naming convention for file names <ReportName_Date_Time>.html
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Google Chrome"
	This runs the 'Google Chrome' report and stores the resulting html file (by default) under ~\Documents\ATAPReports
.EXAMPLE
	PS C:\> Save-ATAPHtmlReport -ReportName "Ubuntu 20.04" -DarkMode
	This runs the 'Ubuntu 20.04' report, turns it into dark mode and stores the resulting html file (by default) under ~\Documents\ATAPReports
.PARAMETER ReportName
	Determine, which OS shall be tested.
.PARAMETER Path
	The path where the result html document should be stored.
.PARAMETER RiskScore
	Add a RiskScore-Matrix to report (works only on Windows OS)
.PARAMETER DarkMode
	By default the report is displayed in light mode. If specified the report will be displayed in dark mode.
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

		# [switch]
		# $DarkMode,

		[Parameter()]
		[switch]
		$Force
	)

	$parent = $path
	if ($Path -match ".html") {
		$parent = Split-Path -Path $Path
	}

	#if input path is not default one
	if($parent -ne $script:atapReportsPath){
		$pathCheck = Test-Path -Path $parent -PathType Container
		#if path doesn't exist
		if($pathCheck -eq $False){
			if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path $parent)) {
				New-Item -ItemType Directory -Path $parent -Force | Out-Null
				Write-Warning "Could not find Path. Path will be created: $parent"
			} else {
				Write-Warning "Could not find Path. Report will be created inside default path: $($script:atapReportsPath)"
				$Path = $($script:atapReportsPath)
			}
		}
	}

	$report = Invoke-ATAPReport -ReportName $ReportName 

	#hashes for each recommendation
	$hashList_sha256 = @()
	$hashList_sha512 = @()
	foreach($recommendation in $report.Sections){
		foreach($section in $recommendation.SubSections){
			$hash_sha256 = ""
			$hash_sha512 = ""
			foreach($test in $section.AuditInfos){
				$statusHash_sha256 = (Get-SHA256Hash $test.Status)
				$hash_sha256 += $statusHash_sha256
				$hash_sha256 = (Get-SHA256Hash $hash_sha256)
				
				$statusHash_sha512 = (Get-SHA512Hash $test.Status)
				$hash_sha512 += $statusHash_sha512
				$hash_sha512 = (Get-SHA512Hash $hash_sha512)
				#hash 512 to 256 due to it's length
				$hash_sha512 = (Get-SHA256Hash $hash_sha512)
			}
			$hashList_sha256 += $hash_sha256
			$hashList_sha512 += $hash_sha512
		}
	}

	#checksum hash for overal check
	$overallHash_sha256 = ""
	foreach($hash in $hashList_sha256){
		$curretHash_sha256 = (Get-SHA256Hash $hash)
		$overallHash_sha256 += $curretHash_sha256
		$overallHash_sha256 = (Get-SHA256Hash $overallHash_sha256)
	}
	$overallHash_sha512 = ""
	foreach($hash in $hashList_sha512){
		$curretHash_sha512 = (Get-SHA512Hash $hash)
		$overallHash_sha512 += $curretHash_sha512
		$overallHash_sha512 = (Get-SHA512Hash $overallHash_sha512)
	}
	#hash 512 to 256 due to it's length
	$overallHash_sha512 = (Get-SHA256Hash $overallHash_sha512)
	
	$hashList_sha256 += $overallHash_sha256
	$hashList_sha512 += $overallHash_sha512

	$report | Get-ATAPHtmlReport -Path $Path -RiskScore:$RiskScore -hashList_sha256:$hashList_sha256 -hashList_sha512:$hashList_sha512 #-DarkMode:$DarkMode 
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