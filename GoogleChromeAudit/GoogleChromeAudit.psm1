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

#region Import tests configuration settings
$DisaRequirements = Import-LocalizedData -FileName "Google_Chrome_DISA_STIG_V1R15.psd1"
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
[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
	[hashtable] $InputObject
)

	Process {
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

		if ($value.Count -gt 1) {
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

		$InputObject.ExpectedValue = $value
		$InputObject.Predicate     = { param([string] $x) $value -eq $x }.GetNewClosure()
		return $InputObject
	}
}
#endregion

#region Audit functions
function Get-RegistryAudit {
[CmdletBinding()]
[OutputType([AuditInfo])]
Param(
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
	[object[]] $Value,

	[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
	[ScriptBlock] $Predicate,

	[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
	[String] $ExpectedValue,

	[Parameter(ValueFromPipelineByPropertyName = $true)]
	[bool] $DoesNotExist = $false
)

	process {
		try {
			$regValues = Get-ItemProperty -ErrorAction Stop -Path $Path -Name $Name `
				| Select-Object -ExpandProperty $Name

			if (-not (& $Predicate $regValues)) {
				Write-LogFile -Path $Settings.LogFilePath -Name $Settings.LogFileName -Level Error `
					-Message "$($Id): Registry value $Name in registry key $Path is not correct."

					$regValue = $regValues -join ", "

				return [AuditInfo]@{
					Id = $Id
					Task = $Task
					Message = "Registry value: $regValue. Differs from allowed value: $ExpectedValue."
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
					Message = "Compliant. Registry value not set."
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

            if ($DoesNotExist) {
				return [AuditInfo]@{
					Id = $Id
					Task = $Task
					Message = "Compliant. Registry value not set."
					Audit = [AuditStatus]::True
				}
			}

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
	[switch] $RegistrySettings
)
	# disa registry settings
	if ($RegistrySettings) {
		$pipline = New-AuditPipeline ${Function:Get-RegistryAudit}
		$DisaRequirements.RegistrySettings | PreprocessSpecialValueSetting |  &$pipline -Verbose:$VerbosePreference
	}
}

function Get-CisAudit {
[CmdletBinding()]
Param(
	[switch] $RegistrySettings
)
	# cis registry settings
	if ($RegistrySettings) {
		$pipline = New-AuditPipeline ${Function:Get-RegistryAudit}
		$CisBenchmarks.RegistrySettings | PreprocessSpecialValueSetting | &$pipline -Verbose:$VerbosePreference
	}
}

#region Report-Generation
<#
	In this section the HTML report gets build and saved to the desired destination set by parameter saveTo
#>

<#
.Synopsis
	Generates an audit report in an html file.
.Description
	The `Get-GoogleChromeHtmlReport` cmdlet tests Google Chrome settings and stores an html report at the path you specify.
.Parameter Path
	Specifies the relative path to the file where the report will be stored.
.Parameter DarkMode
	The report will use a darker color scheme with light text on a dark background.
.Example
	C:\PS> Get-GoogleChromeHtmlReport -Path "reports/report1.html"
#>
function Get-HtmlReport {
	param (
		[string] $Path = [Environment]::GetFolderPath("MyDocuments")+"\"+"$(Get-Date -UFormat %Y%m%d_%H%M)_auditreport.html",

		[switch] $DarkMode
	)

	$parent = Split-Path $Path
	if (Test-Path $parent) {
		[hashtable[]]$sections = @(
			@{
				Title = "DISA Recommendations"
				Description = "This section contains all DISA recommendations"
				SubSections = @(
					@{
						Title = "Registry Settings/Group Policies"
						AuditInfos = Get-DisaAudit -RegistrySettings | Sort-Object -Property Id
					}
				)
			}
		)

		Get-ATAPHtmlReport `
			-Path $Path `
			-Title "Google Chrome Audit Report" `
			-ModuleName "GoogleChromeAudit" `
			-BasedOn "DISA Google Chrome Security Technical Implementation Guide V1R15 2019-01-25" `
			-Sections $sections `
			-DarkMode:$DarkMode
	}
	else {
		Write-Error "The path doesn't not exist!"
	}
}

Set-Alias -Name Get-GoogleChromeHtmlReport -Value Get-HtmlReport
#endregion