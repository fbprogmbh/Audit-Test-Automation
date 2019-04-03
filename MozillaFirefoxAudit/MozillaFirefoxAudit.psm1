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

# Import setting from file
$Settings = Import-LocalizedData -FileName "Settings.psd1"

#region Import tests configuration settings
$CisBenchmarks    = Import-LocalizedData -FileName "Mozilla_Firefox_38_ESR_Benchmark_v1.0.0.psd1"
$DisaRequirements = Import-LocalizedData -FileName "Mozilla_FireFox_DISA_STIG_V4R24.psd1"
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

#region helper classes
class LockPrefSetting {
	[string] $Name
	$Value
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

function PreprocessLockPrefSetting {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[hashtable] $InputObject,

		[LockPrefSetting[]] $CurrentLockPrefs = (Get-FirefoxLockPrefs)
	)

	process {
		$InputObject.CurrentLockPrefs = $CurrentLockPrefs
		return $InputObject
	}
}

function Get-FirefoxInstallDirectory {
	$firefoxPath = "HKLM:\SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox\"
	if (-not (Test-Path $firefoxPath)) {
		$firefoxPath = "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\"
	}
	$currentFirefox = Get-ChildItem -Path $firefoxPath | Select-Object -Last 1
	$installDir = $currentFirefox | Get-ChildItem | Where-Object PSChildName -EQ "Main"
	return $installDir | Get-ItemProperty | Select-Object -ExpandProperty "Install Directory"
}

function Get-FirefoxLocalSettingsFile {
	return "{0}\defaults\pref\local-settings.js" -f (Get-FirefoxInstallDirectory)
}

function Get-FirefoxMozillaCfgFileName {
	$localSettingsFilePath = Get-FirefoxLocalSettingsFile
	$content = if (Test-Path $localSettingsFilePath) { Get-Content $localSettingsFilePath } else { $null }
	$filename = $content | ForEach-Object {
		if ($_ -match "^pref\(`"general\.config\.filename`",\s?`"([\w\-. ]+\.cfg)`"\);") {
			return $Matches[1]
		}
		return $null
	} | Where-Object { $null -ne $_ } | Select-Object -Last 1

	if ($null -eq $filename) {
		return "mozilla.cfg"
	}

	return $filename
}

function Get-FirefoxMozillaCfgFile {
	return "{0}\{1}" -f (Get-FirefoxInstallDirectory), (Get-FirefoxMozillaCfgFileName)
}

function Get-FirefoxLockPrefs {
	if (-not (Test-Path (Get-FirefoxMozillaCfgFile))) {
		return $null
	}

	$regex = "^lockPref\s*\(\s*`"([\w.-]+)`"\s*,\s*({0}|{1}|{2})\s*\);" -f @(
		"(?<bool>true|false)"
		"(?<number>\d+)"
		"`"(?<string>(\\.|[^`"\\])*)`""
	)

	$currentLockPrefs = Get-Content (Get-FirefoxMozillaCfgFile) | ForEach-Object {
		if ($_ -match $regex) {
			$value = $null
			if ($Matches.Keys -contains "bool") {
				$value = [bool]::Parse($Matches["bool"])
			}
			elseif ($Matches.Keys -contains "number") {
				$value = [int]::Parse($Matches["number"])
			}
			elseif ($Matches.Keys -contains "string") {
				$value = $Matches["string"]
			}

			[LockPrefSetting]@{ Name = $Matches[1]; Value = $value }
		}
	} | Where-Object { $null -ne $_ }

	return $currentLockPrefs
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

function Get-FirefoxLocalSettingsFileAudit {
	$Id = "1.1"
	$Task = "Create local-settings.js file"

	if (-not (Test-Path (Get-FirefoxLocalSettingsFile))){
		return [AuditInfo]@{
			Id      = $Id
			Task    = $Task
			Message = "local-settings.js file does not exist."
			Audit   = [AuditStatus]::False
		}
	}

	$generalConfigFilename = Get-Content (Get-FirefoxLocalSettingsFile) | Where-Object {
		$_ -match "^pref\s*\(\s*`"general\.config\.filename`"\s*,\s*`"([\w\-. ]+\.cfg)`"\s*\);"
	}
	
	if ($generalConfigFilename.Count -eq 0) {
		return [AuditInfo]@{
			Id      = $Id
			Task    = $Task
			Message = "File does not set 'general.config.filename'"
			Audit   = [AuditStatus]::False
		}
	}

	$generalConfigObscure = Get-Content (Get-FirefoxLocalSettingsFile) | Where-Object {
		$_ -match "^pref\s*\(\s*`"general\.config\.obscure_value`"\s*,\s*0\s*\);"
	}
	
	if ($generalConfigObscure.Count -eq 0) {
		return [AuditInfo]@{
			Id      = $Id
			Task    = $Task
			Message = "File does not set 'general.config.obscure' = 0"
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

function Get-FirefoxMozillaCfgFileAudit {
	$name = Get-FirefoxMozillaCfgFileName

	$Id = "1.3"
	$Task = "Create $name file"

	if (-not (Test-Path (Get-FirefoxMozillaCfgFile))){
		return [AuditInfo]@{
			Id      = $Id
			Task    = $Task
			Message = "$name file does not exist."
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

function Get-FileAudit {
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
		[scriptblock] $Predicate
	)

	process {
		if (-not (Test-Path $Path)) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "File does not exist."
				Audit = [AuditStatus]::False
			}
		}

		if (-not (&$Predicate (Get-Content $Path))) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "File does not match predicate."
				Audit = [AuditStatus]::False
			}
		}
		
		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant."
			Audit = [AuditStatus]::True
		}
	}
}

function Get-LockPrefSettingAudit {
	[CmdletBinding()]
	[OutputType([AuditInfo])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,
	
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,
	
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[LockPrefSetting[]] $LockPrefs,

		[LockPrefSetting[]] $CurrentLockPrefs = (Get-FirefoxLockPrefs)
	)
	
	process {
		if ($null -eq $CurrentLockPrefs) {
			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "general config does not exist."
				Audit = [AuditStatus]::None
			}
		}

		$missingLockPrefs = $LockPrefs | Where-Object {
			$LockPref = $_
			# LockPref not in currentLockPrefs
			($currentLockPrefs | Where-Object {
				($_.Name -eq $LockPref.Name) -and ($_.Value -is $LockPref.Value.GetType()) -and ($_.Value -eq $LockPref.Value)
			}).Count -eq 0
		}

		if ($missingLockPrefs.Count -gt 0) {
			$msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "

			return [AuditInfo]@{
				Id = $Id
				Task = $Task
				Message = "Missing lockprefs: $msg."
				Audit = [AuditStatus]::False
			}
		}
		
		return [AuditInfo]@{
			Id = $Id
			Task = $Task
			Message = "Compliant."
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

function Get-CisAudit {
[CmdletBinding()]
	Param(
		[switch] $FileConfig,
		[switch] $FirefoxLockPrefSettings
	)
	# cis FirefoxLockPrefSettings
	if ($FileConfig) {
		Get-FirefoxLocalSettingsFileAudit
		# missing 1.2
		Get-FirefoxMozillaCfgFileAudit
		# missing 1.4
		# missing 1.5
	}
	# cis FirefoxLockPrefSettings
	if ($FirefoxLockPrefSettings) {
		$currentLockPrefs = (Get-FirefoxLockPrefs)
		$pipline = New-AuditPipeline ${Function:Get-LockPrefSettingAudit}
		$CisBenchmarks.FirefoxLockPrefSettings | PreprocessLockPrefSetting -CurrentLockPrefs $currentLockPrefs | &$pipline -Verbose:$VerbosePreference
	}
}

function Get-DisaAudit {
	[CmdletBinding()]
	Param(
		[switch] $FirefoxLockPrefSettings
	)
	# disa FirefoxLockPrefSettings
	if ($FirefoxLockPrefSettings) {
		$currentLockPrefs = (Get-FirefoxLockPrefs)
		$pipline = New-AuditPipeline ${Function:Get-LockPrefSettingAudit}
		$DisaRequirements.FirefoxLockPrefSettings | PreprocessLockPrefSetting -CurrentLockPrefs $currentLockPrefs | &$pipline -Verbose:$VerbosePreference
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
	The `Get-MozillaFirefoxHtmlReport` cmdlet tests your current the preferences of Firefox installation and stores an html report at the path you specify.
.Parameter Path
	Specifies the relative path to the file where the report will be stored.
.Parameter DarkMode
	The report will use a darker color scheme with light text on a dark background.
.Example
	C:\PS> Get-MozillaFirefoxHtmlReport -Path "reports/report1.html"
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
				Title = "CIS Benchmarks"
				Description = "This section contains all CIS benchmarks"
				SubSections = @(
					@{
						Title = "Configure Locked Preferences"
						AuditInfos = Get-CisAudit -FileConfig | Sort-Object -Property Id
					}
					@{
						Title = "Preference Settings"
						AuditInfos = Get-CisAudit -FirefoxLockPrefSettings | Sort-Object -Property Id
					}
				)
			}
			
			@{
				Title = "DISA Recommendations"
				Description = "This section contains all DISA recommendations"
				SubSections = @(
					@{
						Title = "Preference Settings"
						AuditInfos = Get-DisaAudit -FirefoxLockPrefSettings | Sort-Object -Property Id
					}
				)
			}
		)

		Get-ATAPHtmlReport `
			-Path $Path `
			-Title "Mozilla Firefox Audit Report" `
			-ModuleName "MozillaFirefoxAudit" `
			-BasedOn @(
				"CIS Mozilla Firefox 38 ESR Benchmark v1.0.0 - 2015-12-31"
				"DISA Mozilla FireFox Security Technical Implementation Guide V4R24 2019-01-25"
			) `
			-Sections $sections `
			-DarkMode:$DarkMode
	}
	else {
		Write-Error "The path doesn't not exist!"
	}
}

Set-Alias -Name Get-MozillaFirefoxHtmlReport -Value Get-HtmlReport
#endregion