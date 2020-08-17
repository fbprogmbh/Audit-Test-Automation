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

#region Import tests configuration settings
$CisBenchmarks = @{
	FirefoxLockPrefSettings = @(
		@{
			Id   = "2.1"
			Task = "Enable Automatic Updates"
			LockPrefs = @(
				@{ Name = "app.update.auto"; Value = $true }
				@{ Name = "app.update.enabled"; Value = $true }
				@{ Name = "app.update.staging.enabled"; Value = $true }
			)
		}
		@{
			Id   = "2.2"
			Task = "Enable Auto-Notification of Outdated Plugins"
			LockPrefs = @(
				@{ Name = "plugins.update.notifyUser"; Value = $true }
			)
		}
		@{
			Id   = "2.3"
			Task = "Enable Information Bar for Outdated Plugins"
			LockPrefs = @(
				@{ Name = "plugins.hide_infobar_for_outdated_plugin"; Value = $false }
			)
		}
		@{
			Id   = "2.4"
			Task = "Set Update Interval Time Checks"
			LockPrefs = @(
				@{ Name = "app.update.interval"; Value = 43200 }
			)
		}
		@{
			Id   = "2.5"
			Task = "Set Update Wait Time Prompt"
			LockPrefs = @(
				@{ Name = "app.update.promptWaitTime"; Value = 172800 }
			)
		}
		@{
			Id   = "2.6"
			Task = "Ensure Update-related UI Components are Displayed"
			LockPrefs = @(
				@{ Name = "app.update.silent"; Value = $false }
			)
		}
		@{
			Id   = "2.7"
			Task = "Set Search Provider Update Behavior"
			LockPrefs = @(
				@{ Name = "app.update.auto"; Value = $true }
				@{ Name = "app.update.enabled"; Value = $true }
			)
		}
		# @{
		# 	Id   = "3.1"
		# 	Task = "Validate Proxy Settings"
		# }
		@{
			Id   = "3.2"
			Task = "Do Not Send Cross SSLTLS Referrer Header"
			LockPrefs = @(
				@{ Name = "network.http.sendSecureXSiteReferrer"; Value = $false }
			)
		}
		@{
			Id   = "3.3"
			Task = "Disable NTLM v1"
			LockPrefs = @(
				@{ Name = "network.auth.force-generic-ntlm-v1"; Value = $false }
			)
		}
		@{
			Id   = "3.4"
			Task = "Enable Warning For Phishy URLs"
			LockPrefs = @(
				@{ Name = "network.http.phishy-userpass-length"; Value = 1 }
			)
		}
		@{
			Id   = "3.5"
			Task = "Enable IDN Show Punycode"
			LockPrefs = @(
				@{ Name = "network.IDN_show_punycode"; Value = $true }
			)
		}
		@{
			Id   = "3.6"
			Task = "Set File URI Origin Policy"
			LockPrefs = @(
				@{ Name = "security.fileuri.strict_origin_policy"; Value = $true }
			)
		}
		@{
			Id   = "3.7"
			Task = "Disable Cloud Sync"
			LockPrefs = @(
				@{ Name = "services.sync.enabled"; Value = $false }
			)
		}
		@{
			Id   = "3.8"
			Task = "Disable WebRTC"
			LockPrefs = @(
				@{ Name = "media.peerconnection.enabled"; Value = $false }
				@{ Name = "media.peerconnection.use_document_iceservers"; Value = $false }
			)
		}
		@{
			Id   = "4.1"
			Task = "Set SSL Override Behavior"
			LockPrefs = @(
				@{ Name  = "browser.ssl_override_behavior"; Value = 0 }
			)
		}
		@{
			Id   = "4.2"
			Task = "Set Security TLS Version Maximum"
			LockPrefs = @(
				@{ Name  = "security.tls.version.max"; Value = 3 }
			)
		}
		@{
			Id   = "4.3"
			Task = "Set Security TLS Version Minimum "
			LockPrefs = @(
				@{ Name  = "security.tls.version.min"; Value = 1 }
			)
		}
		@{
			Id   = "4.4"
			Task = "Set OCSP Use Policy"
			LockPrefs = @(
				@{ Name  = "security.OCSP.enabled"; Value = 1 }
			)
		}
		@{
			Id   = "4.5"
			Task = "Block Mixed Active Content"
			LockPrefs = @(
				@{ Name  = "security.mixed_content.block_active_content"; Value = $true }
			)
		}
		@{
			Id   = "4.6"
			Task = "Set OCSP Response Policy"
			LockPrefs = @(
				@{ Name  = "security.OCSP.require"; Value = $true }
			)
		}
		@{
			Id   = "5.1"
			Task = "Disallow JavaScripts Ability to Change the Status Bar Text"
			LockPrefs = @(
				@{ Name = "dom.disable_window_status_change"; Value = $true }
			)
		}
		@{
			Id   = "5.2"
			Task = "Disable Scripting of Plugins by JavaScript"
			LockPrefs = @(
				@{ Name = "security.xpconnect.plugin.unrestricted"; Value = $false }
			)
		}
		@{
			Id   = "5.3"
			Task = "Disallow JavaScripts Ability to Hide the Address Bar"
			LockPrefs = @(
				@{ Name = "dom.disable_window_open_feature.location"; Value = $true }
			)
		}
		@{
			Id   = "5.4"
			Task = "Disallow JavaScripts Ability to Hide the Status Bar"
			LockPrefs = @(
				@{ Name = "dom.disable_window_open_feature.status"; Value = $true }
			)
		}
		@{
			Id   = "5.5"
			Task = "Disable Closing of Windows via Scripts"
			LockPrefs = @(
				@{ Name = "dom.allow_scripts_to_close_windows"; Value = $false }
			)
		}
		@{
			Id   = "5.6"
			Task = "Block Pop-up Windows"
			LockPrefs = @(
				@{ Name = "privacy.popups.policy"; Value = 1 }
			)
		}
		@{
			Id   = "5.7"
			Task = "Disable Displaying JavaScript in History URLs"
			LockPrefs = @(
				@{ Name = "browser.urlbar.filter.javascript"; Value = $true }
			)
		}
		@{
			Id   = "6.1"
			Task = "Disallow Credential Storage"
			LockPrefs = @(
				@{ Name = "signon.rememberSignons"; Value = $false }
			)
		}
		@{
			Id   = "6.2"
			Task = "Do Not Accept Third Party Cookies"
			LockPrefs = @(
				@{ Name = "network.cookie.cookieBehavior"; Value = 1 }
			)
		}
		@{
			Id   = "6.3"
			Task = "Tracking Protection"
			LockPrefs = @(
				@{ Name = "privacy.donottrackheader.enabled"; Value = $true }
				@{ Name = "privacy.donottrackheader.value"; Value = 1 }
				@{ Name = "privacy.trackingprotection.enabled"; Value = $true }
				@{ Name = "privacy.trackingprotection.pbmode"; Value = $true }
			)
		}
		@{
			Id   = "6.4"
			Task = "Set Delay for Enabling Security Sensitive Dialog Boxes"
			LockPrefs = @(
				@{ Name = "security.dialog_enable_delay"; Value = 2000 }
			)
		}
		@{
			Id   = "6.5"
			Task = "Disable Geolocation Serivces"
			LockPrefs = @(
				@{ Name = "geo.enabled"; Value = $false }
			)
		}
		@{
			Id   = "7.1"
			Task = "Secure Application Plug-ins"
			LockPrefs = @(
				@{ Name = "browser.helperApps.alwaysAsk.force"; Value = $true }
			)
		}
		@{
			Id   = "7.2"
			Task = "Disabling Auto-Install of Add-ons"
			LockPrefs = @(
				@{ Name = "xpinstall.whitelist.required"; Value = $true }
			)
		}
		@{
			Id   = "7.3"
			Task = "Enable Extension Block List"
			LockPrefs = @(
				@{ Name = "extensions.blocklist.enabled"; Value = $true }
			)
		}
		@{
			Id   = "7.4"
			Task = "Set Extension Block List Interval"
			LockPrefs = @(
				@{ Name = "extensions.blocklist.interval"; Value = 86400 }
			)
		}
		@{
			Id   = "7.5"
			Task = "Enable Warning for External Protocol Handler"
			LockPrefs = @(
				@{ Name = "network.protocol-handler.warn-external-default"; Value = $true }
			)
		}
		@{
			Id   = "7.6"
			Task = "Disable Popups Initiated by Plugins"
			LockPrefs = @(
				@{ Name = "privacy.popups.disable_from_plugins"; Value = 2 }
			)
		}
		@{
			Id   = "7.7"
			Task = "Enable Extension Auto Update"
			LockPrefs = @(
				@{ Name = "extensions.update.autoUpdateDefault"; Value = $true }
			)
		}
		@{
			Id   = "7.8"
			Task = "Enable Extension Update"
			LockPrefs = @(
				@{ Name = "extensions.update.enabled"; Value = $true }
			)
		}
		@{
			Id   = "7.9"
			Task = "Set Extension Update Interval Time Checks"
			LockPrefs = @(
				@{ Name = "extensions.update.interval"; Value = 86400 }
			)
		}
		@{
			Id   = "8.1"
			Task = "Enable Virus Scanning for Downloads"
			LockPrefs = @(
				@{ Name = "browser.download.manager.scanWhenDone"; Value = $true }
			)
		}
		@{
			Id   = "8.2"
			Task = "Disable JAR from Opening Unsafe File Types"
			LockPrefs = @(
				@{ Name = "network.jar.open-unsafe-types"; Value = $false }
			)
		}
		@{
			Id   = "8.3"
			Task = "Block Reported Web Forgeries"
			LockPrefs = @(
				@{ Name = "browser.safebrowsing.enabled"; Value = $true }
			)
		}
		@{
			Id   = "8.4"
			Task = "Block Reported Attack Sites"
			LockPrefs = @(
				@{ Name = "browser.safebrowsing.malware.enabled"; Value = $true }
			)
		}
	)
}

$DisaRequirements = @{
	# RegistrySettings = @(
	# 	@{
	# 		Id    = "DTBF003"
	# 		Task  = "Installed version of Firefox unsupported."
	# 		Path  = "HKLM\Software\Mozilla\Mozilla Firefox\CurrentVersion"
	# 		Name  = "firefox.exe"
	# 		Value = 0 # is equal to or greater than 50.1.x (or ESR 45.7.x)
	# 	}
	# )
	FirefoxLockPrefSettings = @(
		@{
			Id   = "DTBF030"
			Task = "Firewall traversal from remote host must be disabled."
			LockPrefs = @(
				@{ Name  = "security.enable_tls"; Value = $true }
				@{ Name  = "security.tls.version.min"; Value = 2 }
				@{ Name  = "security.tls.version.max"; Value = 3 }
			)
		}
		@{
			Id   = "DTBF050"
			Task = "FireFox is configured to ask which certificate to present to a web site when a certificate is required."
			LockPrefs = @(
				@{ Name  = "security.default_personal_cert"; Value = "Ask Every Time" }
			)
		}
		# @{ # Not set - in CIS Benchmarks
		# 	Id = "DTBF080"
		# 	Task = "Firefox application is set to auto-update."
		# }
		@{
			Id   = "DTBF085"
			Task = "Firefox automatically checks for updated version of installed Search plugins."
			LockPrefs = @(
				@{ Name  = "browser.search.update"; Value = $false }
			)
		}
		@{
			Id   = "DTBF090"
			Task = "Firefox automatically updates installed add-ons and plugins."
			LockPrefs = @(
				@{ Name  = "extensions.update.enabled"; Value = $false }
			)
		}
		@{
			Id   = "DTBF105"
			Task = "Network shell protocol is enabled in FireFox."
			LockPrefs = @(
				@{ Name  = "network.protocol-handler.external.shell"; Value = $false }
			)
		}
		# @{ # no longer available 
		# 	Id = "DTBF110"
		# 	Task = "Firefox is not configured to prompt a user before downloading and opening required file types."
		# }
		# @{ # no longer available 
		# 	Id = "DTBF130"
		# 	Task = "Firefox is not configured to provide warnings when a user switches from a secure (SSL-enabled) to a non-secure page."
		# }
		@{
			Id   = "DTBF140"
			Task = "Firefox formfill assistance option is disabled."
			LockPrefs = @(
				@{ Name  = "browser.formfill.enable"; Value = $false }
			)
		}
		@{
			Id   = "DTBF150"
			Task = "Firefox is configured to autofill passwords."
			LockPrefs = @(
				@{ Name  = "signon.autofillForms"; Value = $false }
			)
		}
		# @{ # Not set - in CIS Benchmarks
		# 	Id = "DTBF160"
		# 	Task = "FireFox is configured to use a password store with or without a master password."
		# }
		# @{ # Not set - see CIS benchmark 5.4_L1_Disallow_JavaScripts_Ability_to_Hide_the_Status_Bar
		# 	Id = "DTBF180"
		# 	Task = "FireFox is not configured to block pop-up windows.
		# }
		@{
			Id   = "DTBF181"
			Task = "FireFox is configured to allow JavaScript to move or resize windows."
			LockPrefs = @(
				@{ Name  = "dom.disable_window_move_resize"; Value = $true }
			)
		}
		@{
			Id   = "DTBF183"
			Task = " Firefox is configured to allow JavaScript to disable or replace context menus."
			LockPrefs = @(
				@{ Name  = "dom.event.contextmenu.enabled"; Value = $false }
			)
		}
		# @{ # Not set - in CIS Benchmarks
		# 	Id = "DTBF184"
		# 	Task = "Firefox is configured to allow JavaScript to hide or change the status bar."
		# }
		# @{ # no longer available 
		# 	Id = "DTBF186"
		# 	Task = "Extensions install must be disabled."
		# }
		@{
			Id   = "DTBF190"
			Task = "Background submission of information to Mozilla must be disabled."
			LockPrefs = @(
				@{ Name  = "datareporting.policy.dataSubmissionEnabled"; Value = $false }
				@{ Name  = "datareporting.healthreport.service.enabled"; Value = $false }
				@{ Name  = "datareporting.healthreport.uploadEnabled"; Value = $false }
			)
		}
	)
}

#endregion

#region helper classes
class LockPrefSetting {
	[string] $Name
	$Value
}
#endregion

#region Helper functions
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
					$regValue = $regValues -join ", "

				return @{
					Id = $Id
					Task = $Task
					Message = "Registry value: $regValue. Differs from allowed value: $ExpectedValue."
					Status = "False"
				}
			}
		}
		catch [System.Management.Automation.PSArgumentException] {
			if ($DoesNotExist) {
				return @{
					Id = $Id
					Task = $Task
					Message = "Compliant. Registry value not set."
					Status = "True"
				}
			}

			return @{
				Id = $Id
				Task = $Task
				Message = "Registry value not found."
				Status = "False"
			}
		}
		catch [System.Management.Automation.ItemNotFoundException] {
			if ($DoesNotExist) {
				return @{
					Id = $Id
					Task = $Task
					Message = "Compliant. Registry value not set."
					Status = "True"
				}
			}

			return @{
				Id = $Id
				Task = $Task
				Message = "Registry key not found."
				Status = "False"
			}
		}

		return @{
			Id = $Id
			Task = $Task
			Message = "Compliant"
			Status = "True"
		}
	}
}

function Get-FirefoxLocalSettingsFileAudit {
	$Id = "1.1"
	$Task = "Create local-settings.js file"

	if (-not (Test-Path (Get-FirefoxLocalSettingsFile))){
		return @{
			Id      = $Id
			Task    = $Task
			Message = "local-settings.js file does not exist."
			Status = "False"
		}
	}

	$generalConfigFilename = Get-Content (Get-FirefoxLocalSettingsFile) | Where-Object {
		$_ -match "^pref\s*\(\s*`"general\.config\.filename`"\s*,\s*`"([\w\-. ]+\.cfg)`"\s*\);"
	}
	
	if ($generalConfigFilename.Count -eq 0) {
		return @{
			Id      = $Id
			Task    = $Task
			Message = "File does not set 'general.config.filename'"
			Status = "False"
		}
	}

	$generalConfigObscure = Get-Content (Get-FirefoxLocalSettingsFile) | Where-Object {
		$_ -match "^pref\s*\(\s*`"general\.config\.obscure_value`"\s*,\s*0\s*\);"
	}
	
	if ($generalConfigObscure.Count -eq 0) {
		return @{
			Id      = $Id
			Task    = $Task
			Message = "File does not set 'general.config.obscure' = 0"
			Status = "False"
		}
	}

	return @{
		Id      = $Id
		Task    = $Task
		Message = "Compliant"
		Status = "True"
	}
}

function Get-FirefoxMozillaCfgFileAudit {
	$name = Get-FirefoxMozillaCfgFileName

	$Id = "1.3"
	$Task = "Create $name file"

	if (-not (Test-Path (Get-FirefoxMozillaCfgFile))){
		return @{
			Id      = $Id
			Task    = $Task
			Message = "$name file does not exist."
			Status = "False"
		}
	}

	return @{
		Id      = $Id
		Task    = $Task
		Message = "Compliant"
		Status = "True"
	}
}

function Get-FileAudit {
	[CmdletBinding()]
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
			return @{
				Id = $Id
				Task = $Task
				Message = "File does not exist."
				Status = "False"
			}
		}

		if (-not (&$Predicate (Get-Content $Path))) {
			return @{
				Id = $Id
				Task = $Task
				Message = "File does not match predicate."
				Status = "False"
			}
		}
		
		return @{
			Id = $Id
			Task = $Task
			Message = "Compliant."
			Status = "True"
		}
	}
}

function Get-LockPrefSettingAudit {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Id,
	
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string] $Task,
	
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[array] $LockPrefs,

		[LockPrefSetting[]] $CurrentLockPrefs = (Get-FirefoxLockPrefs)
	)
	
	process {
		if ($null -eq $CurrentLockPrefs) {
			return @{
				Id = $Id
				Task = $Task
				Message = "general config does not exist."
				Status = "None"
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

			return @{
				Id = $Id
				Task = $Task
				Message = "Missing lockprefs: $msg."
				Status = "False"
			}
		}
		
		return @{
			Id = $Id
			Task = $Task
			Message = "Compliant."
			Status = "True"
		}
	}
}
#endregion

$currentLockPrefs = Get-FirefoxLockPrefs

[Report] @{
	Title = 'Mozilla Firefox Audit Report'
	ModuleName = 'ATAPAuditor'
	AuditorVersion = '4.8'
	BasedOn = @(
		'CIS Mozilla Firefox 38 ESR Benchmark, Version: 1.0.0, Date: 2015-12-31'
		'DISA Mozilla FireFox Security Technical Implementation Guide, Version: V4R24, Date: 2019-01-25'
	)
	Sections = @(
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = 'This section contains all CIS benchmarks'
			Subsections = @(
				[ReportSection] @{
					Title = "Configure Locked Preferences"
					AuditInfos = @(
						Get-FirefoxLocalSettingsFileAudit
						# missing 1.2
						Get-FirefoxMozillaCfgFileAudit
						# missing 1.4
						# missing 1.5
					)
				}
				[ReportSection] @{
					Title = "Preference Settings"
					AuditInfos = foreach ($setting in $CisBenchmarks.FirefoxLockPrefSettings) {
						$obj = New-Object -TypeName psobject -Property $setting
						Write-Output ($obj | Get-LockPrefSettingAudit -CurrentLockPrefs $currentLockPrefs)
					}
				}
			)
		}
		[ReportSection] @{
			Title = 'DISA Recommendations'
			Description = 'This section contains all DISA recommendations'
			Subsections = @(
				[ReportSection] @{
					Title = "Preference Settings"
					AuditInfos = foreach ($setting in $DisaRequirements.FirefoxLockPrefSettings) {
						$obj = New-Object -TypeName psobject -Property $setting
						Write-Output ($obj | Get-LockPrefSettingAudit -CurrentLockPrefs $currentLockPrefs)
					}
				}
			)
		}
	)
}