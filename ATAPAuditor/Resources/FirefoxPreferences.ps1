# Calculate Firefox installation path
$firefoxRegKeyPath = 'HKLM:\SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox\'
if (-not (Test-Path $firefoxRegKeyPath)) {
	$firefoxRegKeyPath = 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\'
}
$currentFirefoxRegKey = Get-ChildItem -Path $firefoxRegKeyPath | Select-Object -Last 1
$installDirRegKey = $currentFirefoxRegKey | Get-ChildItem | Where-Object PSChildName -EQ 'Main'
$InstallationPath = $installDirRegKey | Get-ItemProperty | Select-Object -ExpandProperty 'Install Directory'

# Calculate Firefox local-settings path
$LocalSettingsPath = "$InstallationPath\defaults\pref\local-settings.js"

# Calculate Firefox config path
$preferenceConfigFilename = 'mozilla.cfg'
if (Test-Path $LocalSettingsPath) {
	foreach ($line in (Get-Content $LocalSettingsPath)) {
		if ($_ -match "^pref\(`"general\.config\.filename`",\s?`"([\w\-. ]+\.cfg)`"\);") {
			$preferenceConfigFilename = $Matches[1]
		}
	}
}
$PreferenceConfigPath = "$InstallationPath\$preferenceConfigFilename"

# Gather lines into lockPref list
# if (-not (Test-Path $LocalSettingsPath) -or
# 	-not (Test-Path $PreferenceConfigPath)) {
# 	return $null
# }

$boolRegex = '(?<bool>true|false)'
$numberRegex = '(?<number>\d+)'
$stringRegex = '"(?<string>(\\.|[^`"\\])*)"'
$lineRegex = "^lockPref\s*\(\s*`"([\w.-]+)`"\s*,\s*({0}|{1}|{2})\s*\);" -f $boolRegex, $numberRegex, $stringRegex

$LockedPreferences = @()
if (Test-Path $PreferenceConfigPath) {
	foreach ($line in (Get-Content $PreferenceConfigPath)) {
		if ($line -match $lineRegex) {
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
	
			$LockedPreferences += [FirefoxPreference]@{ Name = $Matches[1]; Value = $value }
		}
	}
}

return [PSCustomObject] @{
	InstallationPath = $InstallationPath
	LocalSettingsPath = $LocalSettingsPath
	PreferenceConfigPath = $PreferenceConfigPath
	LockedPreferences = $LockedPreferences
}
