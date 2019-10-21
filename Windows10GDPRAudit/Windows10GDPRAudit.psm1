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

function Test-Windows10_GDPR_MS_1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_1')
	$obj | Add-Member NoteProperty Task('Automatic Root Certificates Update | Check value DisableRootAutoUpdate')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableRootAutoUpdate -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_2.1.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_2.1.1')
	$obj | Add-Member NoteProperty Task('Allow Cortana | Check value AllowCortana')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowCortana -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_2.1.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_2.1.2')
	$obj | Add-Member NoteProperty Task('Allow search and Cortana to use location | Check value AllowSearchToUseLocation')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowSearchToUseLocation -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_2.1.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_2.1.3')
	$obj | Add-Member NoteProperty Task('Do not allow web search | Check value DisableWebSearch')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWebSearch -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_2.1.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_2.1.4')
	$obj | Add-Member NoteProperty Task('Dont search the web or display web results in Search | Check value ConnectedSearchUseWeb')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConnectedSearchUseWeb -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_2.1.5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_2.1.5')
	$obj | Add-Member NoteProperty Task('Set what information is shared in Search | Check value ConnectedSearchPrivacy')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConnectedSearchPrivacy -ErrorAction SilentlyContinue

	if ($regValue -eq "3") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_3.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_3.1')
	$obj | Add-Member NoteProperty Task('Prevent Windows from setting the time automatically | Check value Type')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Type -ErrorAction SilentlyContinue

	if ($regValue -eq "NoSync") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_3.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_3.2')
	$obj | Add-Member NoteProperty Task('Prevent Windows from setting the time automatically | Check value Enabled')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_4')
	$obj | Add-Member NoteProperty Task('Prevent Windows from retrieving device metadata from the Internet | Check value PreventDeviceMetadataFromNetwork')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PreventDeviceMetadataFromNetwork -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_5')
	$obj | Add-Member NoteProperty Task('Turn off Find My Device | Check value AllowFindMyDevice')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowFindMyDevice -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_6 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_6')
	$obj | Add-Member NoteProperty Task('Fonts that are included in Windows but that are not stored on the local device can be downloaded on demand | Check value EnableFontProviders')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableFontProviders -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_7 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_7')
	$obj | Add-Member NoteProperty Task('Turn off Insider Preview builds for Windows 10 | Check value AllowBuildPreview')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowBuildPreview -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.1')
	$obj | Add-Member NoteProperty Task('Turn on Suggested Sites | Check value Enabled')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.2')
	$obj | Add-Member NoteProperty Task('Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar | Check value AllowServicePoweredQSA')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowServicePoweredQSA -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.3')
	$obj | Add-Member NoteProperty Task('Turn off the auto-complete feature for web addresses | Check value AutoSuggest')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoSuggest -ErrorAction SilentlyContinue

	if ($regValue -eq "No") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.4')
	$obj | Add-Member NoteProperty Task('Turn off browser geolocation | Check value PolicyDisableGeolocation')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PolicyDisableGeolocation -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.5')
	$obj | Add-Member NoteProperty Task('Prevent managing SmartScreen filter | Check value EnabledV9')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnabledV9 -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.6 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.6')
	$obj | Add-Member NoteProperty Task('Choose whether employees can configure Compatibility View. | Check value DisableSiteListEditing')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableSiteListEditing -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.7 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.7')
	$obj | Add-Member NoteProperty Task('Turn off the flip ahead with page prediction feature | Check value Enabled')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.8 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.8')
	$obj | Add-Member NoteProperty Task('Turn off background synchronization for feeds and Web Slices | Check value BackgroundSyncStatus')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty BackgroundSyncStatus -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.9 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.9')
	$obj | Add-Member NoteProperty Task('Allow Online Tips | Check value AllowOnlineTips')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowOnlineTips -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.10 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.10')
	$obj | Add-Member NoteProperty Task('To turn off the home page | Check value Start Page')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start Page -ErrorAction SilentlyContinue

	if ($regValue -eq "about:blank") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.11 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.11')
	$obj | Add-Member NoteProperty Task('To turn off the home page | Check value Panel HomePage')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Panel HomePage -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.12 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.12')
	$obj | Add-Member NoteProperty Task('To configure the First Run Wizard | Check value DisableFirstRunCustomize')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableFirstRunCustomize -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.0.13 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.0.13')
	$obj | Add-Member NoteProperty Task('To configure the behavior for a new tab | Check value NewTabPageShow')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NewTabPageShow -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_8.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_8.1')
	$obj | Add-Member NoteProperty Task('ActiveX control blocking periodically downloads a new list of out-of-date ActiveX controls that should be blocked | Check value DownloadVersionList')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\Software\Microsoft\Internet Explorer\VersionManager" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DownloadVersionList -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_9 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_9')
	$obj | Add-Member NoteProperty Task('You can turn off License Manager related traffic by setting the following registry entry | Check value Start')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LicenseManager" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start -ErrorAction SilentlyContinue

	if ($regValue -eq "4") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_10 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_10')
	$obj | Add-Member NoteProperty Task('To turn off Live Tiles | Check value NoCloudApplicationNotification')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoCloudApplicationNotification -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_11 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_11')
	$obj | Add-Member NoteProperty Task('To turn off mail synchronization for Microsoft Accounts that are configured on a device | Check value ManualLaunchAllowed')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Mail" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ManualLaunchAllowed -ErrorAction SilentlyContinue

	if ($regValue -eq "4") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_12 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_12')
	$obj | Add-Member NoteProperty Task('To disable the Microsoft Account Sign-In Assistant | Check value wlidsvc Start')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty wlidsvc Start -ErrorAction SilentlyContinue

	if ($regValue -eq "4") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.1')
	$obj | Add-Member NoteProperty Task('Allow Address Bar drop-down list suggestions | Check value ShowOneBox')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowOneBox -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.2')
	$obj | Add-Member NoteProperty Task('Allow configuration updates for the Books Library | Check value AllowConfigurationUpdateForBooksLibrary')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowConfigurationUpdateForBooksLibrary -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.3')
	$obj | Add-Member NoteProperty Task('Configure Autofill | Check value Use FormSuggest')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Use FormSuggest -ErrorAction SilentlyContinue

	if ($regValue -eq "No") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.4')
	$obj | Add-Member NoteProperty Task('Configure Do Not Track | Check value DoNotTrack')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DoNotTrack -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.5')
	$obj | Add-Member NoteProperty Task('Configure Password Manager | Check value FormSuggest Passwords')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FormSuggest Passwords -ErrorAction SilentlyContinue

	if ($regValue -eq "No") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.6 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.6')
	$obj | Add-Member NoteProperty Task('Configure search suggestions in Address Bar | Check value ShowSearchSuggestionsGlobal')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowSearchSuggestionsGlobal -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.7 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.7')
	$obj | Add-Member NoteProperty Task('Configure Windows Defender SmartScreen Filter (Windows 10, version 1703) | Check value EnabledV9')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnabledV9 -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.8 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.8')
	$obj | Add-Member NoteProperty Task('Allow web content on New Tab page | Check value AllowWebContentOnNewTabPage')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowWebContentOnNewTabPage -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.9 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.9')
	$obj | Add-Member NoteProperty Task('Configure corporate Home pages | Check value ProvisionedHomePages')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProvisionedHomePages -ErrorAction SilentlyContinue

	if ($regValue -eq "about:blank") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.10 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.10')
	$obj | Add-Member NoteProperty Task('Prevent the First Run webpage from opening on Microsoft Edge | Check value PreventFirstRunPage')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PreventFirstRunPage -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_13.11 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_13.11')
	$obj | Add-Member NoteProperty Task('Choose whether employees can configure Compatibility View. | Check value MSCompatibilityMode')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MSCompatibilityMode -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_14 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_14')
	$obj | Add-Member NoteProperty Task('You can turn off NCSI by doing one of the following | Check value NoActiveProbe')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoActiveProbe -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_15.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_15.1')
	$obj | Add-Member NoteProperty Task('You can turn off the ability to download and update offline maps. | Check value AutoDownloadAndUpdateMapData')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoDownloadAndUpdateMapData -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_15.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_15.2')
	$obj | Add-Member NoteProperty Task('You can turn off the ability to download and update offline maps. | Check value AllowUntriggeredNetworkTrafficOnSettingsPage')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowUntriggeredNetworkTrafficOnSettingsPage -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_16.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_16.1')
	$obj | Add-Member NoteProperty Task('To turn off OneDrive in your organization | Check value DisableFileSyncNGSC')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableFileSyncNGSC -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_16.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_16.2')
	$obj | Add-Member NoteProperty Task('To turn off OneDrive in your organization | Check value PreventNetworkTrafficPreUserSignIn')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PreventNetworkTrafficPreUserSignIn -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.1.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.1.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID) | Check value Enabled')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.1.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.1.2')
	$obj | Add-Member NoteProperty Task('To turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID) | Check value DisabledByGroupPolicy')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisabledByGroupPolicy -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.1.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.1.3')
	$obj | Add-Member NoteProperty Task('To turn off Let websites provide locally relevant content by accessing my language list | Check value HttpAcceptLanguageOptOut')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\Control Panel\International\User Profile" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HttpAcceptLanguageOptOut -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.1.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.1.4')
	$obj | Add-Member NoteProperty Task('To turn off Let Windows track app launches to improve Start and search results | Check value Start_TrackProgs')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start_TrackProgs -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.2.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.2.1')
	$obj | Add-Member NoteProperty Task('To turn off Location for this device | Check value LetAppsAccessLocation')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessLocation -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.2.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.2.2')
	$obj | Add-Member NoteProperty Task('To turn off Location | Check value DisableLocation')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableLocation -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.3.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.3.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps use my camera | Check value LetAppsAccessCamera')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessCamera -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.4.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.4.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps use my microphone | Check value LetAppsAccessMicrophone')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessMicrophone -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.5.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.5.1')
	$obj | Add-Member NoteProperty Task('To turn off notifications network usage | Check value NoCloudApplicationNotification')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoCloudApplicationNotification -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.5.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.5.2')
	$obj | Add-Member NoteProperty Task('To turn off Let apps access my notifications | Check value LetAppsAccessNotifications')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessNotifications -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.6.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.6.1')
	$obj | Add-Member NoteProperty Task('To turn off dictation of your voice, speaking to Cortana and other apps, and to prevent sending your voice input to Microsoft Speech services | Check value HasAccepted')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HasAccepted -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.6.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.6.2')
	$obj | Add-Member NoteProperty Task('turn off updates to the speech recognition and speech synthesis models | Check value AllowSpeechModelUpdate')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Speech" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowSpeechModelUpdate -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.7.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.7.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps access my name, picture, and other account info | Check value LetAppsAccessAccountInfo')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessAccountInfo -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.8 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.8')
	$obj | Add-Member NoteProperty Task('To turn off Choose apps that can access contacts | Check value LetAppsAccessContacts')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessContacts -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.9.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.9.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps access my calendar | Check value LetAppsAccessCalendar')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessCalendar -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.10 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.10')
	$obj | Add-Member NoteProperty Task('To turn off Let apps access my call history | Check value LetAppsAccessCallHistory')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessCallHistory -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.11 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.11')
	$obj | Add-Member NoteProperty Task('To turn off Let apps access and send email | Check value LetAppsAccessEmail')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessEmail -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.12.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.12.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps read or send messages (text or MMS) | Check value LetAppsAccessMessaging')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessMessaging -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.12.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.12.3')
	$obj | Add-Member NoteProperty Task('To turn off Message Sync | Check value AllowMessageSync')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Messaging" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowMessageSync -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.13.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.13.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps make phone calls | Check value LetAppsAccessPhone')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessPhone -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.14.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.14.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps control radios | Check value LetAppsAccessRadios')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessRadios -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.15.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.15.1')
	$obj | Add-Member NoteProperty Task('To turn off Let apps automatically share and sync info with wireless devices that do not explicitly pair with your PC, tablet, or phone | Check value LetAppsSyncWithDevices')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsSyncWithDevices -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.15.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.15.2')
	$obj | Add-Member NoteProperty Task('To turn off Let your apps use your trusted devices (hardware youve already connected, or comes with your PC, tablet, or phone) | Check value LetAppsAccessTrustedDevices')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessTrustedDevices -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.16.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.16.1')
	$obj | Add-Member NoteProperty Task('To change how frequently Windows should ask for my feedback | Check value DoNotShowFeedbackNotifications')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DoNotShowFeedbackNotifications -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.16.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.16.2')
	$obj | Add-Member NoteProperty Task('To change the level of diagnostic and usage data sent when you Send your device data to Microsoft | Check value AllowTelemetry')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowTelemetry -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.16.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.16.3')
	$obj | Add-Member NoteProperty Task('To turn off tailored experiences with relevant tips and recommendations by using your diagnostics data | Check value DisableWindowsConsumerFeatures')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWindowsConsumerFeatures -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.16.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.16.4')
	$obj | Add-Member NoteProperty Task('To turn off tailored experiences with relevant tips and recommendations by using your diagnostics data | Check value DisableTailoredExperiencesWithDiagnosticData')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableTailoredExperiencesWithDiagnosticData -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.17 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.17')
	$obj | Add-Member NoteProperty Task('To turn off Let apps run in the background | Check value LetAppsRunInBackground')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsRunInBackground -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.18 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.18')
	$obj | Add-Member NoteProperty Task('To turn off Let Windows and your apps use your motion data and collect motion history | Check value LetAppsAccessMotion')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessMotion -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.19 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.19')
	$obj | Add-Member NoteProperty Task('In the Tasks area, you can choose which apps have access to your tasks | Check value LetAppsAccessTasks')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsAccessTasks -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.20 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.20')
	$obj | Add-Member NoteProperty Task('In the App diagnostics area, you can choose which apps have access to your diagnostic information | Check value LetAppsGetDiagnosticInfo')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsGetDiagnosticInfo -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.21 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.21')
	$obj | Add-Member NoteProperty Task('To turn off Inking & Typing data collection | Check value RestrictImplicitTextCollection')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RestrictImplicitTextCollection -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.22.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.22.1')
	$obj | Add-Member NoteProperty Task('In the Activity History area, you can choose turn Off tracking of your Activity History | Check value EnableActivityFeed')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableActivityFeed -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.22.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.22.2')
	$obj | Add-Member NoteProperty Task('In the Activity History area, you can choose turn Off tracking of your Activity History | Check value PublishUserActivities')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PublishUserActivities -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.22.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.22.3')
	$obj | Add-Member NoteProperty Task('In the Activity History area, you can choose turn Off tracking of your Activity History | Check value UploadUserActivities')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UploadUserActivities -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.23.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.23.1')
	$obj | Add-Member NoteProperty Task('In the Voice activation area, you can choose turn Off apps ability to listen for a Voice keyword. | Check value LetAppsActivateWithVoice')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LetAppsActivateWithVoice -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_18.23.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_18.23.2')
	$obj | Add-Member NoteProperty Task('In the Voice activation area, you can choose turn Off apps ability to listen for a Voice keyword. | Check value PublishUserActivities')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PublishUserActivities -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_19 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_19')
	$obj | Add-Member NoteProperty Task('Enterprise customers can manage their Windows activation status with volume licensing using an on-premises Key Management Server. You can opt out of sending KMS client activation data to Microsoft automatically by doing one of the following | Check value NoGenTicket')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoGenTicket -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_20 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_20')
	$obj | Add-Member NoteProperty Task('Enterprise customers can manage updates to the Disk Failure Prediction Model. | Check value AllowDiskHealthModelUpdates')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\StorageHealth" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowDiskHealthModelUpdates -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_21.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_21.1')
	$obj | Add-Member NoteProperty Task('You can control if your settings are synchronized | Check value DisableSettingSync')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableSettingSync -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_21.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_21.2')
	$obj | Add-Member NoteProperty Task('You can control if your settings are synchronized | Check value DisableSettingSyncUserOverride')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableSettingSyncUserOverride -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_21.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_21.3')
	$obj | Add-Member NoteProperty Task('To turn off Messaging cloud sync | Check value CloudServiceSyncEnabled')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Microsoft\Messaging" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CloudServiceSyncEnabled -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_22 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_22')
	$obj | Add-Member NoteProperty Task('You can disable Teredo by using Group Policy or by using the netsh.exe command | Check value Teredo_State')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Teredo_State -ErrorAction SilentlyContinue

	if ($regValue -eq "Disabled") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_23 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_23')
	$obj | Add-Member NoteProperty Task('To turn off Connect to suggested open hotspots and Connect to networks shared by my contacts | Check value AutoConnectAllowedOEM')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoConnectAllowedOEM -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.1')
	$obj | Add-Member NoteProperty Task('You can disconnect from the Microsoft Antimalware Protection Service | Check value SpyNetReporting')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SpyNetReporting -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.2')
	$obj | Add-Member NoteProperty Task('You can disconnect from the Microsoft Antimalware Protection Service | Check value ')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Updates" -ErrorAction SilentlyContinue

	if ($null -eq $regValue) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.3')
	$obj | Add-Member NoteProperty Task('You can stop sending file samples back to Microsoft | Check value SubmitSamplesConsent')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SubmitSamplesConsent -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.4')
	$obj | Add-Member NoteProperty Task('You can stop downloading Definition Updates | Check value FallbackOrder')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FallbackOrder -ErrorAction SilentlyContinue

	if ($regValue -eq "FileShares") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.5')
	$obj | Add-Member NoteProperty Task('You can stop downloading Definition Updates | Check value DefinitionUpdateFileSharesSources')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -ErrorAction SilentlyContinue

	if ($null -eq $regValue) {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.6 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.6')
	$obj | Add-Member NoteProperty Task('You can turn off Malicious Software Reporting Tool diagnostic data | Check value DontReportInfectionInformation')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MRT" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DontReportInfectionInformation -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.0.7 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.0.7')
	$obj | Add-Member NoteProperty Task('You can turn off Enhanced Notifications as follows | Check value DisableEnhancedNotifications')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableEnhancedNotifications -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.1.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.1.1')
	$obj | Add-Member NoteProperty Task('To disable Windows Defender Smartscreen | Check value EnableSmartScreen')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableSmartScreen -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.1.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.1.2')
	$obj | Add-Member NoteProperty Task('To disable Windows Defender Smartscreen | Check value ConfigureAppInstallControlEnabled')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConfigureAppInstallControlEnabled -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_24.1.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_24.1.3')
	$obj | Add-Member NoteProperty Task('To disable Windows Defender Smartscreen | Check value ConfigureAppInstallControl')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConfigureAppInstallControl -ErrorAction SilentlyContinue

	if ($regValue -eq "Anywhere") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_25.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_25.1')
	$obj | Add-Member NoteProperty Task('Windows Spotlight provides features such as different background images and text on the lock screen, suggested apps, Microsoft account notifications, and Windows tips | Check value DisableWindowsSpotlightFeatures')

	$regValue = Get-ItemProperty -Path Registry::"HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWindowsSpotlightFeatures -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_25.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_25.2')
	$obj | Add-Member NoteProperty Task(' | Check value NoLockScreen')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoLockScreen -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_25.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_25.3')
	$obj | Add-Member NoteProperty Task(' | Check value LockScreenImage')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LockScreenImage -ErrorAction SilentlyContinue

	if ($regValue -eq "C:\windows\web\screen\lockscreen.jpg") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_25.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_25.4')
	$obj | Add-Member NoteProperty Task(' | Check value LockScreenOverlaysDisabled')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LockScreenOverlaysDisabled -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_25.5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_25.5')
	$obj | Add-Member NoteProperty Task(' | Check value DisableSoftLanding')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableSoftLanding -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_25.6 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_25.6')
	$obj | Add-Member NoteProperty Task(' | Check value DisableWindowsConsumerFeatures')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWindowsConsumerFeatures -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_26.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_26.1')
	$obj | Add-Member NoteProperty Task('You can turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded | Check value DisableStoreApps')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableStoreApps -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_26.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_26.2')
	$obj | Add-Member NoteProperty Task('You can turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded | Check value AutoDownload')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoDownload -ErrorAction SilentlyContinue

	if ($regValue -eq "2") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_27 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_27')
	$obj | Add-Member NoteProperty Task('You can turn off apps for websites, preventing customers who visit websites that are registered with their associated app from directly launching the app | Check value EnableAppUriHandlers')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableAppUriHandlers -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_28.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_28.3')
	$obj | Add-Member NoteProperty Task(' | Check value DODownloadMode')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DODownloadMode -ErrorAction SilentlyContinue

	if ($regValue -eq "100") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_29.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_29.1')
	$obj | Add-Member NoteProperty Task('You can turn off Windows Update | Check value DoNotConnectToWindowsUpdateInternetLocations')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DoNotConnectToWindowsUpdateInternetLocations -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_29.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_29.2')
	$obj | Add-Member NoteProperty Task('You can turn off Windows Update | Check value DisableWindowsUpdateAccess')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWindowsUpdateAccess -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_29.3 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_29.3')
	$obj | Add-Member NoteProperty Task('You can turn off Windows Update | Check value WUServer')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty WUServer -ErrorAction SilentlyContinue

	if ($regValue -eq "") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_29.4 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_29.4')
	$obj | Add-Member NoteProperty Task('You can turn off Windows Update | Check value WUStatusServer')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty WUStatusServer -ErrorAction SilentlyContinue

	if ($regValue -eq "") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_29.5 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_29.5')
	$obj | Add-Member NoteProperty Task('You can turn off Windows Update | Check value UpdateServiceUrlAlternate')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UpdateServiceUrlAlternate -ErrorAction SilentlyContinue

	if ($regValue -eq "") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_MS_29.6 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_MS_29.6')
	$obj | Add-Member NoteProperty Task('You can turn off Windows Update | Check value UseWUServer')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UseWUServer -ErrorAction SilentlyContinue

	if ($regValue -eq "1") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Get-MSAuditResult {
	[CmdletBinding()]
	Param()

	Test-Windows10_GDPR_MS_1
	Test-Windows10_GDPR_MS_2.1.1
	Test-Windows10_GDPR_MS_2.1.2
	Test-Windows10_GDPR_MS_2.1.3
	Test-Windows10_GDPR_MS_2.1.4
	Test-Windows10_GDPR_MS_2.1.5
	Test-Windows10_GDPR_MS_3.1
	Test-Windows10_GDPR_MS_3.2
	Test-Windows10_GDPR_MS_4
	Test-Windows10_GDPR_MS_5
	Test-Windows10_GDPR_MS_6
	Test-Windows10_GDPR_MS_7
	Test-Windows10_GDPR_MS_8.0.1
	Test-Windows10_GDPR_MS_8.0.2
	Test-Windows10_GDPR_MS_8.0.3
	Test-Windows10_GDPR_MS_8.0.4
	Test-Windows10_GDPR_MS_8.0.5
	Test-Windows10_GDPR_MS_8.0.6
	Test-Windows10_GDPR_MS_8.0.7
	Test-Windows10_GDPR_MS_8.0.8
	Test-Windows10_GDPR_MS_8.0.9
	Test-Windows10_GDPR_MS_8.0.10
	Test-Windows10_GDPR_MS_8.0.11
	Test-Windows10_GDPR_MS_8.0.12
	Test-Windows10_GDPR_MS_8.0.13
	Test-Windows10_GDPR_MS_8.1
	Test-Windows10_GDPR_MS_9
	Test-Windows10_GDPR_MS_10
	Test-Windows10_GDPR_MS_11
	Test-Windows10_GDPR_MS_12
	Test-Windows10_GDPR_MS_13.1
	Test-Windows10_GDPR_MS_13.2
	Test-Windows10_GDPR_MS_13.3
	Test-Windows10_GDPR_MS_13.4
	Test-Windows10_GDPR_MS_13.5
	Test-Windows10_GDPR_MS_13.6
	Test-Windows10_GDPR_MS_13.7
	Test-Windows10_GDPR_MS_13.8
	Test-Windows10_GDPR_MS_13.9
	Test-Windows10_GDPR_MS_13.10
	Test-Windows10_GDPR_MS_13.11
	Test-Windows10_GDPR_MS_14
	Test-Windows10_GDPR_MS_15.1
	Test-Windows10_GDPR_MS_15.2
	Test-Windows10_GDPR_MS_16.1
	Test-Windows10_GDPR_MS_16.2
	Test-Windows10_GDPR_MS_18.1.1
	Test-Windows10_GDPR_MS_18.1.2
	Test-Windows10_GDPR_MS_18.1.3
	Test-Windows10_GDPR_MS_18.1.4
	Test-Windows10_GDPR_MS_18.2.1
	Test-Windows10_GDPR_MS_18.2.2
	Test-Windows10_GDPR_MS_18.3.1
	Test-Windows10_GDPR_MS_18.4.1
	Test-Windows10_GDPR_MS_18.5.1
	Test-Windows10_GDPR_MS_18.5.2
	Test-Windows10_GDPR_MS_18.6.1
	Test-Windows10_GDPR_MS_18.6.2
	Test-Windows10_GDPR_MS_18.7.1
	Test-Windows10_GDPR_MS_18.8
	Test-Windows10_GDPR_MS_18.9.1
	Test-Windows10_GDPR_MS_18.10
	Test-Windows10_GDPR_MS_18.11
	Test-Windows10_GDPR_MS_18.12.1
	Test-Windows10_GDPR_MS_18.12.3
	Test-Windows10_GDPR_MS_18.13.1
	Test-Windows10_GDPR_MS_18.14.1
	Test-Windows10_GDPR_MS_18.15.1
	Test-Windows10_GDPR_MS_18.15.2
	Test-Windows10_GDPR_MS_18.16.1
	Test-Windows10_GDPR_MS_18.16.2
	Test-Windows10_GDPR_MS_18.16.3
	Test-Windows10_GDPR_MS_18.16.4
	Test-Windows10_GDPR_MS_18.17
	Test-Windows10_GDPR_MS_18.18
	Test-Windows10_GDPR_MS_18.19
	Test-Windows10_GDPR_MS_18.20
	Test-Windows10_GDPR_MS_18.21
	Test-Windows10_GDPR_MS_18.22.1
	Test-Windows10_GDPR_MS_18.22.2
	Test-Windows10_GDPR_MS_18.22.3
	Test-Windows10_GDPR_MS_18.23.1
	Test-Windows10_GDPR_MS_18.23.2
	Test-Windows10_GDPR_MS_19
	Test-Windows10_GDPR_MS_20
	Test-Windows10_GDPR_MS_21.1
	Test-Windows10_GDPR_MS_21.2
	Test-Windows10_GDPR_MS_21.3
	Test-Windows10_GDPR_MS_22
	Test-Windows10_GDPR_MS_23
	Test-Windows10_GDPR_MS_24.0.1
	Test-Windows10_GDPR_MS_24.0.2
	Test-Windows10_GDPR_MS_24.0.3
	Test-Windows10_GDPR_MS_24.0.4
	Test-Windows10_GDPR_MS_24.0.5
	Test-Windows10_GDPR_MS_24.0.6
	Test-Windows10_GDPR_MS_24.0.7
	Test-Windows10_GDPR_MS_24.1.1
	Test-Windows10_GDPR_MS_24.1.2
	Test-Windows10_GDPR_MS_24.1.3
	Test-Windows10_GDPR_MS_25.1
	Test-Windows10_GDPR_MS_25.2
	Test-Windows10_GDPR_MS_25.3
	Test-Windows10_GDPR_MS_25.4
	Test-Windows10_GDPR_MS_25.5
	Test-Windows10_GDPR_MS_25.6
	Test-Windows10_GDPR_MS_26.1
	Test-Windows10_GDPR_MS_26.2
	Test-Windows10_GDPR_MS_27
	Test-Windows10_GDPR_MS_28.3
	Test-Windows10_GDPR_MS_29.1
	Test-Windows10_GDPR_MS_29.2
	Test-Windows10_GDPR_MS_29.3
	Test-Windows10_GDPR_MS_29.4
	Test-Windows10_GDPR_MS_29.5
	Test-Windows10_GDPR_MS_29.6
}
function Test-Windows10_GDPR_BSI_3.1.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_BSI_3.1.1')
	$obj | Add-Member NoteProperty Task('Configuration of the lowest telemetry-level | Check value AllowTelemetry')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllowTelemetry -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_BSI_3.1.2.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_BSI_3.1.2.1')
	$obj | Add-Member NoteProperty Task('Deactivation of the telemetry-service and etw-sessions | Check value Start')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start -ErrorAction SilentlyContinue

	if ($regValue -eq "4") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_BSI_3.1.2.2 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_BSI_3.1.2.2')
	$obj | Add-Member NoteProperty Task('Deactivation of the telemetry-service and etw-sessions | Check value Start')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start -ErrorAction SilentlyContinue

	if ($regValue -eq "0") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Test-Windows10_GDPR_BSI_3.1.3.1 {
	[CmdletBinding()]
	Param()
	$obj = New-Object PSObject
	$obj | Add-Member NoteProperty Name('Test-Windows10_GDPR_BSI_3.1.3.1')
	$obj | Add-Member NoteProperty Task('Deactivation of telemetry according to Microsoft recommendation | Check value Start')

	$regValue = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start -ErrorAction SilentlyContinue

	if ($regValue -eq "4") {
		$obj | Add-Member NoteProperty Status("Compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::True)
	}
	else {
		$obj | Add-Member NoteProperty Status("Not compliant")
		$obj | Add-Member NoteProperty Passed([AuditStatus]::False)
	}
	Write-Output $obj
}

function Get-BSIAuditResult {
	[CmdletBinding()]
	Param()

	Test-Windows10_GDPR_BSI_3.1.1
	Test-Windows10_GDPR_BSI_3.1.2.1
	Test-Windows10_GDPR_BSI_3.1.2.2
	Test-Windows10_GDPR_BSI_3.1.3.1
}

function Convert-ToAuditInfo {
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Psobject] $auditObject
	)

	process {
		Write-Output (New-Object -TypeName AuditInfo -Property @{
				Id = $auditObject.Name
				Task = $auditObject.Task
				Message = $auditObject.Status
				Audit = $auditObject.Passed
			})
	}
}


function Get-Windows10GDPRHtmlReport {
	<#
    .Synopsis
        Generates an audit report in an html file.
    .Description
        The Get-Windows10GDPRHtmlReport cmdlet collects by default data from the current machine to generate an audit report.
    .Parameter Path
        Specifies the relative path to the file in which the report will be stored.
    .Example
        C:\PS> Get-Windows10GDPRHtmlReport -Path "MyReport.html"
    #>

	[CmdletBinding()]
	param (
		[string] $Path = "$($env:HOMEPATH)\Documents\$(Get-Date -UFormat %Y%m%d_%H%M)_auditreport.html",

		[switch] $DarkMode,

		[switch] $PerformanceOptimized
	)

	[hashtable[]]$sections = @(

		@{
			Title = "GDPR settings by MicroSoft"
			AuditInfos = Get-MSAuditResult | Convert-ToAuditInfo | Sort-Object -Property Id
		}

		@{
			Title = "Bundesamt für Sicherheit in der Informationstechnik (BSI)"
			AuditInfos = Get-BSIAuditResult | Convert-ToAuditInfo | Sort-Object -Property Id
		}
	)

	Get-ATAPHtmlReport -Path $Path -Title "Windows 10 GDPR Audit Report" -ModuleName "Windows10GDPRAudit" -BasedOn $sections.Title -Sections $sections -DarkMode:$DarkMode
}
