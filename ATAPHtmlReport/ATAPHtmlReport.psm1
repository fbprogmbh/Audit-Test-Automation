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

    Author(s):        Benedikt Böhme
    Date:             08/19/2018
    Version:          1.0
    Last Change:      08/19/2018
#>

Import-LocalizedData -FileName Settings.ps1 -BindingVariable Settings

enum AuditStatus {
    True
    False
    Warning
    None
}

class AuditInfo {
    [string] $Id
    [string] $Task
    [string] $Message
    [AuditStatus] $Audit
}

function Get-ATAPCombinedAuditStatus {
	param(
		[Parameter(Mandatory = $true)]
		[AuditStatus[]] $Audits
	)

	if ($Audits -contains [AuditStatus]::False) {
		[AuditStatus]::False
	}
	elseif ($Audits -contains [AuditStatus]::Warning) {
		[AuditStatus]::Warning
	}
	elseif ($Audits -contains [AuditStatus]::True) {
		[AuditStatus]::True
	}
	else {
		[AuditStatus]::None
	}
}

function Get-ATAPHtmlSectionStatus {
	param(
		[Parameter(Mandatory = $true)]
		[hashtable] $Section
	)

	$subSectionStatuses = @()
	if ($Section.Keys -contains "AuditInfos") {
		$subSectionStatuses += $Section.AuditInfos.Audit
	}
	if ($Section.Keys -contains "SubSections") {
		$subSectionStatuses += $Section.SubSections | Foreach-Object { Get-ATAPHtmlSectionStatus -Section $_ }
	}
	return Get-ATAPCombinedAuditStatus -Audits $subSectionStatuses
}

function Convert-ATAPAuditStatusToHtmlClass {
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[AuditStatus] $AuditStatus
	)

	process {
		switch ($AuditStatus) {
			"True" { "passed" }
			"False" { "failed" }
			"Warning" { "warning" }
			Default { "" }
		}
	}
}

function Convert-SectionTitleToHtmlId {
	param(
		[Parameter(Mandatory = $true)]
		[string] $Title
	)

	return ([char[]]$Title | ForEach-Object {
			switch ($_) {
				' ' { "-" }
				'-' { "--" }
				Default {$_}
			}
		}) -join ""
}

function Convert-ATAPAuditInfoToHtmlTableRow {
	param(
		[Parameter(Mandatory = $true)]
		[AuditInfo] $AuditInfo
	)

	process {
		$tableData = foreach ($Property in [AuditInfo].GetProperties()) {
			$value = $Property.GetValue($AuditInfo, $null)

			if ($Property.Name -eq "Audit") {
				$auditClass = Convert-ATAPAuditStatusToHtmlClass -AuditStatus $value
				$value = "<span class=`"auditstatus $auditClass`">$value</span>"
			}

			"<td>$value</td>"
		}

		return "<tr>$tableData</tr>"
	}
}

function Get-ATAPHtmlSectionLinks {
	param(
		[Parameter(Mandatory = $true)]
		[hashtable[]] $Sections,

		[string] $Prepend = ""
	)

	$html = "<ul>"
	foreach ($Section in $Sections) {
		$id = Convert-SectionTitleToHtmlId -Title ($Prepend + $Section.Title)

		$html += "<li>"
		$html += "<a href=`"#$id`">$($Section.Title)</a>"
		if ($Section.Keys -contains "SubSections") {
			$html += Get-ATAPHtmlSectionLinks -Sections $Section.SubSections -Prepend ($Prepend + $Section.Title)
		}
		$html += "</li>"
	}
	$html += "</ul>"

	return $html
}

function Get-ATAPHtmlSection {
	param(
		[Parameter(Mandatory = $true)]
		[hashtable[]] $Sections,

		[string] $Prepend = ""
	)

	$html = ""
	foreach ($Section in $Sections) {
		$id = Convert-SectionTitleToHtmlId -Title ($Prepend + $Section.Title)
		$sectionStatus = Get-ATAPHtmlSectionStatus -Section $Section
		$class = Convert-ATAPAuditStatusToHtmlClass -AuditStatus $sectionStatus

		$html += "<section>"
		$html += "<h1 id=`"$id`">"
		$html += "<span class=`"$class`">$($Section.Title)</span>"
		$html += "<a href=`"#`" class=`"totop`">^</a>"
		$html += "</h1>"

		if ($Section.Keys -contains "Description") {
			$html += "<p>$($Section.Description)</p>"
		}
		if ($Section.Keys -contains "AuditInfos") {
			$tableHead = [AuditInfo].GetProperties().Name | ForEach-Object { "<th>$_</th>" }
			$tableRows = $Section.AuditInfos | Foreach-Object { Convert-ATAPAuditInfoToHtmlTableRow -AuditInfo $_ }
			$html += "<table class=`"audit-info`"><tbody><tr>$tableHead</tr>$tableRows</tbody></table>"
		}
		if ($Section.Keys -contains "SubSections") {
			$html += Get-ATAPHtmlSection -Sections $Section.SubSections -Prepend ($Prepend + $Section.Title)
		}
		$html += "</section>"
	}

	return $html
}

function Get-ATAPHostInformation {
	$infos = Get-CimInstance Win32_OperatingSystem
	$disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"

	return [ordered]@{
		"Hostname"                  = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
		"Operating System"          = $infos.Caption
		"Build Number"              = $infos.BuildNumber
		"Free physical memory (GB)" = "{0:N3}" -f ($infos.FreePhysicalMemory / 1MB)
		"Free disk space(GB)      " = "{0:N1}" -f ($disk.FreeSpace / 1GB)
	}
}

function Get-ATAPHtmlReport {
	<#
	.Synopsis
		Generates an audit report in an html file.
	.Description
		The `Get-ATAPHtmlReport` cmdlet collects data from the current machine to generate an audit report.
	.Parameter Path
		Specifies the relative path to the file in which the report will be stored.
	.Example
		C:\PS> Get-ATAPHtmlReport -Path "MyReport.html"
	#>

	[CmdletBinding()]
	[OutputType([string])]
	Param(
		[Parameter(Mandatory = $true)]
		[string] $Path,

		[Parameter(Mandatory = $true)]
		[string] $Title,

		[Parameter(Mandatory = $true)]
		[string] $ModuleName,

		[Parameter(Mandatory = $true)]
		[string[]] $BasedOn,

		[hashtable] $HostInformation = (Get-ATAPHostInformation),

		[hashtable[]] $Sections,

		[switch] $DarkMode
	)

	$scriptRoot = Split-Path -Parent $PSCommandPath

	$cssDocument = if (-not $DarkMode) {
		"/report.css"
	}
	else {
		"/report.dark.css"
	}
	$cssPath = $scriptRoot | Join-path -ChildPath $cssDocument
	$css = Get-Content $cssPath

	# HTML <head> markup
	$head = "<meta charset=`"UTF-8`">"
	$head += "<meta name=`"viewport`" content=`"width=device-width, initial-scale=1.0`">"
	$head += "<meta http-equiv=`"X-UA-Compatible`" content=`"ie=edge`">"
	$head += "<title>$Title [$(Get-Date)]</title>"
	$head += "<style>$css</style>"

	# HTML <body> markup
	# Header
	$body = "<div class=`"header`">"
	$body += "<img alt=`"FB-Pro GmbH`" src=`"$($Settings.Logo)`">"
	$body += "<h1>$Title</h1>"
	$body += "<p>Generated by the <i>$ModuleName</i> Module by FB Pro GmbH. Get it in the <a href=`"$($Settings.PackageLink)`">Audit Test Automation Package</a>.</p>"
	$body += "<p>Based on $($BasedOn -join ", ").</p>"
	$body += "</div>"
	# Main section
	$body += "<p>This report was generated at $((Get-Date)) on $($HostInformation.Hostname).</p>"
	$body += "<table>"
	$body += "<tbody>"
	foreach ($Key in $HostInformation.Keys) {
		$body += "<tr>"
		$body += "<th scope=`"row`">$Key</th><td>$($HostInformation[$Key])</td>"
		$body += "</tr>"
	}
	$body += "</tbody>"
	$body += "</table>"
	# Section navigation
	$body += "<h1>Navigation</h1>"
	$body += "<p>Click the link(s) below for quick access to a report section.</p>"
	$body += Get-ATAPHtmlSectionLinks -Sections $Sections
	# Sections
	$body += Get-ATAPHtmlSection -Sections $Sections

	$html = "<!DOCTYPE html><html lang=`"en`"><head>$head</head><body>$body</body></html> "

	$html > $Path
}