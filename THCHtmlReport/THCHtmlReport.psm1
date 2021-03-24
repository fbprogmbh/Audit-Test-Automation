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

$ScriptRoot = Split-Path -Parent $PSCommandPath

$Settings = Import-PowerShellDataFile -Path "$ScriptRoot\Settings.psd1"
$ModuleVersion = (Import-PowerShellDataFile -Path "$ScriptRoot\THCHtmlReport.psd1").ModuleVersion

$StatusValues = 'True', 'False', 'Warning', 'None', 'Error'
$AuditProperties = @{ Name = 'Id' }, @{ Name = 'Task' }, @{ Name = 'Message' }, @{ Name = 'Status' }

function Join-THCReportStatus {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory = $true)]
		[string[]]
		$Statuses
	)

	if ($Statuses -contains 'False') {
		return 'False'
	}
	elseif ($Statuses -contains 'Error') {
		return 'Warning'
	}
	elseif ($Statuses -contains 'Warning') {
		return 'Warning'
	}
	elseif ($Statuses -contains 'True') {
		return 'True'
	}
	else {
		return 'None'
	}
}

function htmlElement {
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]
		$ElementName,

		[Parameter(Mandatory = $true, Position = 1)]
		[hashtable]
		$Attributes,

		[Parameter(Mandatory = $true, Position = 2)]
		[scriptblock]
		$Children
	)

	$htmlAttributes = @()
	foreach ($attribute in $Attributes.GetEnumerator()) {
		$htmlAttributes += '{0}="{1}"' -f $attribute.Name, $attribute.Value
	}

	[string[]]$htmlChildren = & $Children

	return '<{0} {1}>{2}</{0}>' -f $ElementName, ($htmlAttributes -join ' '), ($htmlChildren -join '')
}

function Get-SectionStatus {
	param(
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[Alias('AuditInfos')]
		[array]
		$ConfigAudits,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Subsections
	)

	process {
		$allStatuses = @()
		if ($null -ne $ConfigAudits) {
			$allStatuses += $ConfigAudits.Status
		}
		if ($null -ne $Subsections) {
			foreach ($subsection in $Subsections) {
				$allStatuses += $subsection | Get-SectionStatus
			}
		}
		return Join-THCReportStatus $allStatuses
	}
}

function Get-HtmlClassFromStatus {
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$Status
	)

	process {
		switch ($Status) {
			'True' { 'passed' }
			'False' { 'failed' }
			'Warning' { 'warning' }
			Default { "" }
		}
	}
}

function Convert-SectionTitleToHtmlId {
	param(
		[Parameter(Mandatory = $true)]
		[string] $Title
	)

	$charMap = {
		switch ($_) {
			' ' { "-" }
			'-' { "--" }
			Default {$_}
		}
	}

	return ([char[]]$Title | ForEach-Object $charMap) -join ''
}

function Get-HtmlTableRow {
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$Audit
	)

	process {
		# $properties = $Audit | Get-Member -MemberType Property

		htmlElement 'tr' @{} {
			foreach ($property in $AuditProperties) {
				$value = $Audit | Select-Object -ExpandProperty $property.Name
				if ($Property.Name -eq 'Status') {
					$class = Get-HtmlClassFromStatus $Audit.Status
					$value = htmlElement 'span' @{ class = "auditstatus $class" } { $value }
				}
				htmlElement 'td' @{} { $value }
			}
		}
	}
}

function Get-HtmlToc {
	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Subsections,

		[string]
		$Prefix = ''
	)

	process {
		$id = Convert-SectionTitleToHtmlId -Title ($Prefix + $Title)
		htmlElement 'li' @{} {
			htmlElement 'a' @{ href = "#$id" } { $Title }
			if ($null -ne $Subsections) {
				htmlElement 'ul' @{} {
					foreach ($subsection in $Subsections) {
						$subsection | Get-HtmlToc -Prefix ($Prefix + $Title)
					}
				}
			}
		}
	}
}

function Get-HtmlReportSection {
	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Description,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[alias('AuditInfos')]
		[array]
		$ConfigAudits,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[alias('Sections')]
		[array]
		$Subsections,

		[Parameter(Mandatory = $false)]
		[string]
		$Prefix
	)

	process {
		$id = Convert-SectionTitleToHtmlId -Title ($Prefix + $Title)
		$sectionStatus = Get-SectionStatus -ConfigAudits $ConfigAudits -Subsections $Subsections
		$class = Get-HtmlClassFromStatus $sectionStatus

		htmlElement 'section' @{} {
			htmlElement 'h1' @{ id = $id } {
				htmlElement 'span' @{ class = $class } { $Title }
				htmlElement 'span' @{ class = 'sectionAction collapseButton' } { '-' }
				htmlElement 'a' @{ href = '#toc'; class = 'sectionAction'} {
					htmlElement 'span' @{ style = "font-size: 75%;" } { '&uarr;' }
				}
			}

			if ($null -ne $Description) {
				htmlElement 'p' @{} { $Description }
			}
			if ($null -ne $ConfigAudits) {
				htmlElement 'table' @{ class = 'audit-info' } {
					htmlElement 'tbody' @{} {
						htmlElement 'tr' @{} {
							foreach ($columnName in $AuditProperties.Name) {
								htmlElement 'th' @{} { $columnName }
							}
						}
						foreach ($configAudit in $ConfigAudits) {
							$configAudit | Get-HtmlTableRow
						}
					}
				}
			}
			if ($null -ne $Subsections) {
				foreach ($subsection in $Subsections) {
					$subsection | Get-HtmlReportSection -Prefix ($Prefix + $Title)
				}
			}
		}
	}
}

function Get-THCHostInformation {
	$infos = Get-CimInstance Win32_OperatingSystem
	$disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"

	return [ordered]@{
		"Hostname"                  = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
		"Operating System"          = $infos.Caption
		"Installation Language"     = ((Get-UICulture).DisplayName)
		"Build Number"              = $infos.BuildNumber
		"Free physical memory (GB)" = "{0:N3}" -f ($infos.FreePhysicalMemory / 1MB)
		"Free disk space(GB)      " = "{0:N1}" -f ($disk.FreeSpace / 1GB)
	}
}

function Get-CompletionStatus {
	param(
		[string[]]
		$Statuses
	)

	$totalCount = $Statuses.Count
	$status = @{
		TotalCount = $totalCount
	}
	foreach ($value in $StatusValues) {
		$count = ($Statuses | Where-Object { $_ -eq $value }).Count
		$status[$value] = @{
			Count = $count
			Percent = (100 * ($count / $totalCount)).ToString("0.00", [cultureinfo]::InvariantCulture)
		}
	}

	return $status
}

function Get-OverallComplianceCSS {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		$completionStatus
	)

	$css = ""
	$percent = $completionStatus['True'].Percent / 1

	if ($percent -gt 50) {
		$degree = 180 + ((($percent-50)/1) * 3.6)
		$css += ".donut-chart.chart .slice.one {clip: rect(0 200px 100px 0); -webkit-transform: rotate(90deg); transform: rotate(90deg);}"
		$css += ".donut-chart.chart .slice.two {clip: rect(0 100px 200px 0); -webkit-transform: rotate($($degree)deg); transform: rotate($($degree)deg);}"
	}
	else {
		$degree = 90 + ($percent * 3.6)
		$css += ".donut-chart.chart .slice.one {clip: rect(0 200px 100px 0); -webkit-transform: rotate($($degree)deg); transform: rotate($($degree)deg);}"
		$css += ".donut-chart.chart .slice.two {clip: rect(0 100px 200px 0); -webkit-transform: rotate(0deg); transform: rotate(0deg);}"
	}

	$css += ".donut-chart.chart .chart-center span:after {content: `"$percent %`";}"

	return $css
}

function Select-ConfigAudit {
	param(
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[Alias('AuditInfos')]
		[array]
		$ConfigAudits,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Subsections
	)

	process {
		$results = @()
		if ($null -ne $ConfigAudits) {
			$results += $ConfigAudits
		}
		if ($null -ne $Subsections) {
			foreach ($subsection in $Subsections) {
				$results += $subsection | Select-ConfigAudit
			}
		}
		return $results
	}
}

function Get-THCHtmlReport {
	<#
	.Synopsis
		Generates an audit report in an html file.
	.Description
		The `Get-THCHtmlReport` cmdlet collects data from the current machine to generate an audit report.
	.Parameter Path
		Specifies the relative path to the file in which the report will be stored.
	.Example
		C:\PS> Get-THCHtmlReport -Path "MyReport.html"
	#>

	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[Parameter(Mandatory = $false)]
		[hashtable]
		$HostInformation = (Get-THCHostInformation),

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ModuleName,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$AuditorVersion,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$BasedOn,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Sections,

		[switch] $DarkMode,

		[switch] $ComplianceStatus
	)

	process {
		$allConfigResults = foreach ($section in $Sections) { $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status' }
		$completionStatus = Get-CompletionStatus $allConfigResults

		# HTML <head> markup
		$head = htmlElement 'head' @{} {
			htmlElement 'meta' @{ charset = 'UTF-8'} { }
			htmlElement 'meta' @{ name = 'viewport'; content = 'width=device-width, initial-scale=1.0' } { }
			htmlElement 'meta' @{ 'http-equiv' = 'X-UA-Compatible'; content = 'ie=edge'} { }
			htmlElement 'title' @{} { "$Title [$(Get-Date)]" }
			htmlElement 'style' @{} {
				$cssEnding = ''
				if ($DarkMode) { $cssEnding = '.dark' }
				$cssPath = $ScriptRoot | Join-path -ChildPath "/report$($cssEnding).css"
				Get-Content $cssPath
				Get-OverallComplianceCSS $completionStatus
			}
		}

		$body = htmlElement 'body' @{} {
			# Header
			htmlElement 'div' @{ class = 'header content'} {
				htmlElement 'img' @{src = $Settings.Logo; width="300"; height="118"} {}
				htmlElement 'h1' @{} { $Title }
				htmlElement 'p' @{} {
					"Generated by the <i>$ModuleName</i> Module Version <i>$AuditorVersion</i> by TEAL Technology Consulting GmbH based on the Audit-Test-Automation by FB Pro GmbH."
				}
				htmlElement 'p' @{} {
					"Based on:"
					htmlElement 'ul' @{} {
						foreach ($item in $BasedOn) {
							htmlElement 'li' @{} { $item }
						}
					}
				}
			}
			# Main section
			htmlElement 'div' @{ class = 'main content' } {
				htmlElement 'div' @{ class = 'host-information' } {
					htmlElement 'p' @{} { "This report was generated at $((Get-Date)) on $($HostInformation.Hostname) with THCHtmlReport version $ModuleVersion." }
					# Host information
					htmlElement 'table' @{} {
						htmlElement 'tbody' @{} {
							foreach ($hostDatum in $HostInformation.GetEnumerator()) {
								htmlElement 'tr' @{} {
									htmlElement 'th' @{ scope = 'row' } { $hostDatum.Name }
									htmlElement 'td' @{} { $hostDatum.Value }
								}
							}
						}
					}
					# Show compliance status
					if ($ComplianceStatus) {
						$sliceColorClass = Get-HtmlClassFromStatus 'True'
						htmlElement 'div' @{ class = 'card'} {
							htmlElement 'h2' @{} { 'Compliance status' }
							htmlElement 'div' @{ class = 'donut-chart chart'} {
								htmlElement 'div' @{ class = "slice one $sliceColorClass" } { }
								htmlElement 'div' @{ class = "slice two $sliceColorClass" } { }
								htmlElement 'div' @{ class = 'chart-center' } { htmlElement 'span' @{} { } }
							}
						}
					}
					# Summary
					htmlElement 'h1' @{ style = 'clear:both; padding-top: 50px;' } { 'Summary' }
					htmlElement 'p' @{} {
						'A total of {0} tests have been run. {1} resulted in false. {2} resulted in warning.' -f @(
							$completionStatus.TotalCount
							$completionStatus['False'].Count
							$completionStatus['Warning'].Count
						)
					}
					# Status percentage gauge
					htmlElement 'div' @{ class = 'gauge' } {
						foreach ($value in $StatusValues) {
							$count = $completionStatus[$value].Count
							$htmlClass = Get-HtmlClassFromStatus $value
							$percent = $completionStatus[$value].Percent

							htmlElement 'div' @{
								class = "gauge-meter $htmlClass"
								style = "width: $($percent)%"
								title = "$value $count test(s), $($percent)%"
							} { }
						}
					}
					htmlElement 'ol' @{ class = 'gauge-info' } {
						foreach ($value in $StatusValues) {
							$count = $completionStatus[$value].Count
							$htmlClass = Get-HtmlClassFromStatus $value
							$percent = $completionStatus[$value].Percent

							htmlElement 'li' @{ class = 'gauge-info-item' } {
								htmlElement 'span' @{ class = "auditstatus $htmlClass" } { $value }
								" $count test(s) &#x2259; $($percent)%"
							}
						}

					}
					# Table of Contents
					htmlElement 'h1' @{ id = 'toc' } { 'Table of Contents' }
					htmlElement 'p' @{} { 'Click the link(s) below for quick access to a report section.' }
					htmlElement 'ul' @{} {
						foreach ($section in $Sections) { $section | Get-HtmlToc  }
					}
					# Report Sections Sections
					foreach ($section in $Sections) { $section | Get-HtmlReportSection }
				}
			}
			htmlElement 'script' @{ type = 'text/javascript' } { @"

function collapseHandler(e) {
	var targetSection = e.target.parentElement.parentElement;
	if (targetSection.classList.toggle('collapsed')) {
		e.target.innerText = '+';
	} else {
		e.target.innerText = '-';
	}
}

var collapseButtons = document.getElementsByClassName("collapseButton");
for (var i = 0; i < collapseButtons.length; i++) {
    collapseButtons[i].addEventListener('click', collapseHandler);
}
"@
			}
		}

		$html = "<!DOCTYPE html><html lang=`"en`">$($head)$($body)</body></html> "
		New-Item $path -type File
		$html | Out-File $Path -Encoding utf8
	}
}