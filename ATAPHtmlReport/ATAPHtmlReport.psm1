﻿<#
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
$ModuleVersion = (Import-PowerShellDataFile -Path "$ScriptRoot\ATAPHtmlReport.psd1").ModuleVersion

$StatusValues = 'True', 'False', 'Warning', 'None', 'Error'
$AuditProperties = @{ Name = 'Id' }, @{ Name = 'Task' }, @{ Name = 'Message' }, @{ Name = 'Status' }

function Join-ATAPReportStatus {
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
		return Join-ATAPReportStatus $allStatuses
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
			# if ($null -ne $ConfigAudits){
			# 	htmlElement 'p' @{} {$ConfigAudits.Count + ' tests have been executed in this section'}
			# }
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

function Get-ATAPHostInformation {
	$unixOS = [System.Environment]::OSVersion.Platform -eq 'Unix' # returns 'Unix' on Linux and MacOS and 'Win32NT' on Windows, PS v6+ has builtin environment variable for this
	if ($unixOS) {
		return [ordered]@{
			"Hostname"                  = hostname
			"Operating System"          = (Get-Content /etc/os-release | Select-String -Pattern '^PRETTY_NAME=\"(.*)\"$').Matches.Groups[1].Value
			"Installation Language"     = (($(locale) | Where-Object {$_ -match "LANG="}) -split '=')[1]
			"Kernel Version"            = uname -r
			"Free physical memory (GB)" = "{0:N1}" -f ((-split (Get-Content /proc/meminfo | Where-Object {$_ -match 'MemFree:'}))[1] / 1MB)
			"Free disk space (GB)"		= "{0:N1}" -f ((Get-PSDrive | Where-Object {$_.Name -eq '/'}).Free / 1GB)
			"Domain role"				= $role			
		}
	} else {
		$infos = Get-CimInstance Win32_OperatingSystem
		$disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"
		$role = Switch ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole) {
			"0"	{"Standalone Workstation"}
			"1"	{"Member Workstation"}
			"2"	{"Standalone Server"}
			"3"	{"Member Server"}
			"4"	{"Backup Domain Controller"}
			"5"	{"Primary Domain Controller"}
		}
		return [ordered]@{
			"Hostname"                  = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
			"Operating System"          = $infos.Caption
			"Installation Language"     = ((Get-UICulture).DisplayName)
			"Build Number"              = $infos.BuildNumber
			"Free physical memory (GB)" = "{0:N3}" -f ($infos.FreePhysicalMemory / 1MB)
			"Free disk space (GB)"		= "{0:N1}" -f ($disk.FreeSpace / 1GB)
			"Domain role"				= $role
		}
	}
}

function Get-CompletionStatus {
	param(
		[string[]]
		$Statuses,

		[array]$Sections
	)

	$totalCount = $Statuses.Count
	$status = @{
		TotalCount = $totalCount
	}

	#Total completion status
	foreach ($value in $StatusValues) {
		$count = ($Statuses | Where-Object { $_ -eq $value }).Count
		$status[$value] = @{
			Count = $count
			Percent = (100 * ($count / $totalCount)).ToString("0.00", [cultureinfo]::InvariantCulture)
		}
	}

	#Section Total Count
	$sectionTotalCountHash = @{}
	foreach ($section in $Sections) {
		$sectionResult = $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status'
		$totalSectionCount = 0
		foreach ($value in $StatusValues) {
			$count = ($sectionResult | Where-Object { $_ -eq $value }).Count
			$totalSectionCount += $count
		}
		$sectionTotalCountHash.Add($section.Title, $totalSectionCount)
	}
	#Counts the completion status for each section and each value. Also calculates the percentage.
	$sectionCountHash = @{}
	foreach ($section in $Sections) {
		$sectionResult = $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status'
		foreach ($value in $StatusValues) {
			$count = ($sectionResult | Where-Object { $_ -eq $value }).Count
			$sectionCountHash.Add($section.Title + $value + "Count", $count)
			$percent = (100 * ($count / $sectionTotalCountHash[$section.Title])).ToString("0.00", [cultureinfo]::InvariantCulture)
			$sectionCountHash.Add($section.Title + $value + "Percent", $percent)
		}
	}
	return $status, $sectionTotalCountHash, $sectionCountHash
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
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[Parameter(Mandatory = $false)]
		[hashtable]
		$HostInformation = (Get-ATAPHostInformation),

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

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[RSFullReport[]]
		$RSReport,

		[switch] $DarkMode,

		[switch] $ComplianceStatus
	)

	process {
		$allConfigResults = foreach ($section in $Sections) { $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status' }
		$completionStatus, $sectionTotalCountHash, $sectionCountHash = Get-CompletionStatus -Statuses $allConfigResults -sections $Sections

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
			htmlElement 'script' @{} {
				$jsPath = $ScriptRoot | Join-path -ChildPath "/report.js"
				Get-Content $jsPath
			}
		}

		$body = htmlElement 'body' @{onload="startConditions()"} {
			# Header
			htmlElement 'div' @{ class = 'header content'} {
				$Settings.LogoSvg
				htmlElement 'h1' @{} { $Title }
				htmlElement 'p' @{} {
					"Generated by the <i>$ModuleName</i> Module Version <i>$AuditorVersion</i> by FB Pro GmbH. Get it in the <a href=`"$($Settings.PackageLink)`">Audit Test Automation Package</a>. Are you seeing a lot of red sections? Check out our <a href=`"$($Settings.SolutionsLink)`">hardening solutions</a>."
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
					htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with TAPHtmlReport version $ModuleVersion." }
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
					htmlElement 'div' @{id='navigationButtons'} {
						htmlElement 'button' @{type='button'; id='summaryBtn'; onclick="clickSummaryBtn()"}{"Summary"}
						htmlElement 'button' @{type='button'; id='riskScoreBtn'; onclick="clickRiskScoreBtn()"}{"Risk Score"}
					}
					#This div hides/reveals the whole summary section
					htmlElement 'div' @{id='summary'}{

						# Summary
						htmlElement 'h1' @{ style = 'clear:both; padding-top: 50px;' } { 'Summary' }
						htmlElement 'p' @{} {
							'A total of {0} tests have been executed.' -f @(
								$completionStatus.TotalCount
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
						# Sections
						foreach ($section in $Sections) {
							htmlElement 'h2' @{ style = 'clear:both; margin-top: 0;' } { $section.Title }
							htmlElement 'p' @{} {
								'A total of {0} tests have been executed in section {1}.' -f @(
									$sectionTotalCountHash[$section.Title]
									$section.Title
								)
							}

							# Status percentage gauge for sections
							htmlElement 'div' @{ class = 'gauge' } {
								foreach ($value in $StatusValues) {
									$count = $sectionCountHash[$section.Title + $value + "Count"]
									$htmlClass = Get-HtmlClassFromStatus $value
									$percent = $sectionCountHash[$section.Title + $value + "Percent"]

									htmlElement 'div' @{
										class = "gauge-meter $htmlClass"
										style = "width: $($percent)%"
										title = "$value $count test(s), $($percent)%"
									} { }
								}
							}
							htmlElement 'ol' @{ class = 'gauge-info' } {
								foreach ($value in $StatusValues) {
									$count = $sectionCountHash[$section.Title + $value + "Count"]
									$htmlClass = Get-HtmlClassFromStatus $value
									$percent = $sectionCountHash[$section.Title + $value + "Percent"]

									htmlElement 'li' @{ class = 'gauge-info-item' } {
										htmlElement 'span' @{ class = "auditstatus $htmlClass" } { $value }
										" $count test(s) &#x2259; $($percent)%"
									}
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

					htmlElement 'p' @{id = 'riskScore'} {"Hier steht der RiskScore"}
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

		$head = "			
		<head>
			<title>A Meaningful Page Title</title>
			<style>
				body{
					font-family: Cambria, Georgia, serif;
				}
				.header {
					background-color: #c6c9cc;
				}
				.green{
					height: 160px; width: 160px;background-color:#33cca6;
				}
				.red{
					height: 160px; width: 160px;background-color:#cc0000;
				}
				td{
					text-align: center;
				}
				table{
					margin-left: auto;
    				margin-right: auto;
				}
				.riskMatrix{
					margin: auto;
					width: 50%;
				}
				h1{
					text-align: center;
					margin-bottom: 25px;
				}
				h1 p{
					text-align: center;
				}
				td {
					border: 1px solid black;
				}
			</style>
		</head>
		"


		#Different Risks:
		#QualityQuantity
		#First word is risk of Quality
		#Second word is risk of Quantity

		#LowLow
		#LowCritical
		#CriticalLow
		#CriticalCritical

		$risk = "CriticalLow"
		
		$html_RiskScore =
		htmlElement 'body' @{} {
			htmlElement 'div' @{ class = 'header'} {
				$Settings.LogoSvg
				htmlElement 'h1' @{} { $Title }
				htmlElement 'p' @{} {
					"Generated by the <i>$ModuleName</i> Module Version <i>$AuditorVersion</i> by FB Pro GmbH. Get it in the <a href=`"$($Settings.PackageLink)`">Audit Test Automation Package</a>. Are you seeing a lot of red sections? Check out our <a href=`"$($Settings.SolutionsLink)`">hardening solutions</a>."
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
			htmlElement 'h1' @{} {'Risk Score'}
			htmlElement 'h1' @{} {
				'Your System has following condition: &nbsp;&nbsp;&nbsp;'
				if($risk.Contains('Critical')){
					htmlElement 'p' @{style="color:#cc0000;"} {"Critical Risk!"}
				}
				else{
					htmlElement 'p' @{style="color:#33cca6;"} {"Low Risk!"}
				}
			}
			htmlElement 'div' @{class = 'riskMatrix'} {
				htmlElement 'table' @{style="border-collapse: collapse;"} {
					htmlElement 'tbody' @{} {
						htmlElement 'tr' @{} {
							htmlElement 'td' @{rowspan=3; style="font-weight:bold;"} {'Quality'}
							htmlElement 'td' @{} {'Critical'}
							htmlElement 'td' @{class='red'} {
								if($risk -eq "LowCritical"){
									'Critical Risk'
								}
							}
							htmlElement 'td' @{class='red'} {
								if($risk -eq "CriticalCritical"){
									'Critical Risk'
								}
							}
						}
						htmlElement 'tr' @{} {
							htmlElement 'td' @{} {'Low'}
							htmlElement 'td' @{class='green'} {
								if($risk -eq "LowLow"){
									'Low Risk'
								}
							}
							htmlElement 'td' @{class='red'} {
								if($risk -eq "CriticalLow"){
									'Critical Risk'
								}
							}
						}
						htmlElement 'tr' @{} {
							htmlElement 'td' @{} {}
							htmlElement 'td' @{} {'Low'}
							htmlElement 'td' @{} {'Critical'}
						}
						htmlElement 'tr' @{} {
							htmlElement 'td' @{} {}
							htmlElement 'td' @{colspan=3; style="text-align:center; font-weight:bold;"} {'Quantity'}
						}
					}
				}
				htmlElement 'table'@{style="width:100%; margin-top: 80px; border-collapse: collapse;"}{
					htmlElement 'tbody' @{}{
						htmlElement 'tr' @{} {
							htmlElement 'td' @{style="font-weight: bold;"} {'Issue'}
							htmlElement 'td' @{style="font-weight: bold;"} {'Description'}
							htmlElement 'td' @{style="font-weight: bold;"} {'Type'}
						}
						htmlElement 'tr' @{} {
							htmlElement 'td' @{} {'Issue01'}
							htmlElement 'td' @{} {'SMBv1 not configured!'}
							htmlElement 'td' @{} {'Quantity'}
						}
						htmlElement 'tr' @{} {
							htmlElement 'td' @{} {'Issue02'}
							htmlElement 'td' @{} {'Driver Server not enabled!'}
							htmlElement 'td' @{} {'Number of Successes: ' + $RSReport.RSSeverityReport.ResultTable.Success
						'Number of Failed: ' + $RSReport.RSSeverityReport.ResultTable.Failed
					'Endresult of Quality: ' + $RSReport.RSSeverityReport.Endresult
				'Test for AuditInfo: ' + $RSReport.RSSeverityReport.TestTable}
							}
						}
					}
				}
			}
		
		$head = $head + " " + $html_RiskScore
		
		if(Test-Path -Path $path){
			Write-Warning "$path already exists. $path will be overridden!"
		}
		
		
		#Create Report Path		
		$reportName = [System.IO.Path]::GetFileNameWithoutExtension($path) 
		$directoryPath = Split-Path -Path $path
		New-Item -Path $directoryPath"\"$reportName -ItemType Directory
		$directoryPath = $directoryPath+"\"+$reportName

		#Create Report file
		New-Item $path -ItemType File -Force
		$html | Out-File -FilePath $path -Encoding utf8
		#Move Report file to newly created directory
		Move-Item -Path $path -Destination $directoryPath

		
		#Create RiskScore file
		New-Item $directoryPath -Name "$($reportName)_RiskScore.html" -ItemType File -Value $head
	}
}