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
			Default { $_ }
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
				htmlElement 'a' @{ href = '#toc'; class = 'sectionAction' } {
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
		return @{
			"Hostname"                  = hostname
			"Domain role"               = $role
			"Operating System"          = (Get-Content /etc/os-release | Select-String -Pattern '^PRETTY_NAME=\"(.*)\"$').Matches.Groups[1].Value
			"Installation Language"     = (($(locale) | Where-Object { $_ -match "LANG=" }) -split '=')[1]
			"Kernel Version"            = uname -r
			"Free physical memory (GB)" = "{0:N1}" -f (( -split (Get-Content /proc/meminfo | Where-Object { $_ -match 'MemFree:' }))[1] / 1MB)
			"Free disk space (GB)"      = "{0:N1}" -f ((Get-PSDrive | Where-Object { $_.Name -eq '/' }).Free / 1GB)
		}
	}
 else {
		$infos = Get-CimInstance Win32_OperatingSystem
		$disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"
		$role = Switch ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole) {
			"0"	{ "Standalone Workstation" }
			"1"	{ "Member Workstation" }
			"2"	{ "Standalone Server" }
			"3"	{ "Member Server" }
			"4"	{ "Backup Domain Controller" }
			"5"	{ "Primary Domain Controller" }
		}
		$freeMemory = ($infos.FreePhysicalMemory /1024) / 1024;
		$totalMemory = ($infos.TotalVirtualMemorySize /1024) /1024;
		
		return @{
			"Hostname"                  = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
			"Domain role"               = $role
			"Operating System"          = $infos.Caption
			"Build Number"              = $infos.BuildNumber
			"Installation Language"     = ((Get-UICulture).DisplayName)
			"Free disk space (GB)"      = "{0:N1}" -f ($disk.FreeSpace / 1GB)
			"Free physical memory (GB)" = "{0:N3}" -f "$([math]::Round(($freeMemory/$totalMemory)*100,1))%  ($([math]::Round($freeMemory,1)) GB / $([math]::Round($totalMemory,1)) GB)" 
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
			Count   = $count
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
		$degree = 180 + ((($percent - 50) / 1) * 3.6)
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
			htmlElement 'meta' @{ charset = 'UTF-8' } { }
			htmlElement 'meta' @{ name = 'viewport'; content = 'width=device-width, initial-scale=1.0' } { }
			htmlElement 'meta' @{ 'http-equiv' = 'X-UA-Compatible'; content = 'ie=edge' } { }
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
		$body = htmlElement 'body' @{onload = "startConditions()" } {
			# Header
			htmlElement 'div' @{ class = 'header content' } {
				$Settings.LogoSvg
				htmlElement 'h1' @{} { $Title }
				# htmlElement 'p' @{} {
				# 	"Generated by the <i>$ModuleName</i> Module Version <i>$AuditorVersion</i> by FB Pro GmbH. Get it in the <a href=`"$($Settings.PackageLink)`">Audit Test Automation Package</a>. Are you seeing a lot of red sections? Check out our <a href=`"$($Settings.SolutionsLink)`">hardening solutions</a>."
				# }
				# htmlElement 'p' @{} {
				# 	"Based on:"
				# 	htmlElement 'ul' @{} {
				# 		foreach ($item in $BasedOn) {
				# 			htmlElement 'li' @{} { $item }
				# 		}
				# 	}
				# 	htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
				# }
			}
			# Main section
			htmlElement 'div' @{ class = 'main content' } {
				htmlElement 'div' @{ class = 'host-information' } {
					# htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
					# # Host information
					# htmlElement 'table' @{} {
					# 	htmlElement 'tbody' @{} {
					# 		foreach ($hostDatum in $HostInformation.GetEnumerator()) {
					# 			htmlElement 'tr' @{} {
					# 				htmlElement 'th' @{ scope = 'row' } { $hostDatum.Name }
					# 				htmlElement 'td' @{} { $hostDatum.Value }
					# 			}
					# 		}

					# 	}
					# }
					# Show compliance status
					if ($ComplianceStatus) {
						$sliceColorClass = Get-HtmlClassFromStatus 'True'
						htmlElement 'div' @{ class = 'card' } {
							htmlElement 'h2' @{} { 'Compliance status' }
							htmlElement 'div' @{ class = 'donut-chart chart' } {
								htmlElement 'div' @{ class = "slice one $sliceColorClass" } { }
								htmlElement 'div' @{ class = "slice two $sliceColorClass" } { }
								htmlElement 'div' @{ class = 'chart-center' } { htmlElement 'span' @{} { } }
							}
						}
					}

					###  Risk Checks ###
					# Quantity
					$TotalAmountOfRules = $completionStatus.TotalCount;
					$AmountOfCompliantRules = 0;
					$AmountOfNonCompliantRules = 0;
					foreach ($value in $StatusValues) {
						if($value -eq 'True'){
							$AmountOfCompliantRules = $completionStatus[$value].Count
						}
						if($value -eq 'False'){
							$AmountOfNonCompliantRules = $completionStatus[$value].Count
						}
					}

					if($Title -match "Win"){
						# percentage of compliance quantity
						$QuantityCompliance = [math]::round(($AmountOfCompliantRules / $TotalAmountOfRules) * 100,2);	
	
						# Variables, which will be evaluated in report.js
						htmlElement 'div' @{id="AmountOfNonCompliantRules"} {"$($AmountOfNonCompliantRules)"}
						htmlElement 'div' @{id="AmountOfCompliantRules"} {"$($AmountOfCompliantRules)"}
						htmlElement 'div' @{id="TotalAmountOfRules"} {"$($TotalAmountOfRules)"}
						htmlElement 'div' @{id="QuantityCompliance"} {"$($QuantityCompliance)"}
	
						# Severity
						htmlElement 'div' @{id="TotalAmountOfSeverityRules"} {"$($RSReport.RSSeverityReport.AuditInfos.Length)"}
						$AmountOfFailedSeverityRules = 0;
						foreach($rule in $RSReport.RSSeverityReport.AuditInfos){
							if($rule.Status -ne "True"){
								$AmountOfFailedSeverityRules ++;
							}
						}
						htmlElement 'div' @{id="AmountOfFailedSeverityRules"} {"$($AmountOfFailedSeverityRules)"}
					}


					htmlElement 'div' @{id = 'navigationButtons' } {
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'summaryBtn'; onclick = "clickButton('1')" } { "Benchmark Compliance" }
						if($Title -match "Win"){
							htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'riskScoreBtn'; onclick = "clickButton('2')" } { "Risk Score" }
						}
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'settingsOverviewBtn'; onclick = "clickButton('4')" } { "Settings Overview" }
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'referenceBtn'; onclick = "clickButton('3')" } { "About Us" }
					}

					htmlElement 'div' @{class = 'tabContent'; id = 'settingsOverview'} {

						# Table of Contents
						htmlElement 'h1' @{ id = 'toc' } { 'Settings Overview' }
						htmlElement 'p' @{} { 'Click the link(s) below for quick access to a report section.' }
						htmlElement 'ul' @{} {
							foreach ($section in $Sections) { $section | Get-HtmlToc }
						}
						# Report Sections Sections
						foreach ($section in $Sections) { $section | Get-HtmlReportSection }
					}


					#This div hides/reveals the whole summary section
					htmlElement 'div' @{class = 'tabContent'; id = 'summary' } {
						# htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
						# Host information
						htmlElement 'h1' @{} { 'Benchmark Compliance' }

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
							htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
						}
						
						htmlElement 'div' @{id="systemData"} {
							htmlElement 'h2' @{} {'System information'}
							htmlElement 'table' @{id='summaryTable'} {
								htmlElement 'tbody' @{} {
									$hostInformation = Get-ATAPHostInformation;
									#Hostname
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[4] }
										htmlElement 'td' @{} { $($hostInformation.Values)[4] }
									}
									#Domain Role
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[2] }
										htmlElement 'td' @{} { $($hostInformation.Values)[2] }
									}
									#Operating System
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[3] }
										htmlElement 'td' @{} { $($hostInformation.Values)[3] }
									}
									#Build Number
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[5] }
										htmlElement 'td' @{} { $($hostInformation.Values)[5] }
									}
									#Installation Language
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[1] }
										htmlElement 'td' @{} { $($hostInformation.Values)[1] }
									}
									#Free disk space (GB)
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[0] }
										htmlElement 'td' @{} { $($hostInformation.Values)[0] }
									}
									#Free physical memory (GB)
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[6] }
										htmlElement 'td' @{} { $($hostInformation.Values)[6] }
									}
								}
							}
						}
						htmlElement 'div' @{id='riskMatrixSummaryArea'}{
							if($Title -match "Win"){
								htmlElement 'h2' @{id = 'CurrentRiskScore'} {"Current Risk Score on tested System: "}
								htmlElement 'h3' @{} {'For further information, please head to the tab "Risk Score".'}
								htmlElement 'div' @{id ='riskMatrixSummary'}{
									htmlElement 'div' @{id='dotSummaryTab'}{}
									htmlElement 'div' @{id ='severity'} {
										htmlElement 'p' @{id = 'severityArea'}{'Severity'}
									}
									htmlElement 'div' @{id ='quantity'} {
										htmlElement 'p' @{id = 'quantityArea'}{'Quantity'}
									}
									htmlElement 'div' @{id ='severityCritical'}{"Critical"}
									htmlElement 'div' @{id ='severityHigh'}{"High"}
									htmlElement 'div' @{id ='severityMedium'}{"Medium"}
									htmlElement 'div' @{id ='severityLow'}{"Low"}
		
									htmlElement 'div' @{id ='quantityCritical'}{"Critical"}
									htmlElement 'div' @{id ='quantityHigh'}{"High"}
									htmlElement 'div' @{id ='quantityMedium'}{"Medium"}
									htmlElement 'div' @{id ='quantityLow'}{"Low"}
		
									#colored areas
									htmlElement 'div' @{id ='critical_low'}{}
									htmlElement 'div' @{id ='high_low'}{}
									htmlElement 'div' @{id ='medium_low'}{}
									htmlElement 'div' @{id ='low_low'}{}
		
									htmlElement 'div' @{id ='critical_medium'}{}
									htmlElement 'div' @{id ='high_medium'}{}
									htmlElement 'div' @{id ='medium_medium'}{}
									htmlElement 'div' @{id ='low_medium'}{}
		
									htmlElement 'div' @{id ='critical_high'}{}
									htmlElement 'div' @{id ='high_high'}{}
									htmlElement 'div' @{id ='medium_high'}{}
									htmlElement 'div' @{id ='low_high'}{}
		
									htmlElement 'div' @{id ='critical_critical'}{}
									htmlElement 'div' @{id ='high_critical'}{}
									htmlElement 'div' @{id ='medium_critical'}{}
									htmlElement 'div' @{id ='low_critical'}{}
								}
							}
							else{
								htmlElement 'h2' @{id = 'CurrentRiskScore'} {"Current Risk Score on tested System: N/A"}
								htmlElement 'h3' @{} {'For further information, consider making a report on a Windows OS-System.'}
								htmlElement 'div' @{id ='riskMatrixSummary'}{
									htmlElement 'div' @{id ='severity'} {
										htmlElement 'p' @{id = 'severityArea'}{'Severity'}
									}
									htmlElement 'div' @{id ='quantity'} {
										htmlElement 'p' @{id = 'quantityArea'}{'Quantity'}
									}
									htmlElement 'div' @{id ='severityCritical'}{"Critical"}
									htmlElement 'div' @{id ='severityHigh'}{"High"}
									htmlElement 'div' @{id ='severityMedium'}{"Medium"}
									htmlElement 'div' @{id ='severityLow'}{"Low"}
		
									htmlElement 'div' @{id ='quantityCritical'}{"Critical"}
									htmlElement 'div' @{id ='quantityHigh'}{"High"}
									htmlElement 'div' @{id ='quantityMedium'}{"Medium"}
									htmlElement 'div' @{id ='quantityLow'}{"Low"}
		
									#colored areas
									htmlElement 'div' @{id ='critical_low'}{}
									htmlElement 'div' @{id ='high_low'}{}
									htmlElement 'div' @{id ='medium_low'}{}
									htmlElement 'div' @{id ='low_low'}{}
		
									htmlElement 'div' @{id ='critical_medium'}{}
									htmlElement 'div' @{id ='high_medium'}{}
									htmlElement 'div' @{id ='medium_medium'}{}
									htmlElement 'div' @{id ='low_medium'}{}
		
									htmlElement 'div' @{id ='critical_high'}{}
									htmlElement 'div' @{id ='high_high'}{}
									htmlElement 'div' @{id ='medium_high'}{}
									htmlElement 'div' @{id ='low_high'}{}
		
									htmlElement 'div' @{id ='critical_critical'}{}
									htmlElement 'div' @{id ='high_critical'}{}
									htmlElement 'div' @{id ='medium_critical'}{}
									htmlElement 'div' @{id ='low_critical'}{}
								}
							}
						}
						# Benchmark compliance
						htmlElement 'h1' @{ style = 'clear:both;' } {}
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


						# # Table of Contents
						# htmlElement 'h1' @{ id = 'toc' } { 'Table of Contents' }
						# htmlElement 'p' @{} { 'Click the link(s) below for quick access to a report section.' }
						# htmlElement 'ul' @{} {
						# 	foreach ($section in $Sections) { $section | Get-HtmlToc }
						# }
						# # Report Sections Sections
						# foreach ($section in $Sections) { $section | Get-HtmlReportSection }
					}


					
					htmlElement 'div' @{class = 'tabContent'; id = 'riskScore' } {
						htmlElement 'h1'@{} {"Risk Score"}
						htmlElement 'p'@{} {'To get a quick overview of how risky the tested system is, the Risk Score is used. This is made up of the areas "Severity" and "Quantity". The higher risk is used as the overall risk.'}
						htmlElement 'h2' @{id = 'CurrentRiskScoreRS'} {"Current Risk Score on tested System: "}

						htmlElement 'div' @{id ='riskMatrixContainer'}{
							htmlElement 'div' @{id='dotRiskScoreTab'}{}
							htmlElement 'div' @{id ='severity'} {
								htmlElement 'p' @{id = 'severityArea'}{'Severity'}
							}
							htmlElement 'div' @{id ='quantity'} {
								htmlElement 'p' @{id = 'quantityArea'}{'Quantity'}
							}
							htmlElement 'div' @{id ='severityCritical'}{"Critical"}
							htmlElement 'div' @{id ='severityHigh'}{"High"}
							htmlElement 'div' @{id ='severityMedium'}{"Medium"}
							htmlElement 'div' @{id ='severityLow'}{"Low"}

							htmlElement 'div' @{id ='quantityCritical'}{"Critical"}
							htmlElement 'div' @{id ='quantityHigh'}{"High"}
							htmlElement 'div' @{id ='quantityMedium'}{"Medium"}
							htmlElement 'div' @{id ='quantityLow'}{"Low"}

							#colored areas
							htmlElement 'div' @{id ='critical_low'}{}
							htmlElement 'div' @{id ='high_low'}{}
							htmlElement 'div' @{id ='medium_low'}{}
							htmlElement 'div' @{id ='low_low'}{}

							htmlElement 'div' @{id ='critical_medium'}{}
							htmlElement 'div' @{id ='high_medium'}{}
							htmlElement 'div' @{id ='medium_medium'}{}
							htmlElement 'div' @{id ='low_medium'}{}

							htmlElement 'div' @{id ='critical_high'}{}
							htmlElement 'div' @{id ='high_high'}{}
							htmlElement 'div' @{id ='medium_high'}{}
							htmlElement 'div' @{id ='low_high'}{}

							htmlElement 'div' @{id ='critical_critical'}{}
							htmlElement 'div' @{id ='high_critical'}{}
							htmlElement 'div' @{id ='medium_critical'}{}
							htmlElement 'div' @{id ='low_critical'}{}
						}

						htmlElement 'div' @{id='calculationTables'} {
							htmlElement 'h3' @{class = 'calculationTablesText'} {"Risk Score Calculation"}
							htmlElement 'p' @{class = 'calculationTablesText'} {"The calculation of the Risk Score is based on the set of compliant rules at the quantity level and also at the severity level."}
							htmlElement 'table' @{id='quantityTable'}{
								htmlElement 'tr' @{}{
									htmlElement 'th' @{}{'Compliance to Benchmarks (Quantity)'}
									htmlElement 'th' @{}{'Risk Assessment'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'85% < X'}
									htmlElement 'td' @{}{'Low'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'70% < X < 85%'}
									htmlElement 'td' @{}{'Medium'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'55% < X < 70%'}
									htmlElement 'td' @{}{'High'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'X < 55%'}
									htmlElement 'td' @{}{'Critical'}
								}
							}
	
							htmlElement 'table' @{id='severityTable'}{
								htmlElement 'tr' @{}{
									htmlElement 'th' @{}{'Compliance to Benchmarks (Severity)'}
									htmlElement 'th' @{}{'Risk Assessment'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'X = 0'}
									htmlElement 'td' @{}{'Low'}
								}
								# htmlElement 'tr' @{}{
								# 	htmlElement 'td' @{}{'70% < X < 85%'}
								# 	htmlElement 'td' @{}{'Medium'}
								# }
								# htmlElement 'tr' @{}{
								# 	htmlElement 'td' @{}{'55% < X < 70%'}
								# 	htmlElement 'td' @{}{'High'}
								# }
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'X > 1'}
									htmlElement 'td' @{}{'Critical'}
								}
							}
						}


						htmlElement 'div' @{id ="severityCompliance"} {
							htmlElement 'p' @{id="complianceStatus"}{'Severity Compliance'}
							htmlElement 'span' @{class="sectionAction collapseButton"; id="severityComplianceCollapse"} {"-"}
							htmlElement 'table' @{id = 'severityDetails'}{
								htmlElement 'tr' @{}{
									htmlElement 'th' @{}{'Id'}
									htmlElement 'th' @{}{'Task'}
									htmlElement 'th' @{}{'Status'}
								}
								foreach($info in $RSReport.RSSeverityReport.AuditInfos){
									htmlElement 'tr' @{}{
										htmlElement 'td' @{} {"$($info.Id)"}
										htmlElement 'td' @{} {"$($info.Task)"}
										htmlElement 'td' @{} {
											if($info.Status -eq 'False'){
												htmlElement 'span' @{class="severityResultFalse"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'True'){
												htmlElement 'span' @{class="severityResultTrue"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'None'){
												htmlElement 'span' @{class="severityResultNone"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'Warning'){
												htmlElement 'span' @{class="severityResultWarning"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'Error'){
												htmlElement 'span' @{class="severityResultError"}{
													"$($info.Status)"
												}
											}
										}
									}
								}
							}
						}

						


						# htmlElement 'h2' @{} {'Number of Successes: ' + $RSReport.RSSeverityReport.ResultTable.Success }
						# htmlElement 'h2' @{} {'Number of Failed: ' + $RSReport.RSSeverityReport.ResultTable.Failed }
						# htmlElement 'h2' @{} {'Endresult of Quality: ' + $RSReport.RSSeverityReport.Endresult }

						# 'Test for AuditInfo: ' + $RSReport.RSSeverityReport.TestTable
					}

					htmlElement 'div' @{class = 'tabContent'; id = 'references'}{
						htmlElement 'h2' @{} {"About us: What makes FB Pro GmbH different"}
						htmlElement 'h3' @{} {"What do we want?"}
						htmlElement 'p' @{} {"Protect our customers' data and information - and thus implicitly contribute to the safe use of the Internet."}
						htmlElement 'h3' @{} {"How we achieve this? "}
						htmlElement 'p' @{} {"We implement in-depth IT security for our customers. And we always do so in a state-of-the-art, efficient and automated manner."}
						htmlElement 'div'@{id="referencesContainer"}{
							htmlElement 'div'@{}{
								htmlElement 'h2' @{} {"Check out our hardening solution"}
								htmlElement 'a' @{href="https://www.fb-pro.com/enforce-administrator-product/"}{
									htmlElement 'img' @{height="400px"; width="250px"; src=" data:image/jpeg;base64,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"}{}
								}

							}

							htmlElement 'div'@{}{
								htmlElement 'h2' @{} {"Check out our Audit Report Tool here"}
								htmlElement 'a' @{href="https://github.com/fbprogmbh/Audit-Test-Automation"}{
									htmlElement 'img' @{height="400px"; width="250px"; src=" data:image/jpeg;base64,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"}{}		
								}
							}				
						}
					}


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


		if (Test-Path -Path $path) {
			Write-Warning "$path already exists. $path will be overridden!"
		}

		#Create Report file
		New-Item $path -ItemType File -Force
		$html | Out-File -FilePath $path -Encoding utf8
	}
}